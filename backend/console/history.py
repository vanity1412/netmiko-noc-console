"""SQLite run history and per-device result metadata.

Raw CLI text is stored on disk (one TXT + one JSON file per device/run) so the
database stays small and history stays fast even with thousands of devices.
"""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("netmiko_web.history")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    started_at REAL,
    finished_at TEXT,
    status TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0,
    commands_json TEXT NOT NULL,
    options_json TEXT NOT NULL,
    retry_of TEXT,
    note TEXT,
    cancelled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    name TEXT NOT NULL,
    host TEXT,
    device_type TEXT,
    vendor TEXT,
    profile TEXT,
    status TEXT NOT NULL,
    fault_status TEXT,
    error_reason TEXT,
    error_category TEXT,
    error_stage TEXT,
    message TEXT,
    elapsed_ms INTEGER,
    session_reused INTEGER,
    steps_json TEXT,
    output_file TEXT,
    json_file TEXT,
    output_bytes INTEGER,
    output_lines INTEGER,
    output_sha256 TEXT,
    notes_json TEXT,
    finished_at TEXT,
    PRIMARY KEY (run_id, name),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_devices_run_status ON devices(run_id, status);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
"""


def utc_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


class HistoryStore:
    def __init__(self, path: Path, runs_dir: Path):
        self.path = Path(path)
        self.runs_dir = Path(runs_dir)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ writes
    def create_run(
        self,
        run_id: str,
        commands: list[str],
        options: dict[str, Any],
        devices: list[dict[str, Any]],
        *,
        retry_of: str | None = None,
        note: str = "",
        started: float | None = None,
    ) -> None:
        created = utc_iso(started)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO runs (id, created_at, started_at, status, total, commands_json, options_json, retry_of, note) "
                "VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?)",
                (
                    run_id,
                    created,
                    started or time.time(),
                    len(devices),
                    json.dumps(commands, ensure_ascii=False),
                    json.dumps(options, ensure_ascii=False),
                    retry_of,
                    note,
                ),
            )
            self._db.executemany(
                "INSERT INTO devices (run_id, seq, name, host, device_type, vendor, profile, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED')",
                [
                    (
                        run_id,
                        index,
                        device["name"],
                        device.get("host") or "",
                        device.get("device_type") or "",
                        device.get("vendor") or "",
                        device.get("profile") or "",
                    )
                    for index, device in enumerate(devices)
                ],
            )

    def update_device(self, run_id: str, name: str, fields: dict[str, Any]) -> None:
        allowed = {
            "status",
            "fault_status",
            "error_reason",
            "error_category",
            "error_stage",
            "message",
            "elapsed_ms",
            "session_reused",
            "steps_json",
            "output_file",
            "json_file",
            "output_bytes",
            "output_lines",
            "output_sha256",
            "notes_json",
            "finished_at",
        }
        values = {key: value for key, value in fields.items() if key in allowed}
        if not values:
            return
        if isinstance(values.get("steps_json"), (list, dict)):
            values["steps_json"] = json.dumps(values["steps_json"], ensure_ascii=False)
        if isinstance(values.get("notes_json"), (list, dict)):
            values["notes_json"] = json.dumps(values["notes_json"], ensure_ascii=False)
        assignments = ", ".join(f"{key} = ?" for key in values)
        with self._lock, self._db:
            self._db.execute(
                f"UPDATE devices SET {assignments} WHERE run_id = ? AND name = ?",
                (*values.values(), run_id, name),
            )

    def finish_run(self, run_id: str, status: str, *, finished: float | None = None) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE runs SET status = ?, finished_at = ? WHERE id = ?",
                (status, utc_iso(finished), run_id),
            )

    def mark_interrupted(self) -> int:
        with self._lock, self._db:
            rows = self._db.execute(
                "SELECT id FROM runs WHERE status IN ('running', 'queued')"
            ).fetchall()
            for row in rows:
                self._db.execute(
                    "UPDATE runs SET status = 'interrupted', finished_at = ? WHERE id = ?",
                    (utc_iso(), row["id"]),
                )
                self._db.execute(
                    "UPDATE devices SET status = 'ERROR', error_reason = 'web_restarted', "
                    "message = 'Web Console dừng trước khi thiết bị hoàn tất', finished_at = ? "
                    "WHERE run_id = ? AND status IN ('QUEUED', 'RUNNING')",
                    (utc_iso(), row["id"]),
                )
            self._db.commit()
        return len(rows)

    # ------------------------------------------------------------------- reads
    def _counts(self, run_ids: Iterable[str]) -> dict[str, Counter]:
        ids = list(run_ids)
        result: dict[str, Counter] = {run_id: Counter() for run_id in ids}
        if not ids:
            return result
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._db.execute(
                f"SELECT run_id, status, COUNT(*) AS count FROM devices "
                f"WHERE run_id IN ({placeholders}) GROUP BY run_id, status",
                ids,
            ).fetchall()
        for row in rows:
            result[row["run_id"]][row["status"]] += row["count"]
        return result

    @staticmethod
    def _summary(row: sqlite3.Row, counts: Counter) -> dict[str, Any]:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "status": row["status"],
            "total": row["total"],
            "retry_of": row["retry_of"],
            "note": row["note"],
            "cancelled": bool(row["cancelled"]),
            "commands": json.loads(row["commands_json"] or "[]"),
            "counts": {
                "success": counts.get("SUCCESS", 0),
                "partial": counts.get("PARTIAL", 0),
                "error": counts.get("ERROR", 0),
                "queued": counts.get("QUEUED", 0),
                "running": counts.get("RUNNING", 0),
                "cancelled": counts.get("CANCELLED", 0),
            },
        }

    def list_runs(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            rows = self._db.execute(
                "SELECT * FROM runs ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        counts = self._counts(row["id"] for row in rows)
        return {
            "runs": [self._summary(row, counts[row["id"]]) for row in rows],
            "total": total,
        }

    def get_run(self, run_id: str, *, include_steps: bool = True) -> dict[str, Any] | None:
        with self._lock:
            run = self._db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                return None
            devices = self._db.execute(
                "SELECT * FROM devices WHERE run_id = ? ORDER BY seq", (run_id,)
            ).fetchall()
        counts = self._counts([run_id])[run_id]
        summary = self._summary(run, counts)
        summary["options"] = json.loads(run["options_json"] or "{}")
        device_rows = []
        for row in devices:
            notes = json.loads(row["notes_json"] or "[]")
            steps = json.loads(row["steps_json"] or "[]") if include_steps else []
            device_rows.append(
                {
                    "seq": row["seq"],
                    "name": row["name"],
                    "host": row["host"],
                    "device_type": row["device_type"],
                    "vendor": row["vendor"],
                    "profile": row["profile"],
                    "status": row["status"],
                    "fault_status": row["fault_status"],
                    "error_reason": row["error_reason"],
                    "error_category": row["error_category"],
                    "error_stage": row["error_stage"],
                    "message": row["message"],
                    "elapsed_ms": row["elapsed_ms"],
                    "session_reused": bool(row["session_reused"]),
                    "steps": steps,
                    "output_bytes": row["output_bytes"] or 0,
                    "output_lines": row["output_lines"] or 0,
                    "output_sha256": row["output_sha256"],
                    "notes": notes,
                    "finished_at": row["finished_at"],
                }
            )
        summary["devices"] = device_rows
        return summary

    def device(self, run_id: str, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM devices WHERE run_id = ? AND name = ?", (run_id, name)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["output_bytes"] = result.get("output_bytes") or 0
        result["output_lines"] = result.get("output_lines") or 0
        return result

    def failed_devices(self, run_id: str) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT name FROM devices WHERE run_id = ? AND status IN ('ERROR', 'PARTIAL') "
                "ORDER BY seq",
                (run_id,),
            ).fetchall()
        return [row["name"] for row in rows]

    def delete_run(self, run_id: str) -> bool:
        with self._lock:
            row = self._db.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return False
            if row["status"] == "running":
                raise RuntimeError("Run đang chạy; không thể xóa")
            with self._db:
                self._db.execute("DELETE FROM devices WHERE run_id = ?", (run_id,))
                self._db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        directory = self.runs_dir / run_id
        if directory.is_dir():
            shutil.rmtree(directory, ignore_errors=True)
        return True

    def delete_finished(self) -> int:
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM runs WHERE status != 'running'"
            ).fetchall()
            ids = [row["id"] for row in rows]
            for run_id in ids:
                with self._db:
                    self._db.execute("DELETE FROM devices WHERE run_id = ?", (run_id,))
                    self._db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        for run_id in ids:
            directory = self.runs_dir / run_id
            if directory.is_dir():
                shutil.rmtree(directory, ignore_errors=True)
        return len(ids)

    # --------------------------------------------------------------- retention
    def prune(self, keep: int) -> int:
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            if total <= keep:
                return 0
            victims = self._db.execute(
                "SELECT id FROM runs ORDER BY created_at ASC, rowid ASC LIMIT ?",
                (total - keep,),
            ).fetchall()
            removed = 0
            for row in victims:
                run_id = row["id"]
                with self._db:
                    self._db.execute("DELETE FROM devices WHERE run_id = ?", (run_id,))
                    self._db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
                directory = self.runs_dir / run_id
                if directory.is_dir():
                    shutil.rmtree(directory, ignore_errors=True)
                removed += 1
            return removed
