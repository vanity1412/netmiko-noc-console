"""TXT / CSV / JSON / ZIP exports built from stored evidence."""
from __future__ import annotations

import csv
import io
import json
import logging
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Iterator

from .evidence import EvidenceNotFound, EvidenceStore
from .history import HistoryStore
from .settings import VERSION, Settings

log = logging.getLogger("netmiko_web.exports")

CSV_COLUMNS = [
    "run_id",
    "created_at",
    "device",
    "host",
    "device_type",
    "vendor",
    "device_status",
    "fault_status",
    "error_reason",
    "device_message",
    "elapsed_ms",
    "session_reused",
    "command_index",
    "command",
    "command_status",
    "command_error_reason",
    "command_message",
    "command_elapsed_ms",
    "output_complete",
    "characters",
    "lines",
    "output_id",
    "output",
]


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def export_filename(run_id: str, extension: str) -> str:
    return f"netmiko-{run_id}-{_stamp()}.{extension}"


class ExportService:
    def __init__(self, settings: Settings, history: HistoryStore, evidence: EvidenceStore):
        self.settings = settings
        self.history = history
        self.evidence = evidence

    def _run(self, run_id: str) -> dict[str, Any]:
        run = self.history.get_run(run_id, include_steps=False)
        if run is None:
            raise KeyError(run_id)
        return run

    def _device_json(self, run_id: str, device: dict[str, Any]) -> dict[str, Any]:
        path = self.evidence.json_path(run_id, device["name"])
        if path is not None:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.warning("invalid device json for %s/%s", run_id, device["name"])
        return {
            "run_id": run_id,
            "device": device["name"],
            "host": device.get("host"),
            "device_type": device.get("device_type"),
            "vendor": device.get("vendor"),
            "status": device.get("status"),
            "fault_status": device.get("fault_status"),
            "error_reason": device.get("error_reason"),
            "message": device.get("message"),
            "elapsed_ms": device.get("elapsed_ms"),
            "steps": device.get("steps") or [],
            "note": "Không có file JSON chi tiết; dùng metadata từ database",
        }

    # --------------------------------------------------------------------- TXT
    def txt(self, run_id: str) -> Iterator[str]:
        run = self._run(run_id)
        counts = run["counts"]
        yield (
            "NETMIKO WEB CONSOLE - RAW CLI EVIDENCE\n"
            f"run        : {run['id']}\n"
            f"created_at : {run['created_at']}\n"
            f"status     : {run['status']}\n"
            f"total      : {run['total']} | success: {counts['success']} | partial: {counts['partial']} | error: {counts['error']}\n"
            f"commands   : {len(run['commands'])}\n"
            f"{'=' * 100}\n\n"
        )
        for device in run["devices"]:
            try:
                content = self.evidence.read_all(run_id, device["name"])
            except EvidenceNotFound as exc:
                content = (
                    f"===== {device['name']} ({device.get('host') or '-'}) =====\n"
                    f"status: {device['status']}\n"
                    f"error_reason: {device.get('error_reason') or ''}\n"
                    f"message: {device.get('message') or exc}\n"
                )
            yield content
            if not content.endswith("\n"):
                yield "\n"
            yield "\n"

    # --------------------------------------------------------------------- CSV
    def csv(self, run_id: str) -> Iterator[str]:
        run = self._run(run_id)
        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
        writer.writerow(CSV_COLUMNS)
        yield "\ufeff" + buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        for device in run["devices"]:
            detail = self._device_json(run_id, device)
            steps = detail.get("steps") or []
            base = [
                run["id"],
                run["created_at"],
                device["name"],
                device.get("host") or "",
                device.get("device_type") or "",
                device.get("vendor") or "",
                device.get("status") or "",
                device.get("fault_status") or "",
                device.get("error_reason") or "",
                device.get("message") or "",
                device.get("elapsed_ms") or 0,
                "yes" if device.get("session_reused") else "no",
            ]
            if not steps:
                writer.writerow(base + ["", "", "", "", "", "", "", "", "", "", device.get("message") or ""])
            else:
                for step in steps:
                    writer.writerow(
                        base
                        + [
                            step.get("index", ""),
                            step.get("command", ""),
                            step.get("status", ""),
                            step.get("error_reason") or "",
                            step.get("message") or "",
                            step.get("elapsed_ms") or 0,
                            step.get("output_complete", ""),
                            step.get("characters", ""),
                            step.get("lines", ""),
                            step.get("output_id") or "",
                            step.get("output") or "",
                        ]
                    )
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    # -------------------------------------------------------------------- JSON
    def json(self, run_id: str) -> Iterator[str]:
        run = self._run(run_id)
        meta = {key: value for key, value in run.items() if key != "devices"}
        yield '{"exported_at":' + json.dumps(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())) + \
            ',"web_console_version":' + json.dumps(VERSION) + ',"run":' + json.dumps(meta, ensure_ascii=False) + ',"devices":['
        first = True
        for device in run["devices"]:
            if not first:
                yield ","
            first = False
            payload = self._device_json(run_id, device)
            yield json.dumps(payload, ensure_ascii=False)
        yield "]}"

    # --------------------------------------------------------------------- ZIP
    def zip(self, run_id: str) -> tuple[Path, str]:
        run = self._run(run_id)
        self.settings.tmp_dir.mkdir(parents=True, exist_ok=True)
        filename = export_filename(run_id, "zip")
        path = self.settings.tmp_dir / f"{uuid.uuid4().hex}-{filename}"
        files_manifest: list[dict[str, Any]] = []
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            summary_text = self._summary_text(run)
            archive.writestr("summary.txt", summary_text)
            with archive.open("summary.csv", "w") as raw:
                for chunk in self.csv(run_id):
                    raw.write(chunk.encode("utf-8"))
            with archive.open("run.json", "w") as raw:
                for chunk in self.json(run_id):
                    raw.write(chunk.encode("utf-8"))
            for device in run["devices"]:
                base = f"devices/{int(device.get('seq') or 0):05d}-{device['name']}"
                try:
                    content = self.evidence.read_all(run_id, device["name"])
                    archive.writestr(base + ".txt", content)
                    files_manifest.append({"file": base + ".txt", "bytes": len(content.encode('utf-8'))})
                except EvidenceNotFound:
                    pass
                json_path = self.evidence.json_path(run_id, device["name"])
                if json_path is not None:
                    archive.writestr(base + ".json", json_path.read_bytes())
                    files_manifest.append({"file": base + ".json", "bytes": json_path.stat().st_size})
            manifest = {
                "run": {key: value for key, value in run.items() if key != "devices"},
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "web_console_version": VERSION,
                "files": files_manifest,
                "notes": [
                    "raw text is stored unchanged per device; headers are added by the Web Console",
                    "output_id points to the Netmiko MCP evidence store",
                ],
            }
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
        return path, filename

    def _summary_text(self, run: dict[str, Any]) -> str:
        counts = run["counts"]
        lines = [
            "NETMIKO WEB CONSOLE - RUN SUMMARY",
            f"run        : {run['id']}",
            f"created_at : {run['created_at']}",
            f"finished_at: {run.get('finished_at') or '-'}",
            f"status     : {run['status']}",
            f"total      : {run['total']}",
            f"success    : {counts['success']}",
            f"partial    : {counts['partial']}",
            f"error      : {counts['error']}",
            f"cancelled  : {counts['cancelled']}",
            "",
            "commands:",
            *[f"  - {command}" for command in run["commands"]],
            "",
            f"{'DEVICE':40} {'STATUS':10} {'REASON':22} MESSAGE",
        ]
        for device in run["devices"]:
            lines.append(
                f"{device['name'][:40]:40} {device['status'][:10]:10} "
                f"{(device.get('error_reason') or '-')[:22]:22} {(device.get('message') or '')[:100]}"
            )
        return "\n".join(lines) + "\n"
