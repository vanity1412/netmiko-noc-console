"""Concurrent run orchestration on top of the existing MCP tools.

Each selected device is one ``ssh_execute_many`` MCP call in a worker thread.
The MCP server keeps its own Netmiko session pool, autodetect cache and output
reader; the Web Console only schedules, classifies and stores the evidence.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, AsyncIterator

from .history import HistoryStore, utc_iso
from .inventory import InventoryService
from .mcp_client import (
    MCPCallError,
    MCPError,
    MCPTimeout,
    MCPUnavailable,
    StdioMCPClient,
)
from .settings import Settings

log = logging.getLogger("netmiko_web.runner")

DEVICE_STATUSES = ("SUCCESS", "PARTIAL", "ERROR", "QUEUED", "RUNNING", "CANCELLED")
FAILED_STATUSES = {"ERROR", "PARTIAL", "CANCELLED"}


class RunValidationError(ValueError):
    pass


def _slug(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")[:80] or "device"
    digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:6]
    return f"{base}-{digest}"


def _short(text: Any, limit: int = 800) -> str:
    value = " ".join(str(text or "").split())
    return value[:limit]


def _step_status(step: dict[str, Any]) -> str:
    if step.get("skipped") is True:
        return "SKIPPED"
    if step.get("awaiting_input") is True:
        return "AWAITING_INPUT"
    if step.get("ok") is True:
        return "SUCCESS"
    return str(step.get("status") or step.get("fault_status") or "ERROR")


def classify_device_result(payload: dict[str, Any], commands: list[str]) -> dict[str, Any]:
    """Map the MCP result into the Web Console's SUCCESS/PARTIAL/ERROR view."""
    steps = payload.get("results")
    if not isinstance(steps, list):
        steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    steps = [step for step in steps if isinstance(step, dict)]
    ok_steps = [step for step in steps if step.get("ok") is True]
    skipped = [step for step in steps if step.get("skipped") is True]
    failed = [step for step in steps if step.get("ok") is not True and step.get("skipped") is not True]
    awaiting = [step for step in steps if step.get("awaiting_input") is True]
    total_commands = len(commands)

    if not steps:
        status = "SUCCESS" if payload.get("ok") is True and payload.get("status") == "SUCCESS" else "ERROR"
    elif payload.get("ok") is True and not failed and not skipped and len(ok_steps) >= total_commands:
        status = "SUCCESS"
    elif ok_steps:
        status = "PARTIAL"
    else:
        status = "ERROR"

    error_reason = None
    message = ""
    category = payload.get("error_category")
    stage = payload.get("error_stage")
    first_failed = failed[0] if failed else {}
    if awaiting:
        status = "ERROR"
        error_reason = "awaiting_input"
        category = "awaiting_input"
        stage = "cli"
        message = "Thiết bị đang chờ phản hồi (pager/xác nhận); Web Console không tự trả lời."
    elif status != "SUCCESS":
        error_reason = (
            first_failed.get("error_reason")
            or payload.get("error_reason")
            or payload.get("failed_error_reason")
            or (skipped[0].get("skipped_reason") if skipped and not failed else None)
            or payload.get("error_category")
            or "unknown_error"
        )
        category = first_failed.get("error_category") or category
        stage = first_failed.get("error_stage") or stage
        message = _short(
            payload.get("message")
            or first_failed.get("message")
            or (skipped[0].get("message") if skipped else "")
            or payload.get("error")
            or ""
        )
    if status == "PARTIAL" and not message:
        message = _short(
            f"{len(ok_steps)}/{total_commands} lệnh thành công; "
            f"{len(failed)} lỗi, {len(skipped)} bỏ qua"
        )
    elapsed = payload.get("elapsed_ms")
    if not isinstance(elapsed, (int, float)):
        elapsed = sum(int(step.get("elapsed_ms") or 0) for step in steps)
    session_reused = bool(payload.get("session_reused")) or any(
        bool(step.get("session_reused")) for step in steps
    )
    step_summaries = []
    for index, step in enumerate(steps):
        step_summaries.append(
            {
                "index": int(step.get("command_index", index) or 0),
                "command": str(step.get("command") or (commands[index] if index < len(commands) else "")),
                "status": _step_status(step),
                "ok": step.get("ok") is True,
                "skipped": step.get("skipped") is True,
                "error_reason": step.get("error_reason") or step.get("skipped_reason"),
                "error_category": step.get("error_category"),
                "error_stage": step.get("error_stage"),
                "message": _short(step.get("message"), 400),
                "elapsed_ms": int(step.get("elapsed_ms") or 0),
                "output_complete": step.get("output_complete"),
                "characters": step.get("characters"),
                "lines": step.get("lines"),
                "output_id": step.get("output_id"),
                "awaiting_input": bool(step.get("awaiting_input")),
            }
        )
    return {
        "status": status,
        "fault_status": str(payload.get("status") or payload.get("fault_status") or status),
        "error_reason": error_reason,
        "error_category": category,
        "error_stage": stage,
        "message": message[:1000],
        "elapsed_ms": int(elapsed or 0),
        "session_reused": session_reused,
        "steps": step_summaries,
        "raw_steps": steps,
        "read_commands": total_commands,
    }


def diagnose_preparation(
    classification: dict[str, Any], payload: dict[str, Any]
) -> list[str]:
    """Translate known MCP/Netmiko preparation failures into actionable notes.

    The MCP result is preserved (fault_status/raw output), but a timeout during
    Junos terminal setup is almost always a restricted login class rather than a
    Web Console network/read problem.
    """
    notes: list[str] = []
    if classification.get("status") == "SUCCESS" or payload.get("error_stage") != "preparation":
        return notes
    output = str(payload.get("output") or "")
    preparation = str(payload.get("preparation_command") or "")
    text = (preparation + "\n" + output).casefold()
    if "set cli screen-width" in text and (
        "syntax error" in text or "expecting <command>" in text
    ):
        classification.update(
            error_reason="juniper_terminal_setup_denied",
            error_category="preparation_policy",
            error_stage="preparation",
            message=(
                "Junos từ chối thiết lập terminal của Netmiko (set cli screen-width/complete-on-space). "
                "Tài khoản SSH bị giới hạn login class; chưa có lệnh CLI nào được gửi tới thiết bị."
            ),
        )
        notes.append(
            "Chẩn đoán Web Console: MCP/Netmiko không thể thiết lập terminal Junos. "
            "Thiết bị trả 'syntax error, expecting <command>' cho lệnh preparation. "
            "Đây là giới hạn quyền CLI (login class), không phải lỗi Web Console hay lỗi đọc output."
        )
        notes.append(
            "Cách xử lý: cấp cho tài khoản automation quyền chạy 'set cli screen-width 511', "
            "'set cli complete-on-space off', 'set cli screen-length 0' (hoặc dùng login class/tài khoản "
            "khác) rồi chạy lại. Không cần nhập các lệnh này trong Web Console."
        )
        if payload.get("error_reason"):
            notes.append(
                f"MCP gốc: {payload.get('error_category') or 'unknown'}/"
                f"{payload.get('error_reason')} — raw output vẫn được giữ nguyên."
            )
    elif "permission denied" in text or "not authorized" in text:
        classification.update(
            error_reason="preparation_permission_denied",
            error_category="preparation_policy",
            error_stage="preparation",
            message="Tài khoản SSH không được phép chạy lệnh thiết lập phiên của Netmiko.",
        )
        notes.append(
            "Chẩn đoán Web Console: preparation bị từ chối quyền; cần kiểm tra login class/profile SSH."
        )
    return notes


def _header(device: dict[str, Any], status: str, commands: list[str]) -> str:
    lines = [
        "=" * 100,
        f"WEB CONSOLE RUN EVIDENCE",
        f"device   : {device['name']} ({device.get('host') or '-'})",
        f"driver   : {device.get('device_type') or '-'}",
        f"vendor   : {device.get('vendor') or '-'}",
        f"status   : {status}",
        f"commands : {len(commands)}",
        "=" * 100,
        "",
    ]
    return "\n".join(lines)


def build_raw_output(
    device: dict[str, Any],
    commands: list[str],
    payload: dict[str, Any],
    classification: dict[str, Any],
    outputs: dict[int, dict[str, Any]],
) -> str:
    chunks = [_header(device, classification["status"], commands)]
    raw_steps = classification.get("raw_steps") or []
    if not raw_steps:
        chunks.append("--- Không có output lệnh (lỗi kết nối/khởi tạo) ---\n")
        for key in ("error_category", "error_stage", "error_reason", "message"):
            if payload.get(key):
                chunks.append(f"{key}: {payload.get(key)}\n")
        if payload.get("output"):
            chunks.append("\n" + str(payload["output"]) + "\n")
        if payload.get("preparation_command"):
            chunks.append(f"preparation_command: {payload['preparation_command']}\n")
        return "".join(chunks)
    for index, step in enumerate(raw_steps):
        info = outputs.get(index, {})
        text = info.get("text")
        if text is None:
            text = step.get("output") if isinstance(step.get("output"), str) else ""
            if not text and step.get("preview"):
                text = str(step.get("preview"))
        command = str(step.get("command") or (commands[index] if index < len(commands) else ""))
        status = _step_status(step)
        meta = [
            f"----- [{index + 1}/{len(raw_steps)}] {command} -----",
            f"status: {status} | elapsed_ms: {int(step.get('elapsed_ms') or 0)} "
            f"| output_complete: {step.get('output_complete')} "
            f"| chars: {step.get('characters', len(text or ''))} | lines: {step.get('lines', '?')}",
        ]
        if step.get("error_reason"):
            meta.append(f"error_reason: {step.get('error_reason')}")
        if step.get("error_category"):
            meta.append(f"error_category: {step.get('error_category')} / stage: {step.get('error_stage')}")
        if step.get("message"):
            meta.append(f"message: {_short(step.get('message'), 500)}")
        if info.get("note"):
            meta.append(f"web_console_note: {info['note']}")
        chunks.append("\n".join(meta) + "\n\n")
        chunks.append(text or "")
        if text and not str(text).endswith("\n"):
            chunks.append("\n")
        chunks.append("\n")
    preceding = payload.get("preceding_output")
    if preceding:
        chunks.append("\n----- preceding output (unattributed) -----\n")
        chunks.append(str(preceding))
        if not str(preceding).endswith("\n"):
            chunks.append("\n")
    return "".join(chunks)


class RunState:
    def __init__(
        self,
        run_id: str,
        commands: list[str],
        options: dict[str, Any],
        devices: list[dict[str, Any]],
        *,
        retry_of: str | None = None,
        note: str = "",
    ) -> None:
        self.id = run_id
        self.commands = commands
        self.options = options
        self.devices = devices
        self.status = "running"
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.retry_of = retry_of
        self.note = note
        self.cancel_requested = False
        self.subscribers: set[asyncio.Queue] = set()
        self.seq = 0
        self.task: asyncio.Task | None = None

    def counts(self) -> dict[str, int]:
        counter = Counter(device["status"] for device in self.devices)
        return {
            "success": counter.get("SUCCESS", 0),
            "partial": counter.get("PARTIAL", 0),
            "error": counter.get("ERROR", 0),
            "queued": counter.get("QUEUED", 0),
            "running": counter.get("RUNNING", 0),
            "cancelled": counter.get("CANCELLED", 0),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": utc_iso(self.started_at),
            "started_at": self.started_at,
            "finished_at": utc_iso(self.finished_at) if self.finished_at else None,
            "status": self.status,
            "total": len(self.devices),
            "counts": self.counts(),
            "commands": self.commands,
            "retry_of": self.retry_of,
            "note": self.note,
            "cancelled": self.cancel_requested,
            "options": self.options,
        }

    def public_devices(self) -> list[dict[str, Any]]:
        return [self._public(device) for device in self.devices]

    @staticmethod
    def _public(device: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "seq", "name", "host", "device_type", "vendor", "profile", "status", "fault_status",
            "error_reason", "error_category", "error_stage", "message", "elapsed_ms",
            "session_reused", "steps", "output_bytes", "output_lines", "output_sha256", "notes", "finished_at",
        )
        return {key: device.get(key) for key in keys}

    def emit(self, event: dict[str, Any]) -> None:
        self.seq += 1
        event = {**event, "seq": self.seq, "run_id": self.id}
        payload = json.dumps(event, ensure_ascii=False)
        dead = []
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(payload)
            except (asyncio.QueueFull, RuntimeError):
                dead.append(queue)
        for queue in dead:
            self.subscribers.discard(queue)


class RunManager:
    def __init__(
        self,
        settings: Settings,
        mcp: StdioMCPClient,
        history: HistoryStore,
        inventory: InventoryService,
    ):
        self.settings = settings
        self.mcp = mcp
        self.history = history
        self.inventory = inventory
        self._runs: dict[str, RunState] = {}
        self._finished: deque[str] = deque()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ helpers
    def active_count(self) -> int:
        return sum(1 for state in self._runs.values() if state.status == "running")

    def get(self, run_id: str) -> RunState | None:
        return self._runs.get(run_id)

    @staticmethod
    def _validate_commands(commands: Any, settings: Settings) -> list[str]:
        if not isinstance(commands, list) or not commands:
            raise RunValidationError("Cần ít nhất một lệnh CLI")
        if len(commands) > settings.max_commands_per_run:
            raise RunValidationError(
                f"Tối đa {settings.max_commands_per_run} lệnh mỗi lượt"
            )
        result = []
        for raw in commands:
            if not isinstance(raw, str):
                raise RunValidationError("Lệnh phải là chuỗi")
            command = raw.strip()
            if not command:
                continue
            if len(command) > settings.command_max_len:
                raise RunValidationError("Lệnh quá dài")
            if any(ord(char) < 32 or ord(char) == 127 for char in command):
                raise RunValidationError("Mỗi dòng chỉ chứa một lệnh, không có ký tự điều khiển")
            result.append(command)
        if not result:
            raise RunValidationError("Cần ít nhất một lệnh CLI")
        return result

    def _make_id(self) -> str:
        return "run_" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "_" + hashlib.sha1(
            (str(time.time()) + str(id(self))).encode()
        ).hexdigest()[:6]

    def _resolve_devices(self, names: list[str], snapshot) -> list[dict[str, Any]]:
        if not names:
            raise RunValidationError("Chọn ít nhất một thiết bị")
        if len(names) > self.settings.max_devices_per_run:
            raise RunValidationError(
                f"Tối đa {self.settings.max_devices_per_run} thiết bị mỗi lượt"
            )
        devices = []
        missing = []
        seen = set()
        for raw in names:
            name = str(raw).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            row = snapshot.by_name.get(name)
            if row is None:
                missing.append(name)
                continue
            devices.append(
                {
                    "name": row["name"],
                    "host": row["host"],
                    "device_type": row["device_type"],
                    "vendor": row["vendor"],
                    "profile": row.get("profile") or "default",
                }
            )
        if missing:
            preview = ", ".join(missing[:5]) + ("..." if len(missing) > 5 else "")
            raise RunValidationError(f"Không có trong inventory MCP: {preview}")
        if not devices:
            raise RunValidationError("Không có thiết bị hợp lệ")
        return devices

    async def start_run(
        self,
        device_names: list[str],
        commands: list[str],
        options: dict[str, Any] | None,
        *,
        retry_of: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        options = options or {}
        validated_commands = self._validate_commands(commands, self.settings)
        try:
            concurrency = int(options.get("concurrency") or self.settings.default_concurrency)
        except (TypeError, ValueError):
            raise RunValidationError("Concurrency không hợp lệ") from None
        concurrency = max(1, min(concurrency, self.settings.max_concurrency))
        try:
            read_timeout = int(options.get("read_timeout") or 30)
        except (TypeError, ValueError):
            raise RunValidationError("Read timeout không hợp lệ") from None
        read_timeout = max(5, min(read_timeout, 120))
        continue_on_error = bool(options.get("continue_on_error", True))
        clean_options = {
            "concurrency": concurrency,
            "read_timeout": read_timeout,
            "continue_on_error": continue_on_error,
        }
        snapshot = await asyncio.to_thread(self.inventory.get)
        devices = self._resolve_devices(device_names, snapshot)
        for index, device in enumerate(devices):
            device.update(
                {
                    "seq": index,
                    "status": "QUEUED",
                    "fault_status": None,
                    "error_reason": None,
                    "error_category": None,
                    "error_stage": None,
                    "message": "",
                    "elapsed_ms": 0,
                    "session_reused": False,
                    "steps": [],
                    "output_bytes": 0,
                    "output_lines": 0,
                    "notes": [],
                    "finished_at": None,
                }
            )
        if not await asyncio.to_thread(self.mcp.ping, 5):
            try:
                await asyncio.to_thread(self.mcp.ensure_ready)
            except MCPError as exc:
                raise RunValidationError(f"MCP chưa sẵn sàng để chạy: {exc}") from exc
        run_id = self._make_id()
        state = RunState(
            run_id,
            validated_commands,
            clean_options,
            devices,
            retry_of=retry_of,
            note=(note or "")[:200],
        )
        await asyncio.to_thread(
            self.history.create_run,
            run_id,
            validated_commands,
            clean_options,
            devices,
            retry_of=retry_of,
            note=state.note,
            started=state.started_at,
        )
        async with self._lock:
            self._runs[run_id] = state
        state.emit({"type": "run", "run": state.summary()})
        state.task = asyncio.create_task(self._execute(state), name=f"run:{run_id}")
        log.info("run %s started: %s devices, %s commands", run_id, len(devices), len(validated_commands))
        return state.summary()

    async def _execute(self, state: RunState) -> None:
        sem = asyncio.Semaphore(int(state.options.get("concurrency") or 6))
        timeout = self._mcp_timeout(state)

        async def one(device: dict[str, Any]) -> None:
            async with sem:
                if state.cancel_requested:
                    await self._cancel_device(state, device)
                    return
                device["status"] = "RUNNING"
                state.emit({"type": "device", "device": state._public(device)})
                try:
                    record = await asyncio.to_thread(
                        self._execute_device_sync, state, device, timeout
                    )
                except Exception as exc:  # defensive: never lose a device record
                    log.exception("device worker crashed")
                    record = {
                        **device,
                        "status": "ERROR",
                        "error_reason": "web_error",
                        "error_category": type(exc).__name__,
                        "error_stage": "web",
                        "message": _short(exc),
                        "finished_at": utc_iso(),
                        "steps": [],
                        "notes": ["Lỗi nội bộ Web Console khi xử lý kết quả"],
                    }
                device.update(record)
                await asyncio.to_thread(
                    self._persist_record_sync, state.id, device
                )
                state.emit({"type": "device", "device": state._public(device)})
                state.emit({"type": "run", "run": state.summary()})

        await asyncio.gather(*(one(device) for device in state.devices), return_exceptions=True)
        try:
            # Defensive sweep: a crashed worker must never leave a device RUNNING forever.
            for device in state.devices:
                if device["status"] == "RUNNING":
                    device.update(
                        {
                            "status": "ERROR",
                            "error_reason": "web_error",
                            "message": "Worker Web Console dừng trước khi có kết quả",
                            "finished_at": utc_iso(),
                        }
                    )
                    await asyncio.to_thread(self._persist_record_sync, state.id, device)
                    state.emit({"type": "device", "device": state._public(device)})
                elif device["status"] == "QUEUED":
                    await self._cancel_device(state, device)
            state.finished_at = time.time()
            state.status = "cancelled" if state.cancel_requested else "completed"
            try:
                await asyncio.to_thread(
                    self.history.finish_run, state.id, state.status, finished=state.finished_at
                )
            except Exception:
                log.exception("could not finalize run %s", state.id)
            state.emit({"type": "run", "run": state.summary()})
            state.emit({"type": "done", "run": state.summary()})
            log.info(
                "run %s finished: %s", state.id, json.dumps(state.counts(), ensure_ascii=False)
            )
        finally:
            self._retire(state)

    async def _cancel_device(self, state: RunState, device: dict[str, Any]) -> None:
        device.update(
            {
                "status": "CANCELLED",
                "error_reason": "cancelled",
                "message": "Đã hủy trước khi chạy",
                "finished_at": utc_iso(),
            }
        )
        try:
            await asyncio.to_thread(self._persist_record_sync, state.id, device)
        except Exception:
            log.exception("could not persist cancelled device")
        state.emit({"type": "device", "device": state._public(device)})

    def _retire(self, state: RunState) -> None:
        self._finished.append(state.id)
        while len(self._finished) > 12:
            old = self._finished.popleft()
            old_state = self._runs.get(old)
            if old_state and old_state.status != "running" and not old_state.subscribers:
                self._runs.pop(old, None)
        try:
            asyncio.get_running_loop().call_later(
                600, lambda: self._expire(state.id)
            )
        except RuntimeError:  # pragma: no cover - no loop during shutdown
            pass

    def _expire(self, run_id: str) -> None:
        state = self._runs.get(run_id)
        if state and state.status != "running" and not state.subscribers:
            self._runs.pop(run_id, None)

    def _mcp_timeout(self, state: RunState) -> float:
        commands = len(state.commands)
        read_timeout = int(state.options.get("read_timeout") or 30)
        wanted = max(135, commands * read_timeout + 45)
        return float(min(max(wanted, 135), self.settings.mcp_tool_timeout))

    # ----------------------------------------------------------- worker thread
    def _execute_device_sync(
        self, state: RunState, device: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "target": device["name"],
            "commands": state.commands,
            "device_type": device["device_type"] or "autodetect",
            "read_timeout": int(state.options.get("read_timeout") or 30),
            "continue_on_error": bool(state.options.get("continue_on_error", True)),
        }
        notes: list[str] = []
        try:
            payload, meta = self.mcp.call_tool(
                "ssh_execute_many", arguments, timeout=timeout
            )
        except (MCPTimeout, MCPUnavailable, MCPCallError) as exc:
            category = (
                "mcp_timeout"
                if isinstance(exc, MCPTimeout)
                else "mcp_unavailable"
                if isinstance(exc, MCPUnavailable)
                else "mcp_error"
            )
            log.warning("MCP call failed for %s: %s", device["name"], exc)
            return {
                "status": "ERROR",
                "fault_status": "MCP_ERROR",
                "error_reason": category,
                "error_category": category,
                "error_stage": "mcp",
                "message": _short(exc),
                "elapsed_ms": int(timeout * 1000),
                "session_reused": False,
                "steps": [],
                "notes": [
                    "Không nhận được kết quả từ MCP. Không tự động retry vì lệnh có thể đã gửi tới thiết bị."
                ],
                "finished_at": utc_iso(),
            }
        classification = classify_device_result(payload, state.commands)
        notes.extend(diagnose_preparation(classification, payload))
        outputs: dict[int, dict[str, Any]] = {}
        used_bytes = 0
        for index, step in enumerate(classification.get("raw_steps") or []):
            if "output" in step and isinstance(step.get("output"), str):
                text = step["output"]
                outputs[index] = {"text": text}
                used_bytes += len(text.encode("utf-8"))
                continue
            output_id = step.get("output_id")
            if output_id:
                text, note, size = self._read_full_output(
                    str(output_id),
                    max_bytes=self.settings.max_output_bytes_per_device - used_bytes,
                )
                used_bytes += size
                if note:
                    notes.append(note)
                outputs[index] = {"text": text, "note": note, "output_id": output_id}
            else:
                preview = step.get("preview") or ""
                outputs[index] = {
                    "text": str(preview),
                    "note": "MCP không trả output đầy đủ" if preview else "",
                }
        raw_text = build_raw_output(device, state.commands, payload, classification, outputs)
        if used_bytes > self.settings.max_output_bytes_per_device:
            notes.append("Output vượt giới hạn lưu của Web Console; raw đầy đủ vẫn còn trong MCP output_id")
        output_file = json_file = None
        output_bytes = len(raw_text.encode("utf-8"))
        output_lines = raw_text.count("\n") + (1 if raw_text and not raw_text.endswith("\n") else 0)
        digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        try:
            output_file, json_file = self._write_evidence(
                state, device, payload, classification, outputs, raw_text
            )
        except Exception as exc:
            log.exception("could not write evidence for %s", device["name"])
            notes.append(f"Không ghi được file evidence: {_short(exc)}")
        return {
            "status": classification["status"],
            "fault_status": classification["fault_status"],
            "error_reason": classification["error_reason"],
            "error_category": classification["error_category"],
            "error_stage": classification["error_stage"],
            "message": classification["message"],
            "elapsed_ms": classification["elapsed_ms"] or meta.get("duration_ms", 0),
            "session_reused": classification["session_reused"],
            "steps": classification["steps"],
            "output_file": output_file,
            "json_file": json_file,
            "output_bytes": output_bytes,
            "output_lines": output_lines,
            "output_sha256": digest,
            "notes": notes,
            "finished_at": utc_iso(),
        }

    def _read_full_output(
        self, output_id: str, *, max_bytes: int
    ) -> tuple[str, str, int]:
        chunks: list[str] = []
        offset = 0
        used = 0
        note = ""
        while True:
            if max_bytes > 0 and used >= max_bytes:
                note = "Dừng đọc ở giới hạn dung lượng Web Console"
                break
            try:
                payload, _meta = self.mcp.call_tool(
                    "ssh_read_output",
                    {"output_id": output_id, "offset": offset, "limit": 1000},
                    timeout=self.settings.mcp_output_timeout,
                )
            except MCPError as exc:
                note = f"Không đọc được output_id {output_id}: {_short(exc, 200)}"
                break
            text = payload.get("text")
            if not isinstance(text, str):
                note = f"MCP trả dữ liệu output không hợp lệ cho {output_id}"
                break
            chunks.append(text)
            used += len(text.encode("utf-8"))
            next_offset = payload.get("next_offset")
            more = bool(payload.get("more"))
            if not more:
                break
            if not isinstance(next_offset, int) or next_offset <= offset:
                note = "MCP báo còn dữ liệu nhưng không tăng offset; dừng để tránh lặp"
                break
            offset = next_offset
            if payload.get("oversized_line"):
                note = "Có dòng quá dài; dùng ssh_read_output_bytes trong MCP để xem đầy đủ"
                break
        return "".join(chunks), note, used

    def _write_evidence(
        self,
        state: RunState,
        device: dict[str, Any],
        payload: dict[str, Any],
        classification: dict[str, Any],
        outputs: dict[int, dict[str, Any]],
        raw_text: str,
    ) -> tuple[str, str]:
        run_dir = self.settings.runs_dir / state.id
        run_dir.mkdir(parents=True, exist_ok=True)
        seq = int(device.get("seq") or 0)
        stem = f"{seq:05d}-{_slug(device['name'])}"
        text_path = run_dir / f"{stem}.txt"
        json_path = run_dir / f"{stem}.json"
        self._atomic_write(text_path, raw_text)
        detail = {
            "run_id": state.id,
            "device": device["name"],
            "host": device.get("host"),
            "device_type": device.get("device_type"),
            "vendor": device.get("vendor"),
            "commands": state.commands,
            "status": classification["status"],
            "fault_status": classification["fault_status"],
            "error_reason": classification["error_reason"],
            "message": classification["message"],
            "elapsed_ms": classification["elapsed_ms"],
            "steps": [
                {
                    **{key: value for key, value in summary.items() if key != "output_id"},
                    "output": outputs.get(index, {}).get("text", ""),
                    "output_id": summary.get("output_id"),
                }
                for index, summary in enumerate(classification["steps"])
            ],
            "raw_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
            "mcp_payload_summary": {
                key: payload.get(key)
                for key in ("status", "fault_status", "ok", "error_category", "error_stage", "error_reason")
            },
        }
        self._atomic_write(json_path, json.dumps(detail, ensure_ascii=False, indent=1))
        return text_path.name, json_path.name

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
        temporary.replace(path)

    def _persist_record_sync(self, run_id: str, device: dict[str, Any]) -> None:
        self.history.update_device(
            run_id,
            device["name"],
            {
                "status": device.get("status"),
                "fault_status": device.get("fault_status"),
                "error_reason": device.get("error_reason"),
                "error_category": device.get("error_category"),
                "error_stage": device.get("error_stage"),
                "message": device.get("message"),
                "elapsed_ms": device.get("elapsed_ms"),
                "session_reused": 1 if device.get("session_reused") else 0,
                "steps_json": device.get("steps") or [],
                "output_file": device.get("output_file"),
                "json_file": device.get("json_file"),
                "output_bytes": device.get("output_bytes"),
                "output_lines": device.get("output_lines"),
                "output_sha256": device.get("output_sha256"),
                "notes_json": device.get("notes") or [],
                "finished_at": device.get("finished_at"),
            },
        )

    # ---------------------------------------------------------------- API bits
    def cancel(self, run_id: str) -> dict[str, Any]:
        state = self._runs.get(run_id)
        if state is None:
            raise RunValidationError("Không tìm thấy run đang hoạt động")
        if state.status != "running":
            return {"cancelled": False, "message": "Run đã kết thúc"}
        state.cancel_requested = True
        state.emit({"type": "run", "run": state.summary()})
        return {"cancelled": True, "message": "Đã dừng nhận thiết bị mới; lệnh đang chạy sẽ hoàn tất"}

    async def retry_failed(self, run_id: str) -> dict[str, Any]:
        state = self._runs.get(run_id)
        if state and state.status == "running":
            raise RunValidationError("Run gốc vẫn đang chạy")
        detail = await asyncio.to_thread(self.history.get_run, run_id, include_steps=False)
        if detail is None:
            raise RunValidationError("Không tìm thấy run")
        if detail.get("status") == "running":
            raise RunValidationError("Run gốc vẫn đang chạy")
        failed = await asyncio.to_thread(self.history.failed_devices, run_id)
        if not failed:
            raise RunValidationError("Run này không có thiết bị lỗi/partial để retry")
        return await self.start_run(
            failed,
            detail["commands"],
            detail.get("options") or {},
            retry_of=run_id,
            note=f"Retry {len(failed)} thiết bị lỗi từ {run_id}",
        )

    async def delete_run(self, run_id: str) -> bool:
        state = self._runs.get(run_id)
        if state and state.status == "running":
            raise RunValidationError("Run đang chạy; không thể xóa")
        deleted = await asyncio.to_thread(self.history.delete_run, run_id)
        if state is not None and state.status != "running":
            self._runs.pop(run_id, None)
            with contextlib.suppress(ValueError):
                self._finished.remove(run_id)
        return deleted

    async def delete_finished(self) -> int:
        deleted = await asyncio.to_thread(self.history.delete_finished)
        for run_id, state in list(self._runs.items()):
            if state.status != "running":
                self._runs.pop(run_id, None)
                with contextlib.suppress(ValueError):
                    self._finished.remove(run_id)
        return deleted

    async def subscribe(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        state = self._runs.get(run_id)
        if state is None:
            yield {"type": "error", "message": "Run không còn trong bộ nhớ; xem chi tiết qua API"}
            return
        queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        state.subscribers.add(queue)
        try:
            yield {
                "type": "snapshot",
                "run": state.summary(),
                "devices": state.public_devices(),
            }
            if state.status != "running":
                yield {"type": "done", "run": state.summary()}
                return
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    if state.status != "running":
                        yield {"type": "done", "run": state.summary()}
                        break
                    yield {"type": "heartbeat", "ts": time.time()}
                    continue
                yield json.loads(payload)
                if json.loads(payload).get("type") == "done":
                    break
        finally:
            state.subscribers.discard(queue)
