"""Minimal, dependency-free MCP stdio client.

The Netmiko MCP server (``mcp/bootstrap.py``) speaks JSON-RPC 2.0 over
stdin/stdout. This client starts a dedicated Web Console instance of that
server and speaks the documented MCP tool protocol. No SSH logic is
re-implemented here.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any

log = logging.getLogger("netmiko_web.mcp")

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "netmiko-web-console", "version": "1.0.0"}


class MCPError(RuntimeError):
    """Base error for the MCP bridge."""


class MCPUnavailable(MCPError):
    pass


class MCPCallError(MCPError):
    def __init__(self, message: str, *, code: int | None = None):
        super().__init__(message)
        self.code = code


class MCPTimeout(MCPError):
    def __init__(self, message: str, *, request_id: int | None = None):
        super().__init__(message)
        self.request_id = request_id


class _WindowsJob:
    """Kill-on-close job object so the MCP child never outlives the Web server."""

    def __init__(self) -> None:
        self.handle = None
        if os.name != "nt":
            return
        try:
            from ctypes import wintypes

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error())
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(info), ctypes.sizeof(info)
            ):
                kernel32.CloseHandle(handle)
                raise OSError(ctypes.get_last_error())
            self.handle = handle
            self._kernel32 = kernel32
        except Exception as exc:  # pragma: no cover - best effort on Windows
            log.warning("MCP process job object unavailable: %s", exc)

    def assign(self, pid: int) -> None:
        if not self.handle or os.name != "nt":
            return
        PROCESS_SET_QUOTA = 0x0100
        PROCESS_TERMINATE = 0x0001
        try:
            process = self._kernel32.OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid
            )
            if not process:
                raise OSError(ctypes.get_last_error())
            try:
                if not self._kernel32.AssignProcessToJobObject(self.handle, process):
                    raise OSError(ctypes.get_last_error())
            finally:
                self._kernel32.CloseHandle(process)
        except Exception as exc:  # pragma: no cover - best effort on Windows
            log.warning("MCP child could not be attached to job object: %s", exc)

    def close(self) -> None:
        if self.handle:
            try:
                self._kernel32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None


class StdioMCPClient:
    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path | str,
        env: dict[str, str] | None = None,
        init_timeout: float = 60.0,
        log_path: Path | None = None,
    ) -> None:
        if not command:
            raise ValueError("MCP command is empty")
        self.command = [str(part) for part in command]
        self.cwd = Path(cwd)
        self.env = env
        self.init_timeout = init_timeout
        self.log_path = log_path
        self._life_lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[int, Future] = {}
        self._next_id = 0
        self._process: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._job: _WindowsJob | None = None
        self._state = "stopped"
        self._last_error: str | None = None
        self._server_info: dict[str, Any] = {}
        self._tools: list[dict[str, Any]] = []
        self._stderr_tail: deque[str] = deque(maxlen=120)
        self._started_at: float | None = None
        self._ready_at: float | None = None
        self._restarts = 0
        self._calls = 0
        self._failures = 0
        self._unsolicited = 0

    # ------------------------------------------------------------------ status
    @property
    def state(self) -> str:
        return self._state

    def status(self) -> dict[str, Any]:
        with self._life_lock:
            process = self._process
            pid = process.pid if process and process.poll() is None else None
            return {
                "state": self._state,
                "transport": "stdio",
                "pid": pid,
                "server": dict(self._server_info),
                "tools": [tool.get("name") for tool in self._tools],
                "tool_count": len(self._tools),
                "command": self.command,
                "cwd": str(self.cwd),
                "started_at": self._started_at,
                "ready_at": self._ready_at,
                "uptime_seconds": round(time.time() - self._started_at, 1) if self._started_at else 0,
                "restarts": self._restarts,
                "calls": self._calls,
                "failures": self._failures,
                "last_error": self._last_error,
                "stderr_tail": list(self._stderr_tail)[-12:],
                "dedicated_instance": True,
            }

    # --------------------------------------------------------------- lifecycle
    def start(self) -> dict[str, Any]:
        with self._life_lock:
            if self._state == "ready" and self._process and self._process.poll() is None:
                return self.status()
            self._stop_locked(graceful=False)
            self._state = "starting"
            self._last_error = None
            env = dict(self.env if self.env is not None else os.environ)
            env.setdefault("PYTHONIOENCODING", "utf-8")
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                )
            log.info("Starting MCP stdio server: %s", " ".join(self.command))
            try:
                process = subprocess.Popen(
                    self.command,
                    cwd=str(self.cwd),
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=creationflags,
                )
            except Exception as exc:
                self._state = "error"
                self._last_error = f"Không khởi động được MCP: {exc}"
                raise MCPUnavailable(self._last_error) from exc
            self._process = process
            self._started_at = time.time()
            self._ready_at = None
            self._reader = threading.Thread(
                target=self._read_stdout, name="mcp-stdout", daemon=True
            )
            self._stderr_reader = threading.Thread(
                target=self._read_stderr, name="mcp-stderr", daemon=True
            )
            self._reader.start()
            self._stderr_reader.start()
            self._job = _WindowsJob()
            if self._job:
                self._job.assign(process.pid)
            try:
                self._initialize(process)
            except Exception as exc:
                self._last_error = str(exc)
                self._state = "error"
                self._stop_locked(graceful=False)
                raise
            self._state = "ready"
            self._ready_at = time.time()
            return self.status()

    def ensure_ready(self) -> dict[str, Any]:
        if self._state == "ready" and self._process and self._process.poll() is None:
            return self.status()
        with self._life_lock:
            if self._state == "ready" and self._process and self._process.poll() is None:
                return self.status()
            self._restarts += 1
            return self.start()

    def restart(self) -> dict[str, Any]:
        with self._life_lock:
            self._stop_locked(graceful=True)
            self._restarts += 1
            return self.start()

    def close(self, timeout: float = 12.0) -> None:
        with self._life_lock:
            self._stop_locked(graceful=True, timeout=timeout)

    def _stop_locked(self, *, graceful: bool, timeout: float = 10.0) -> None:
        process = self._process
        self._process = None
        self._state = "stopped"
        self._ready_at = None
        if process is None:
            return
        if process.poll() is None:
            try:
                if graceful and process.stdin:
                    process.stdin.close()
                process.wait(timeout=timeout)
            except Exception:
                try:
                    process.terminate()
                    process.wait(timeout=4)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
        for stream in (process.stdout, process.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass
        if self._job:
            self._job.close()
            self._job = None
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for future in pending:
            if not future.done():
                future.set_exception(MCPUnavailable("MCP đã dừng"))

    def __enter__(self) -> "StdioMCPClient":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------- IO
    def _initialize(self, process: subprocess.Popen) -> None:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
            timeout=self.init_timeout,
        )
        if not isinstance(result, dict):
            raise MCPUnavailable("MCP initialize trả về dữ liệu không hợp lệ")
        self._server_info = dict(result.get("serverInfo") or {})
        self._notify("notifications/initialized", {})
        listing = self._rpc("tools/list", {}, timeout=self.init_timeout)
        tools = listing.get("tools") if isinstance(listing, dict) else None
        if not isinstance(tools, list):
            raise MCPUnavailable("MCP tools/list trả về dữ liệu không hợp lệ")
        self._tools = tools
        # Remove start counters so uptime is accurate for this generation.
        self._started_at = time.time()
        self._ready_at = self._started_at

    def list_tools(self) -> list[dict[str, Any]]:
        return [dict(tool) for tool in self._tools]

    def call_tool(
        self, name: str, arguments: dict[str, Any], *, timeout: float = 120.0
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Call an MCP tool; return (payload, meta). Payload is decoded JSON text."""
        if self._state != "ready" or not self._process or self._process.poll() is not None:
            raise MCPUnavailable("MCP chưa sẵn sàng")
        request_id, future = self._send(
            "tools/call", {"name": name, "arguments": arguments}
        )
        started = time.monotonic()
        try:
            message = future.result(timeout=timeout)
        except FutureTimeout:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            self._failures += 1
            raise MCPTimeout(
                f"MCP không phản hồi sau {timeout:.0f}s khi gọi {name}",
                request_id=request_id,
            ) from None
        except MCPUnavailable:
            self._failures += 1
            raise
        self._calls += 1
        if "error" in message:
            error = message.get("error") or {}
            self._failures += 1
            code = error.get("code")
            text = str(error.get("message") or "MCP tool error")
            raise MCPCallError(text, code=code)
        result = message.get("result") or {}
        content = result.get("content") or []
        text = ""
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text += str(part.get("text") or "")
        payload: dict[str, Any]
        if text:
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                decoded = {"ok": False, "error": "InvalidJsonFromMCP", "text": text[:4000]}
            payload = decoded if isinstance(decoded, dict) else {"value": decoded}
        else:
            payload = {}
        meta = {
            "request_id": request_id,
            "is_error": bool(result.get("isError")),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "tool": name,
        }
        return payload, meta

    def ping(self, timeout: float = 5.0) -> bool:
        if self._state != "ready":
            return False
        try:
            self._rpc("ping", {}, timeout=timeout)
            return True
        except Exception:
            return False

    def _send(self, method: str, params: dict[str, Any]) -> tuple[int, Future]:
        process = self._process
        if not process or not process.stdin or process.poll() is not None:
            raise MCPUnavailable("MCP không chạy")
        with self._pending_lock:
            self._next_id += 1
            request_id = self._next_id
            future: Future = Future()
            self._pending[request_id] = future
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            with self._write_lock:
                process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
                process.stdin.flush()
        except Exception as exc:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise MCPUnavailable(f"Không gửi được yêu cầu tới MCP: {exc}") from exc
        return request_id, future

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        process = self._process
        if not process or not process.stdin:
            return
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        with self._write_lock:
            try:
                process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
                process.stdin.flush()
            except Exception:
                pass

    def _rpc(
        self, method: str, params: dict[str, Any], *, timeout: float
    ) -> Any:
        request_id, future = self._send(method, params)
        try:
            message = future.result(timeout=timeout)
        except FutureTimeout:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise MCPTimeout(f"MCP không phản hồi sau {timeout:.0f}s ({method})") from None
        if "error" in message:
            error = message.get("error") or {}
            raise MCPCallError(
                str(error.get("message") or "MCP error"), code=error.get("code")
            )
        return message.get("result")

    def _read_stdout(self) -> None:
        process = self._process
        if not process or not process.stdout:
            return
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("MCP stdout non-JSON line: %s", line[:300])
                    continue
                if not isinstance(message, dict):
                    continue
                request_id = message.get("id")
                if request_id is None:
                    self._unsolicited += 1
                    continue
                with self._pending_lock:
                    future = self._pending.pop(request_id, None)
                if future is not None and not future.done():
                    future.set_result(message)
        except Exception as exc:
            log.warning("MCP stdout reader stopped: %s", exc)
        finally:
            with self._pending_lock:
                pending = list(self._pending.values())
                self._pending.clear()
            for future in pending:
                if not future.done():
                    future.set_exception(MCPUnavailable("MCP đã đóng stdout"))
            with self._life_lock:
                if self._process is process:
                    if self._state == "ready":
                        self._last_error = "MCP process đã kết thúc"
                        self._state = "error"

    def _read_stderr(self) -> None:
        process = self._process
        if not process or not process.stderr:
            return
        try:
            for line in process.stderr:
                text = line.rstrip()
                if not text:
                    continue
                self._stderr_tail.append(text[:2000])
                if not text.startswith("WARNING: The script"):
                    log.debug("mcp stderr: %s", text[:500])
                if self.log_path:
                    try:
                        with self.log_path.open("a", encoding="utf-8") as handle:
                            handle.write(time.strftime("%Y-%m-%dT%H:%M:%S") + " " + text + "\n")
                    except OSError:
                        pass
        except Exception:
            pass
