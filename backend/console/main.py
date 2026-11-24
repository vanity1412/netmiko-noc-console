"""FastAPI application for the Netmiko Web Console."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import starlette.routing

if not getattr(starlette.routing, "_compat_patched", False):
    _orig_router_init = starlette.routing.Router.__init__

    def _compat_router_init(self, *args, **kwargs):
        kwargs.pop("on_startup", None)
        kwargs.pop("on_shutdown", None)
        return _orig_router_init(self, *args, **kwargs)

    starlette.routing.Router.__init__ = _compat_router_init
    starlette.routing._compat_patched = True

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
FastAPI.max_body_size = None
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .evidence import EvidenceNotFound, EvidenceStore
from .exports import ExportService, export_filename
from .history import HistoryStore
from .inventory import InventoryService, InventoryUnavailable
from .credentials import CredentialError, CredentialStore
from .lsp import LspNotFound, LspService, LspValidationError
from .agent import AgentService
from .mcp_client import StdioMCPClient
from .runner import RunManager, RunValidationError
from .settings import VERSION, Settings, display_command

log = logging.getLogger("netmiko_web")


def configure_logging(settings: Settings) -> None:
    if getattr(configure_logging, "_configured", False):
        return
    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        settings.logs_dir / "web-console.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger("netmiko_web")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(console)
    root.propagate = False
    configure_logging._configured = True


class RunOptions(BaseModel):
    concurrency: int = Field(default=6, ge=1, le=16)
    read_timeout: int = Field(default=30, ge=5, le=120)
    continue_on_error: bool = True


class RunRequest(BaseModel):
    devices: list[str] = Field(min_length=1)
    commands: list[str] = Field(min_length=1)
    options: RunOptions = Field(default_factory=RunOptions)
    note: str = Field(default="", max_length=200)


class CredentialProfileInput(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str | None = Field(default=None, max_length=4096)
    secret: str | None = Field(default=None, max_length=4096)
    passphrase: str | None = Field(default=None, max_length=4096)
    key_file: str | None = Field(default=None, max_length=4096)
    use_keys: bool | None = None
    allow_agent: bool | None = None
    clear_password: bool = False
    clear_secret: bool = False
    clear_passphrase: bool = False


class VisibilityNote(BaseModel):
    transport: str = "stdio"
    dedicated_instance: bool = True


class LspDiscoverRequest(BaseModel):
    source: str = Field(min_length=1, max_length=256)
    lsp: str = Field(default="", max_length=160)
    refresh: bool = False


class LspTraceRequest(BaseModel):
    source: str = Field(min_length=1, max_length=256)
    lsp: str = Field(min_length=1, max_length=160)
    discovery_id: str | None = Field(default=None, max_length=80)
    label: str = Field(default="", max_length=120)
    snapshot_type: str = Field(default="CAPTURE", max_length=16)
    refresh: bool = False


class LspCompareRequest(BaseModel):
    before: str = Field(min_length=1, max_length=80)
    after: str = Field(min_length=1, max_length=80)


class LspPlanRequest(BaseModel):
    ticket: str = Field(min_length=1, max_length=200_000)
    source: str = Field(default="", max_length=256)
    lsp: str = Field(default="", max_length=160)


class LspClassifyRequest(BaseModel):
    label: str = Field(default="", max_length=120)
    snapshot_type: str = Field(default="", max_length=16)


class AgentAnalyzeRequest(BaseModel):
    ticket: str = Field(min_length=1, max_length=100_000)
    history: list[dict[str, Any]] | None = None
    provider: str | None = None
    model: str | None = None
    reasoning_effort: str | None = "high"
    api_key: str | None = None


class AgentInvestigateRequest(BaseModel):
    ticket: str = Field(min_length=1, max_length=100_000)
    history: list[dict[str, Any]] | None = None
    auto_execute: bool = True
    provider: str | None = None
    model: str | None = None
    reasoning_effort: str | None = "high"
    api_key: str | None = None


class AgentTestRequest(BaseModel):
    provider: str | None = None
    model: str | None = None


class AgentConfigRequest(BaseModel):
    active_provider: str | None = None
    active_model: str | None = None
    reasoning_effort: str | None = None
    providers: dict[str, Any] | None = None
    email: dict[str, Any] | None = None


class AgentEmailTestRequest(BaseModel):
    host: str | None = None
    port: int | None = None
    security: str | None = None
    sender: str | None = None
    username: str | None = None
    password: str | None = None
    recipient: str | None = None


class AgentSendEmailReportRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=500)
    report: str = Field(min_length=1, max_length=200_000)
    recipient: str | None = None


def _json_error(status: int, code: str, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, **extra}},
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    configure_logging(settings)
    settings.ensure_dirs()
    instance_id = uuid.uuid4().hex
    token = secrets.token_urlsafe(32) if settings.require_token else ""
    started_at = time.time()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        history = HistoryStore(settings.db_path, settings.runs_dir)
        interrupted = history.mark_interrupted()
        pruned = history.prune(settings.keep_runs)
        mcp = StdioMCPClient(
            settings.mcp_command,
            cwd=settings.mcp_cwd,
            log_path=settings.logs_dir / "mcp-stderr.log",
        )
        inventory = InventoryService(settings, mcp)
        evidence = EvidenceStore(settings, history)
        exports = ExportService(settings, history, evidence)
        runner = RunManager(settings, mcp, history, inventory)
        credentials = CredentialStore(settings, inventory)
        lsp = LspService(settings, mcp, inventory)
        agent = AgentService(settings, mcp, inventory)
        app.state.settings = settings
        app.state.history = history
        app.state.mcp = mcp
        app.state.inventory = inventory
        app.state.evidence = evidence
        app.state.exports = exports
        app.state.runner = runner
        app.state.credentials = credentials
        app.state.lsp = lsp
        app.state.agent = agent
        app.state.instance_id = instance_id
        app.state.token = token
        app.state.started_at = started_at
        app.state.shutdown_event = asyncio.Event()
        app.state.interrupted_runs = interrupted
        app.state.pruned_runs = pruned
        _write_runtime(app, settings)
        log.info(
            "Web Console %s started on %s:%s (instance %s, MCP %s)",
            VERSION,
            settings.host,
            settings.port,
            instance_id,
            "enabled" if settings.mcp_command else "disabled",
        )

        async def start_mcp() -> None:
            try:
                await asyncio.to_thread(mcp.start)
                _write_runtime(app, settings)
                log.info("MCP ready: pid=%s tools=%s", mcp.status().get("pid"), mcp.status().get("tool_count"))
            except Exception as exc:
                log.warning("MCP failed to start: %s", exc)

        app.state.mcp_start_task = asyncio.create_task(start_mcp())
        try:
            yield
        finally:
            task = getattr(app.state, "mcp_start_task", None)
            if task and not task.done():
                task.cancel()
            try:
                await asyncio.to_thread(mcp.close)
            except Exception:
                log.warning("MCP close failed", exc_info=True)
            try:
                history.close()
            except Exception:
                pass
            try:
                if settings.runtime_file.is_file():
                    data = json.loads(settings.runtime_file.read_text(encoding="utf-8"))
                    if data.get("instance_id") == instance_id:
                        settings.runtime_file.unlink(missing_ok=True)
            except OSError:
                pass
            log.info("Web Console stopped (instance %s)", instance_id)

    app = FastAPI(
        title="Netmiko Web Console",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # ------------------------------------------------------------- middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0].strip().lower()
        allowed_hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
        if host and host not in allowed_hosts:
            return _json_error(421, "bad_host", "Host không hợp lệ cho Web Console nội bộ")
        path = request.url.path
        if (
            settings.require_token
            and path.startswith("/api/")
            and path not in {"/api/health", "/api/bootstrap"}
        ):
            supplied = request.headers.get("x-web-console-token") or ""
            if not secrets.compare_digest(supplied, token):
                return _json_error(401, "unauthorized", "Thiếu hoặc sai token Web Console")
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    # ------------------------------------------------------------ diagnostics
    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        mcp = app.state.mcp
        return {
            "status": "ok",
            "instance_id": instance_id,
            "version": VERSION,
            "uptime_seconds": round(time.time() - started_at, 1),
            "active_runs": app.state.runner.active_count(),
            "mcp_state": mcp.state,
            "inventory_cached": app.state.inventory._snapshot is not None,
            "time": time.time(),
        }

    @app.get("/api/bootstrap")
    async def bootstrap() -> dict[str, Any]:
        mcp = app.state.mcp
        return {
            "token": token,
            "version": VERSION,
            "instance_id": instance_id,
            "uptime_seconds": round(time.time() - started_at, 1),
            "limits": {
                "max_devices_per_run": settings.max_devices_per_run,
                "max_commands_per_run": settings.max_commands_per_run,
                "max_concurrency": settings.max_concurrency,
                "default_concurrency": settings.default_concurrency,
                "command_max_len": settings.command_max_len,
            },
            "mcp": _mcp_public(mcp),
            "interrupted_runs": app.state.interrupted_runs,
        }

    def _mcp_public(mcp: StdioMCPClient, *, sessions: bool = False) -> dict[str, Any]:
        status = mcp.status()
        command_display = display_command(status.pop("command", []))
        command_display = command_display.replace(str(settings.root), "<app>")
        command_display = command_display.replace(str(settings.root.parent), "<workspace>")
        status["command_display"] = command_display
        cwd = str(status.get("cwd"))
        if cwd == str(settings.root):
            cwd = "."
        elif cwd == str(settings.root.parent):
            cwd = "<workspace>"
        status["cwd"] = cwd
        status["note"] = (
            "MCP server chạy stdio trong process riêng do Web Console quản lý. "
            "Web Console dùng MCP server bundled trong vendor/mcp, không viết lại SSH engine. "
            "Session pool, autodetect, reader và evidence thuộc instance này."
        )
        status["visibility"] = {"transport": "stdio", "dedicated_instance": True}
        status["web_mcp_shim"] = {
            "juniper_terminal_setup": os.environ.get("NETMIKO_WEB_JUNIPER_PREP", "skip").strip().lower(),
            "launcher": "<app>/backend/console/mcp_launcher.py",
            "note": (
                "MCP chạy stdio trong process riêng do Web Console quản lý. "
                "Mặc định bỏ 3 lệnh set cli terminal của Juniper để tương thích login class bị giới hạn; "
                "đặt NETMIKO_WEB_JUNIPER_PREP=strict để dùng hành vi gốc."
            ),
        }
        if sessions:
            try:
                payload, meta = mcp.call_tool("ssh_status", {}, timeout=8)
                status["session_pool"] = {
                    "version": payload.get("version"),
                    "sessions": len(payload.get("sessions") or []),
                    "connections_opened": payload.get("connections_opened"),
                    "session_reuses": payload.get("session_reuses"),
                    "connection_failures": payload.get("connection_failures"),
                    "max_sessions": payload.get("max_sessions"),
                    "max_workers": payload.get("max_workers"),
                    "output_dir": str(payload.get("output_dir") or "").replace(
                        str(settings.root), "<app>"
                    ),
                    "autodetect_cache_hits": payload.get("autodetect_cache_hits"),
                    "persistent_autodetect_hits": payload.get("persistent_autodetect_hits"),
                    "latency_ms": meta.get("duration_ms"),
                }
            except Exception as exc:
                status["session_pool_error"] = str(exc)
        return status

    @app.get("/api/mcp/status")
    async def mcp_status(sessions: bool = Query(default=False)) -> dict[str, Any]:
        return await asyncio.to_thread(_mcp_public, app.state.mcp, sessions=sessions)

    @app.post("/api/mcp/restart")
    async def mcp_restart() -> Any:
        if app.state.runner.active_count():
            return _json_error(
                409,
                "run_active",
                "Không restart MCP khi đang có run chạy; hãy chờ hoặc dừng nhận thiết bị mới trước.",
            )
        try:
            status = await asyncio.to_thread(app.state.mcp.restart)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Không restart được MCP: {exc}") from exc
        app.state.inventory.invalidate()
        _write_runtime(app, settings)
        return {"ok": True, "mcp": _mcp_public(app.state.mcp)}

    # -------------------------------------------------------------- inventory
    @app.get("/api/inventory")
    async def inventory(
        q: str = "",
        vendor: str = "",
        device_type: str = "",
        category: str = "",
        pop: str = "",
        zone: str = "",
        profile: str = "",
        function: str = "",
        page: int = 1,
        limit: int = 100,
        sort: str = "name",
        direction: str = "asc",
    ) -> Any:
        try:
            snapshot = await asyncio.to_thread(app.state.inventory.get)
        except InventoryUnavailable as exc:
            return _json_error(503, "inventory_unavailable", str(exc))
        result = snapshot.query(
            q=q,
            vendors=[vendor],
            device_types=[device_type],
            categories=[category],
            pops=[pop],
            zones=[zone],
            profiles=[profile],
            functions=[function],
            page=page,
            limit=limit,
            sort=sort,
            direction=direction,
        )
        result["meta"] = _inventory_meta(app.state.mcp, snapshot)
        return result

    @app.get("/api/inventory/names")
    async def inventory_names(
        q: str = "",
        vendor: str = "",
        device_type: str = "",
        category: str = "",
        pop: str = "",
        zone: str = "",
        profile: str = "",
        function: str = "",
    ) -> Any:
        try:
            snapshot = await asyncio.to_thread(app.state.inventory.get)
        except InventoryUnavailable as exc:
            return _json_error(503, "inventory_unavailable", str(exc))
        names = snapshot.names(
            q=q,
            vendors=[vendor],
            device_types=[device_type],
            categories=[category],
            pops=[pop],
            zones=[zone],
            profiles=[profile],
            functions=[function],
        )
        items = [
            {
                "name": name,
                "vendor": snapshot.by_name[name]["vendor"],
                "device_type": snapshot.by_name[name]["device_type"],
            }
            for name in names
        ]
        return {"names": names, "items": items, "total": len(names)}

    @app.post("/api/inventory/refresh")
    async def inventory_refresh() -> Any:
        try:
            snapshot = await asyncio.to_thread(app.state.inventory.get, force=True)
        except InventoryUnavailable as exc:
            return _json_error(503, "inventory_unavailable", str(exc))
        return {
            "ok": True,
            "total": len(snapshot.devices),
            "meta": _inventory_meta(app.state.mcp, snapshot),
        }

    def _inventory_meta(mcp: StdioMCPClient, snapshot) -> dict[str, Any]:
        meta = dict(snapshot.meta)
        meta["cache_age_seconds"] = round(time.time() - snapshot.cached_at, 1)
        meta["mcp_state"] = mcp.state
        return meta

    @app.get("/api/presets")
    async def presets() -> dict[str, Any]:
        path = settings.presets_path
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Preset lỗi: {exc}") from exc
        return data

    # ------------------------------------------------------------------- runs
    @app.post("/api/runs")
    async def create_run(payload: RunRequest) -> Any:
        try:
            summary = await app.state.runner.start_run(
                payload.devices,
                payload.commands,
                payload.options.model_dump(),
                note=payload.note,
            )
        except RunValidationError as exc:
            return _json_error(400, "run_rejected", str(exc))
        return JSONResponse(status_code=202, content={"run": summary})

    @app.get("/api/runs")
    async def list_runs(limit: int = 50, offset: int = 0) -> dict[str, Any]:
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        return await asyncio.to_thread(app.state.history.list_runs, limit, offset)

    @app.delete("/api/runs/{run_id}")
    async def delete_run(run_id: str) -> Any:
        try:
            deleted = await app.state.runner.delete_run(run_id)
        except (RunValidationError, RuntimeError) as exc:
            return _json_error(409, "run_active", str(exc))
        if not deleted:
            return _json_error(404, "run_not_found", "Không tìm thấy run")
        return {"deleted": True, "run_id": run_id}

    @app.delete("/api/runs")
    async def delete_finished_runs() -> dict[str, Any]:
        deleted = await app.state.runner.delete_finished()
        return {"deleted": deleted}

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> Any:
        state = app.state.runner.get(run_id)
        if state is not None:
            data = state.summary()
            data["devices"] = state.public_devices()
            return {"run": data, "live": True}
        detail = await asyncio.to_thread(app.state.history.get_run, run_id)
        if detail is None:
            return _json_error(404, "run_not_found", "Không tìm thấy run")
        return {"run": detail, "live": False}

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, request: Request) -> StreamingResponse:
        async def stream():
            try:
                async for event in app.state.runner.subscribe(run_id):
                    if await request.is_disconnected():
                        break
                    yield f"event: {event.get('type', 'message')}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("SSE failed for %s: %s", run_id, exc)
                yield "event: error\ndata: " + json.dumps({"type": "error", "message": str(exc)}) + "\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_run(run_id: str) -> Any:
        try:
            return app.state.runner.cancel(run_id)
        except RunValidationError as exc:
            return _json_error(400, "cancel_failed", str(exc))

    @app.post("/api/runs/{run_id}/retry-failed")
    async def retry_failed(run_id: str) -> Any:
        try:
            summary = await app.state.runner.retry_failed(run_id)
        except RunValidationError as exc:
            return _json_error(400, "retry_rejected", str(exc))
        return JSONResponse(status_code=202, content={"run": summary})

    @app.get("/api/runs/{run_id}/devices/{name}/output")
    async def device_output(
        run_id: str, name: str, offset: int = 0, limit: int = 0
    ) -> Any:
        try:
            return await asyncio.to_thread(
                app.state.evidence.page,
                run_id,
                name,
                offset=offset,
                limit=limit or settings.output_page_lines,
            )
        except EvidenceNotFound as exc:
            return _json_error(404, "evidence_not_found", str(exc))

    @app.get("/api/runs/{run_id}/devices/{name}/search")
    async def device_search(
        run_id: str,
        name: str,
        q: str,
        regex: bool = False,
        limit: int = 200,
    ) -> Any:
        try:
            return await asyncio.to_thread(
                app.state.evidence.search,
                run_id,
                name,
                q,
                regex=regex,
                limit=limit,
            )
        except EvidenceNotFound as exc:
            return _json_error(404, "evidence_not_found", str(exc))
        except ValueError as exc:
            return _json_error(400, "invalid_query", str(exc))

    @app.get("/api/runs/{run_id}/devices/{name}/raw")
    async def device_raw(run_id: str, name: str) -> Any:
        try:
            path = app.state.evidence.path(run_id, name)
        except EvidenceNotFound as exc:
            return _json_error(404, "evidence_not_found", str(exc))
        return FileResponse(
            path,
            media_type="text/plain; charset=utf-8",
            filename=_download_name(name) + ".txt",
        )

    @app.get("/api/runs/{run_id}/export")
    async def export_run(run_id: str, format: str = "txt") -> Any:
        fmt = format.lower().strip()
        detail = await asyncio.to_thread(app.state.history.get_run, run_id, include_steps=False)
        if detail is None:
            return _json_error(404, "run_not_found", "Không tìm thấy run")
        if fmt == "zip":
            try:
                path, filename = await asyncio.to_thread(
                    app.state.exports.zip, run_id
                )
            except Exception as exc:
                log.exception("zip export failed")
                return _json_error(500, "export_failed", str(exc))
            return FileResponse(
                path,
                media_type="application/zip",
                filename=filename,
                background=_unlink_background(path),
            )
        if fmt not in {"txt", "csv", "json"}:
            return _json_error(400, "invalid_format", "format phải là txt, csv, json hoặc zip")
        generator = getattr(app.state.exports, fmt)(run_id)
        media = {"txt": "text/plain; charset=utf-8", "csv": "text/csv; charset=utf-8",
                 "json": "application/json; charset=utf-8"}[fmt]
        return StreamingResponse(
            generator,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{export_filename(run_id, fmt)}"',
                "Cache-Control": "no-store",
            },
        )

    # ------------------------------------------------------------- credentials
    def _credential_headers() -> dict[str, str]:
        return {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"}

    @app.get("/api/credentials")
    async def list_credentials() -> Any:
        try:
            data = await asyncio.to_thread(app.state.credentials.list)
        except CredentialError as exc:
            return _json_error(400, "credential_error", str(exc))
        return JSONResponse(content=data, headers=_credential_headers())

    @app.get("/api/credentials/{name}/reveal")
    async def reveal_credential(name: str) -> Any:
        try:
            data = await asyncio.to_thread(app.state.credentials.reveal, name)
        except CredentialError as exc:
            return _json_error(404, "credential_not_found", str(exc))
        return JSONResponse(content=data, headers=_credential_headers())

    @app.post("/api/credentials/{name}")
    async def save_credential(name: str, payload: CredentialProfileInput) -> Any:
        try:
            result = await asyncio.to_thread(
                app.state.credentials.upsert,
                name,
                **payload.model_dump(),
            )
            listing = await asyncio.to_thread(app.state.credentials.list)
        except CredentialError as exc:
            return _json_error(400, "credential_invalid", str(exc))
        return JSONResponse(
            content={
                **result,
                "profiles": listing["profiles"],
                "unused_profiles": listing["unused_profiles"],
            },
            headers=_credential_headers(),
        )

    @app.delete("/api/credentials/{name}")
    async def delete_credential(name: str, force: bool = False) -> Any:
        usage = await asyncio.to_thread(app.state.credentials.usage)
        used = usage.get(name, 0)
        if not force and (name == "default" or used):
            reason = (
                "Profile 'default' đang là profile mặc định"
                if name == "default"
                else f"Có {used} thiết bị đang dùng profile '{name}'"
            )
            return _json_error(409, "credential_in_use", reason)
        try:
            result = await asyncio.to_thread(app.state.credentials.delete, name, force=force)
            listing = await asyncio.to_thread(app.state.credentials.list)
        except CredentialError as exc:
            return _json_error(400, "credential_invalid", str(exc))
        return JSONResponse(
            content={
                **result,
                "profiles": listing["profiles"],
                "unused_profiles": listing["unused_profiles"],
            },
            headers=_credential_headers(),
        )

    # -------------------------------------------------------------- LSP ViewPath
    def _lsp_error(exc: Exception) -> JSONResponse:
        if isinstance(exc, LspNotFound):
            return _json_error(404, "lsp_not_found", str(exc))
        if isinstance(exc, LspValidationError):
            return _json_error(400, "lsp_invalid", str(exc))
        if isinstance(exc, KeyError):
            return _json_error(404, "lsp_not_found", f"Không tìm thấy LSP {exc}")
        log.exception("LSP operation failed")
        return _json_error(500, "lsp_error", str(exc))

    @app.get("/api/lsp/status")
    async def lsp_status() -> dict[str, Any]:
        return {
            "ok": True,
            "cache_ttl_seconds": settings.lsp_cache_ttl_seconds,
            "max_verify_nodes": settings.lsp_max_verify_nodes,
            "snapshots": len(app.state.lsp.list_snapshots(limit=500)),
            "read_only": True,
            "note": (
                "LSP ViewPath chỉ chạy lệnh show/display qua Netmiko MCP; "
                "không commit, không đổi LSP, không mở SSH engine mới."
            ),
        }

    @app.post("/api/lsp/discover")
    async def lsp_discover(payload: LspDiscoverRequest) -> Any:
        try:
            return await app.state.lsp.discover(
                payload.source, payload.lsp, refresh=payload.refresh
            )
        except Exception as exc:  # noqa: BLE001 - mapped to a JSON error
            return _lsp_error(exc)

    @app.post("/api/lsp/trace")
    async def lsp_trace(payload: LspTraceRequest) -> Any:
        try:
            return await app.state.lsp.trace(
                payload.source,
                payload.lsp,
                discovery_id=payload.discovery_id,
                label=payload.label,
                snapshot_type=payload.snapshot_type,
                refresh=payload.refresh,
            )
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)

    @app.post("/api/lsp/refresh")
    async def lsp_refresh() -> dict[str, Any]:
        app.state.lsp.refresh()
        return {"ok": True, "message": "Đã xóa cache LSP; lần Discover/Trace tiếp theo sẽ đọc lại thiết bị"}

    @app.get("/api/lsp/snapshots")
    async def lsp_snapshots(limit: int = 50) -> dict[str, Any]:
        items = await asyncio.to_thread(app.state.lsp.list_snapshots, limit=max(1, min(limit, 200)))
        return {"snapshots": items, "total": len(items)}

    @app.get("/api/lsp/snapshots/{snapshot_id}")
    async def lsp_snapshot(snapshot_id: str) -> Any:
        try:
            return await asyncio.to_thread(app.state.lsp.get_snapshot, snapshot_id)
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)

    @app.delete("/api/lsp/snapshots/{snapshot_id}")
    async def lsp_snapshot_delete(snapshot_id: str) -> Any:
        try:
            deleted = await asyncio.to_thread(app.state.lsp.delete_snapshot, snapshot_id)
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)
        if not deleted:
            return _json_error(404, "lsp_not_found", "Không tìm thấy snapshot LSP")
        return {"deleted": True, "snapshot_id": snapshot_id, "raw_deleted": True}

    @app.delete("/api/lsp/snapshots")
    async def lsp_snapshots_delete_all() -> Any:
        try:
            result = await asyncio.to_thread(app.state.lsp.delete_all_snapshots)
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)
        return {"deleted": True, **result}

    @app.delete("/api/lsp/raw/discovery")
    async def lsp_discovery_raw_delete() -> Any:
        try:
            result = await asyncio.to_thread(
                app.state.lsp.cleanup_raw, include_discovery=True
            )
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)
        return {"deleted": True, **result}

    @app.delete("/api/lsp/raw/{snapshot_id}")
    async def lsp_raw_delete(snapshot_id: str) -> Any:
        try:
            files = await asyncio.to_thread(app.state.lsp.delete_raw, snapshot_id)
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)
        return {"deleted": True, "snapshot_id": snapshot_id, "files": files}

    @app.post("/api/lsp/snapshots/{snapshot_id}/classify")
    async def lsp_snapshot_classify(snapshot_id: str, payload: LspClassifyRequest) -> Any:
        try:
            record = await asyncio.to_thread(
                app.state.lsp.classify_snapshot,
                snapshot_id,
                label=payload.label,
                snapshot_type=payload.snapshot_type,
            )
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)
        return {
            "id": record.get("id"),
            "label": record.get("label"),
            "snapshot_type": record.get("snapshot_type"),
            "created_at": record.get("created_at"),
        }

    @app.post("/api/lsp/compare")
    async def lsp_compare(payload: LspCompareRequest) -> Any:
        try:
            return await asyncio.to_thread(app.state.lsp.compare, payload.before, payload.after)
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)

    @app.post("/api/lsp/plan")
    async def lsp_plan(payload: LspPlanRequest) -> Any:
        try:
            return await asyncio.to_thread(
                app.state.lsp.plan, payload.ticket, source=payload.source, lsp=payload.lsp
            )
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)

    @app.get("/api/lsp/evidence/{snapshot_id}/{evidence_id}")
    async def lsp_evidence(snapshot_id: str, evidence_id: str) -> Any:
        try:
            return await asyncio.to_thread(
                app.state.lsp.read_evidence, snapshot_id, evidence_id
            )
        except Exception as exc:  # noqa: BLE001
            return _lsp_error(exc)

    # ------------------------------------------------------------- AI NOC Agent
    @app.get("/api/agent/status")
    @app.get("/api/agent/config")
    async def agent_status() -> dict[str, Any]:
        return app.state.agent.get_status()

    @app.get("/api/agent/configured_models")
    async def agent_configured_models() -> dict[str, Any]:
        return {"ok": True, "configured_models": app.state.agent.get_configured_models()}

    @app.get("/api/agent/models")
    async def agent_models(provider: str | None = None) -> dict[str, Any]:
        models = await app.state.agent.fetch_models(provider=provider)
        return {"ok": True, "provider": provider or app.state.agent.config.get("active_provider"), "models": models}

    @app.post("/api/agent/config")
    async def agent_save_config(payload: AgentConfigRequest) -> dict[str, Any]:
        return app.state.agent.save_config(payload.model_dump(exclude_unset=True))

    @app.post("/api/agent/test")
    async def agent_test_connection(payload: AgentTestRequest) -> dict[str, Any]:
        return await app.state.agent.test_connection(provider=payload.provider, model=payload.model)

    @app.post("/api/agent/sync_opencode")
    async def agent_sync_opencode() -> dict[str, Any]:
        return app.state.agent.sync_from_opencode()

    @app.post("/api/agent/login_chatgpt_browser")
    async def agent_login_chatgpt_browser() -> dict[str, Any]:
        return app.state.agent.trigger_chatgpt_browser_login()

    @app.get("/api/agent/email")
    async def agent_get_email() -> dict[str, Any]:
        return {"ok": True, "email": app.state.agent.get_email_settings()}

    @app.post("/api/agent/email/test")
    async def agent_test_email(payload: AgentEmailTestRequest) -> dict[str, Any]:
        override = {k: v for k, v in payload.model_dump().items() if v is not None}
        return await asyncio.to_thread(app.state.agent.test_email_connection, override or None)

    @app.post("/api/agent/email/send")
    async def agent_send_email(payload: AgentSendEmailReportRequest) -> dict[str, Any]:
        return await asyncio.to_thread(
            app.state.agent.send_email_report,
            payload.subject,
            payload.report,
            recipient=payload.recipient,
        )

    @app.post("/api/agent/analyze")
    async def agent_analyze(payload: AgentAnalyzeRequest) -> Any:
        try:
            result = await app.state.agent.analyze_ticket_quick(
                payload.ticket,
                history=payload.history,
                provider=payload.provider,
                model=payload.model,
                reasoning_effort=payload.reasoning_effort,
            )
            return result
        except Exception as exc:
            log.exception("Agent analyze failed")
            return _json_error(500, "agent_error", str(exc))

    @app.post("/api/agent/investigate")
    async def agent_investigate(payload: AgentInvestigateRequest) -> Any:
        async def event_generator():
            try:
                async for event in app.state.agent.run_investigation_stream(
                    payload.ticket,
                    history=payload.history,
                    auto_execute=payload.auto_execute,
                    provider=payload.provider,
                    model=payload.model,
                    reasoning_effort=payload.reasoning_effort,
                ):
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            except Exception as exc:
                log.exception("Agent investigation stream error")
                err_ev = {"type": "error", "message": str(exc)}
                yield f"data: {json.dumps(err_ev, ensure_ascii=False)}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # ---------------------------------------------------------------- shutdown
    @app.post("/api/admin/shutdown")
    async def shutdown(force: bool = False) -> Any:
        active = app.state.runner.active_count()
        if active and not force:
            return _json_error(
                409,
                "run_active",
                f"Còn {active} run đang chạy; dùng force=true nếu thực sự muốn dừng Web",
            )

        def trigger() -> None:
            server = getattr(app.state, "uvicorn_server", None)
            if server is not None:
                server.should_exit = True
            else:
                app.state.shutdown_event.set()

        asyncio.get_running_loop().call_later(0.2, trigger)
        return {"ok": True, "message": "Web Console đang dừng"}

    # ----------------------------------------------------------------- static
    static_dir = settings.static_dir
    if (static_dir / "index.html").is_file():
        assets = static_dir / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/")
        async def index() -> FileResponse:
            return FileResponse(
                static_dir / "index.html",
                media_type="text/html; charset=utf-8",
                headers={"Cache-Control": "no-store, max-age=0"},
            )

        @app.get("/{path:path}")
        async def spa(path: str) -> Any:
            if path.startswith("api/"):
                return _json_error(404, "not_found", "API không tồn tại")
            candidate = (static_dir / path).resolve()
            if static_dir.resolve() in candidate.parents and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(
                static_dir / "index.html",
                media_type="text/html; charset=utf-8",
                headers={"Cache-Control": "no-store, max-age=0"},
            )
    else:

        @app.get("/")
        async def missing_frontend() -> PlainTextResponse:
            return PlainTextResponse(
                "Frontend chưa được build. Chạy START_WINDOWS.bat để build tự động, "
                "hoặc: cd frontend && npm install && npm run build",
                status_code=503,
            )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s", request.url.path)
        return _json_error(500, "internal_error", "Lỗi nội bộ Web Console")

    return app


def _write_runtime(app: FastAPI, settings: Settings) -> None:
    try:
        mcp_status = app.state.mcp.status()
        data = {
            "instance_id": app.state.instance_id,
            "pid": os.getpid(),
            "host": settings.host,
            "port": settings.port,
            "token": app.state.token,
            "started_at": app.state.started_at,
            "version": VERSION,
            "mcp_pid": mcp_status.get("pid"),
            "mcp_state": mcp_status.get("state"),
        }
        settings.ensure_dirs()
        temporary = settings.runtime_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=1), encoding="utf-8")
        temporary.replace(settings.runtime_file)
    except OSError as exc:  # pragma: no cover
        log.warning("cannot write runtime file: %s", exc)


def _unlink_background(path: Path):
    from starlette.background import BackgroundTask

    def cleanup() -> None:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass

    return BackgroundTask(cleanup)


def _download_name(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")[:80]
    return value or "device"
