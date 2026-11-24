"""Entrypoint used by START_WINDOWS.bat (single process: API + static UI)."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import starlette.routing
_orig_router_init = starlette.routing.Router.__init__
def _compat_router_init(self, *args, **kwargs):
    kwargs.pop("on_startup", None)
    kwargs.pop("on_shutdown", None)
    return _orig_router_init(self, *args, **kwargs)
starlette.routing.Router.__init__ = _compat_router_init

import fastapi
fastapi.FastAPI.max_body_size = None

import uvicorn  # noqa: E402

from backend.console.main import create_app  # noqa: E402
from backend.console.settings import Settings  # noqa: E402

log = logging.getLogger("netmiko_web.server")


def main() -> int:
    parser = argparse.ArgumentParser(description="Netmiko Web Console server")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()
    settings = Settings.load()
    if args.host:
        settings = settings.__class__(**{**settings.__dict__, "host": args.host})
    if args.port:
        settings = settings.__class__(**{**settings.__dict__, "port": args.port})
    app = create_app(settings)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level=args.log_level,
        access_log=False,
        loop="asyncio",
        lifespan="on",
    )
    server = uvicorn.Server(config)
    app.state.uvicorn_server = server
    try:
        server.run()
    except OSError as exc:
        log.error("Không mở được cổng %s:%s: %s", settings.host, settings.port, exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
