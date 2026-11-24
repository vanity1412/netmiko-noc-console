"""Web Console launcher for the bundled Netmiko MCP server.

The Web Console ships its own MCP server under ``vendor/mcp`` and launches it
with the existing MCP config, session pool and tools. It does not modify any
external MCP installation.

For restricted Junos login classes, Netmiko's three terminal-setup commands

    set cli screen-width 511
    set cli complete-on-space off
    set cli screen-length 0

are skipped by default for this MCP child. Set
``NETMIKO_WEB_JUNIPER_PREP=strict`` before starting the Web Console to restore
the original behavior.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARENT = ROOT.parent
DEFAULT_MCP_ROOT = PARENT / "mcp"


def log(message: str) -> None:
    sys.stderr.write("[web-mcp-shim] " + message + "\n")
    sys.stderr.flush()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def patch_juniper_preparation(backend, *, mode: str) -> None:
    if mode != "skip":
        log("Juniper terminal setup uses original MCP/Netmiko behavior")
        return
    try:
        from netmiko.juniper.juniper import JuniperBase
    except (ImportError, ModuleNotFoundError):
        log("netmiko Juniper driver not available; shim skipped")
        return

    def web_session_preparation(conn) -> None:
        """Minimal prompt preparation, without restricted set-cli commands."""
        conn._test_channel_read(pattern=r"[%>$#]")
        conn.enter_cli_mode()
        prompt = backend.last_prompt(conn.find_prompt())
        if not prompt:
            raise ValueError("Junos did not return a valid CLI prompt before setup")
        conn.base_prompt = prompt[:-1]
        conn._network_prompt_text = prompt
        conn._network_prompt_regex = r"(?m)^" + re.escape(prompt) + r"\s*$"
        conn._network_juniper_terminal_setup_skipped = True

    JuniperBase.session_preparation = web_session_preparation
    try:
        from netmiko.juniper.juniper import JuniperSSH, JuniperTelnet

        # Defensive: some Netmiko releases may define the method on subclasses.
        for cls in (JuniperSSH, JuniperTelnet):
            if cls.session_preparation is not web_session_preparation:
                cls.session_preparation = web_session_preparation
    except Exception:
        pass
    log(
        "Juniper terminal setup commands skipped for Web MCP child "
        "(screen-width/complete-on-space/screen-length). Output may wrap at 80 columns; "
        "MCP pager handling remains active."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--inventory-csv")
    parser.add_argument("--credentials-file")
    parser.add_argument("--output-dir")
    parser.add_argument("--mcp-root", default=str(DEFAULT_MCP_ROOT))
    parser.add_argument("--known-hosts")
    parser.add_argument("--autodetect-cache")
    parser.add_argument(
        "--junos-prep",
        default=os.environ.get("NETMIKO_WEB_JUNIPER_PREP", "skip").strip().lower(),
        choices=["skip", "strict"],
    )
    args = parser.parse_args()

    mcp_root = Path(args.mcp_root).resolve()
    bootstrap_path = mcp_root / "bootstrap.py"
    backend_path = mcp_root / "collector_backend.py"
    if not bootstrap_path.is_file() or not backend_path.is_file():
        raise SystemExit(f"MCP source not found under {mcp_root}")

    if str(mcp_root) not in sys.path:
        sys.path.insert(0, str(mcp_root))
    if str(PARENT) not in sys.path:
        sys.path.insert(0, str(PARENT))

    bootstrap = load_module("web_mcp_bootstrap", bootstrap_path)
    bootstrap.prepare_environment()
    backend = load_module("goosenet_collector", backend_path)

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = mcp_root / config_path
    config = backend.load_config(str(config_path), credentials_file=args.credentials_file)
    if args.inventory_csv:
        inventory_path = Path(args.inventory_csv)
        if not inventory_path.is_absolute():
            inventory_path = mcp_root / inventory_path
        config = backend.load_inventory_csv(config, str(inventory_path))
    known_hosts = Path(args.known_hosts or (mcp_root / "ssh" / "known_hosts")).resolve()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    autodetect_cache = Path(
        args.autodetect_cache or (ROOT / "data" / "autodetect.sqlite3")
    ).resolve()
    autodetect_cache.parent.mkdir(parents=True, exist_ok=True)
    config.setdefault("defaults", {})["alt_key_file"] = str(known_hosts)
    config["defaults"].setdefault("alt_host_keys", True)
    config["defaults"]["autodetect_cache_file"] = str(autodetect_cache)
    if args.output_dir:
        output_path = Path(args.output_dir)
        config["defaults"]["output_dir"] = str(
            output_path if output_path.is_absolute() else PARENT / output_path
        )

    collector = backend.Collector(config)
    patch_juniper_preparation(backend, mode=args.junos_prep)
    log(
        json.dumps(
            {
                "junos_prep": args.junos_prep,
                "devices": len(collector.devices),
                "output_dir": str(collector.output_dir),
                "known_hosts": str(known_hosts),
                "autodetect_cache": str(autodetect_cache),
                "mcp_root": str(mcp_root),
            },
            ensure_ascii=False,
        )
    )
    if hasattr(backend, "run_stdio"):
        backend.run_stdio(collector)
    else:
        try:
            from mcp_rpc import run_stdio
        except (ImportError, ModuleNotFoundError):
            rpc_module = load_module("mcp_rpc", mcp_root / "mcp_rpc.py")
            run_stdio = rpc_module.run_stdio
        run_stdio(collector)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
