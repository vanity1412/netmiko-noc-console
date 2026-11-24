"""Runtime settings for the standalone Netmiko Web Console.

Everything the Web Console writes lives under this project folder. The MCP
server and inventory are bundled in ``vendor/mcp`` and ``config`` for a
self-contained deployment; no external project folder is required.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

VERSION = "1.2.0"


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _split_command(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        parsed = json.loads(raw)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise ValueError("NETMIKO_WEB_MCP_COMMAND JSON must be an array of strings")
        return parsed
    return shlex.split(raw, posix=False)


@dataclass(frozen=True)
class Settings:
    root: Path
    parent: Path
    data_dir: Path
    logs_dir: Path
    runs_dir: Path
    db_path: Path
    inventory_csv: Path
    static_dir: Path
    mcp_command: list[str]
    mcp_cwd: Path
    mcp_root: Path
    mcp_config: Path
    mcp_credentials: Path | None
    mcp_known_hosts: Path
    mcp_autodetect_cache: Path
    bundled_mcp: bool = False
    host: str = "127.0.0.1"
    port: int = 8787
    default_concurrency: int = 6
    max_concurrency: int = 16
    max_devices_per_run: int = 1000
    max_commands_per_run: int = 30
    command_max_len: int = 8192
    inventory_ttl_seconds: int = 120
    mcp_tool_timeout: float = 150.0
    mcp_inventory_timeout: float = 45.0
    mcp_output_timeout: float = 45.0
    lsp_cache_ttl_seconds: int = 180
    lsp_read_timeout: int = 20
    lsp_tool_timeout: float = 145.0
    lsp_max_verify_nodes: int = 12
    route_read_timeout: int = 20
    route_tool_timeout: float = 220.0
    route_max_devices: int = 8
    route_hard_max_devices: int = 16
    route_seed_limit: int = 6
    max_output_bytes_per_device: int = 64 * 1024 * 1024
    output_page_lines: int = 5000
    keep_runs: int = 200
    version: str = VERSION
    require_token: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def mcp_bootstrap(self) -> Path:
        return self.mcp_root / "bootstrap.py"

    @property
    def presets_path(self) -> Path:
        return self.root / "backend" / "console" / "presets.json"

    @property
    def runtime_file(self) -> Path:
        return self.data_dir / "runtime.json"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def credentials_path(self) -> Path:
        if self.mcp_credentials is not None:
            return self.mcp_credentials
        if self.bundled_mcp:
            return (self.root / "config" / "credentials.json").resolve()
        return (self.mcp_root / "credentials.json").resolve()

    @classmethod
    def load(cls, root: Path | None = None) -> "Settings":
        root = Path(root or Path(__file__).resolve().parents[2]).resolve()
        parent = root.parent
        data_dir = Path(os.environ.get("NETMIKO_WEB_DATA_DIR") or (root / "data")).resolve()
        logs_dir = Path(os.environ.get("NETMIKO_WEB_LOG_DIR") or (root / "logs")).resolve()
        static_dir = Path(os.environ.get("NETMIKO_WEB_STATIC_DIR") or (root / "frontend" / "dist")).resolve()

        bundled_root = root / "vendor" / "mcp"
        env_mcp_root = os.environ.get("NETMIKO_WEB_MCP_ROOT", "").strip()
        if env_mcp_root:
            mcp_root = Path(env_mcp_root).resolve()
            bundled_mcp = bundled_root == mcp_root
        elif (bundled_root / "bootstrap.py").is_file():
            mcp_root = bundled_root
            bundled_mcp = True
        else:
            mcp_root = (parent / "mcp").resolve()
            bundled_mcp = False

        env_config = os.environ.get("NETMIKO_WEB_MCP_CONFIG", "").strip()
        if env_config:
            mcp_config = Path(env_config).resolve()
        elif bundled_mcp and (root / "config" / "devices.json").is_file():
            mcp_config = (root / "config" / "devices.json").resolve()
        else:
            mcp_config = (mcp_root / "devices.json").resolve()

        env_inventory = os.environ.get("NETMIKO_WEB_INVENTORY_CSV", "").strip()
        if env_inventory:
            inventory_csv = Path(env_inventory).resolve()
        elif bundled_mcp and (root / "config" / "device.csv").is_file():
            inventory_csv = (root / "config" / "device.csv").resolve()
        elif (parent / "input" / "device.csv").is_file():
            inventory_csv = (parent / "input" / "device.csv").resolve()
        elif bundled_mcp:
            inventory_csv = (root / "config" / "device.csv").resolve()
        else:
            inventory_csv = (parent / "input" / "device.csv").resolve()

        env_credentials = os.environ.get("NETMIKO_WEB_MCP_CREDENTIALS", "").strip()
        if env_credentials:
            mcp_credentials: Path | None = Path(env_credentials).resolve()
        elif bundled_mcp and (root / "config" / "credentials.json").is_file():
            mcp_credentials = (root / "config" / "credentials.json").resolve()
        elif (mcp_root / "credentials.json").is_file():
            mcp_credentials = (mcp_root / "credentials.json").resolve()
        else:
            mcp_credentials = None

        env_known = os.environ.get("NETMIKO_WEB_KNOWN_HOSTS", "").strip()
        if env_known:
            mcp_known_hosts = Path(env_known).resolve()
        elif bundled_mcp:
            mcp_known_hosts = (data_dir / "mcp-known_hosts").resolve()
        else:
            mcp_known_hosts = (mcp_root / "ssh" / "known_hosts").resolve()

        env_autodetect = os.environ.get("NETMIKO_WEB_AUTODETECT_CACHE", "").strip()
        if env_autodetect:
            mcp_autodetect_cache = Path(env_autodetect).resolve()
        elif bundled_mcp:
            mcp_autodetect_cache = (data_dir / "autodetect.sqlite3").resolve()
        else:
            mcp_autodetect_cache = (parent / "runtime" / "data" / "netmiko" / "autodetect.sqlite3").resolve()

        raw_command = os.environ.get("NETMIKO_WEB_MCP_COMMAND", "").strip()
        if raw_command:
            mcp_command = _split_command(raw_command)
        else:
            mcp_command = [
                sys.executable,
                "-u",
                str(root / "backend" / "console" / "mcp_launcher.py"),
                "--config",
                str(mcp_config),
                "--mcp-root",
                str(mcp_root),
                "--output-dir",
                str(data_dir / "mcp-outputs"),
                "--known-hosts",
                str(mcp_known_hosts),
                "--autodetect-cache",
                str(mcp_autodetect_cache),
            ]
            if inventory_csv.is_file():
                mcp_command.extend(["--inventory-csv", str(inventory_csv)])
            if mcp_credentials is not None:
                mcp_command.extend(["--credentials-file", str(mcp_credentials)])
        mcp_cwd = Path(
            os.environ.get("NETMIKO_WEB_MCP_CWD") or (root if bundled_mcp else parent)
        ).resolve()
        port = int(os.environ.get("NETMIKO_WEB_PORT", "8787"))
        max_devices = int(os.environ.get("NETMIKO_WEB_MAX_DEVICES", "1000"))
        default_concurrency = int(os.environ.get("NETMIKO_WEB_CONCURRENCY", "6"))
        return cls(
            root=root,
            parent=parent,
            data_dir=data_dir,
            logs_dir=logs_dir,
            runs_dir=data_dir / "runs",
            db_path=data_dir / "history.sqlite3",
            inventory_csv=inventory_csv,
            static_dir=static_dir,
            mcp_command=mcp_command,
            mcp_cwd=mcp_cwd,
            mcp_root=mcp_root,
            mcp_config=mcp_config,
            mcp_credentials=mcp_credentials,
            mcp_known_hosts=mcp_known_hosts,
            mcp_autodetect_cache=mcp_autodetect_cache,
            bundled_mcp=bundled_mcp,
            host=os.environ.get("NETMIKO_WEB_HOST", "127.0.0.1"),
            port=port,
            default_concurrency=max(1, min(default_concurrency, 16)),
            max_devices_per_run=max(1, min(max_devices, 5000)),
            keep_runs=int(os.environ.get("NETMIKO_WEB_KEEP_RUNS", "200")),
            require_token=not _env_flag("NETMIKO_WEB_DISABLE_TOKEN"),
            lsp_cache_ttl_seconds=max(10, int(os.environ.get("NETMIKO_WEB_LSP_CACHE_TTL", "180"))),
            lsp_read_timeout=max(5, min(120, int(os.environ.get("NETMIKO_WEB_LSP_READ_TIMEOUT", "20")))),
            lsp_tool_timeout=max(60.0, float(os.environ.get("NETMIKO_WEB_LSP_TOOL_TIMEOUT", "145"))),
            lsp_max_verify_nodes=max(1, min(32, int(os.environ.get("NETMIKO_WEB_LSP_MAX_NODES", "12")))),
            route_read_timeout=max(5, min(120, int(os.environ.get("NETMIKO_WEB_ROUTE_READ_TIMEOUT", "20")))),
            route_tool_timeout=max(60.0, float(os.environ.get("NETMIKO_WEB_ROUTE_TOOL_TIMEOUT", "220"))),
            route_max_devices=max(2, min(16, int(os.environ.get("NETMIKO_WEB_ROUTE_MAX_DEVICES", "8")))),
            route_hard_max_devices=max(2, min(32, int(os.environ.get("NETMIKO_WEB_ROUTE_HARD_MAX", "16")))),
            route_seed_limit=max(3, min(24, int(os.environ.get("NETMIKO_WEB_ROUTE_SEED_LIMIT", "6")))),
        )

    def ensure_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.logs_dir,
            self.runs_dir,
            self.tmp_dir,
            self.mcp_known_hosts.parent,
            self.mcp_autodetect_cache.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)


def display_command(command: Iterable[str]) -> str:
    """Human-readable MCP command with no credential material (there is none)."""
    parts = []
    for item in command:
        text = str(item)
        parts.append(f'"{text}"' if " " in text else text)
    return " ".join(parts)
