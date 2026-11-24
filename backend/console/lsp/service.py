"""Read-only LSP discovery/trace service on top of the existing Netmiko MCP."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..inventory import InventoryService, InventorySnapshot, InventoryUnavailable
from ..mcp_client import MCPCallError, MCPError, MCPTimeout, MCPUnavailable, StdioMCPClient
from ..settings import Settings
from .parser import (
    clean_lines,
    parse_config_interfaces_set,
    parse_config_set,
    parse_interface_descriptions,
    parse_interfaces_terse,
    parse_isis_adjacency,
    parse_lldp_neighbors,
    parse_mpls_lsp_extensive,
    parse_planned_ticket,
    parse_rsvp_interface,
    parse_rsvp_session_extensive,
)
from .topology import build_topology

log = logging.getLogger("netmiko_web.lsp")

LSP_NAME_RE = re.compile(r"^[A-Za-z0-9_.:<>+=@,-]{1,160}$")

DISCOVER_COMMANDS = [
    "show configuration protocols mpls | display set | no-more",
    "show mpls lsp extensive | no-more",
    "show rsvp session extensive | no-more",
]

TRACE_COMMANDS = [
    "show configuration protocols mpls | display set | no-more",
    "show configuration protocols mpls label-switched-path {lsp} | display set | no-more",
    "show mpls lsp name {lsp} extensive | no-more",
    "show rsvp session extensive | no-more",
    "show rsvp interface | no-more",
    "show isis adjacency | no-more",
    "show lldp neighbors | no-more",
    "show interfaces descriptions | no-more",
    "show interfaces terse | no-more",
]

VERIFY_COMMANDS = [
    "show interfaces terse | no-more",
    "show interfaces descriptions | no-more",
    "show lldp neighbors | no-more",
    "show isis adjacency | no-more",
    "show configuration interfaces | display set | no-more",
]

INVENTORY_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _name_variants(value: str | None) -> list[str]:
    raw = str(value or "").strip().rstrip(",")
    if not raw:
        return []
    base = raw.split("(")[0].strip()
    variants = [raw, raw.split(".")[0], base, base.split(".")[0]]
    for item in list(variants):
        stripped = re.sub(r"-re\d+$", "", item, flags=re.I)
        if stripped and stripped not in variants:
            variants.append(stripped)
    return [item for item in variants if item]


def _slug(value: str, limit: int = 64) -> str:
    text = INVENTORY_SAFE.sub("_", value).strip("._-")
    digest = hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:6]
    return f"{(text or 'item')[:limit]}-{digest}"


def _iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or time.time()))


class LspValidationError(ValueError):
    pass


class LspNotFound(LookupError):
    pass


class LspService:
    def __init__(self, settings: Settings, mcp: StdioMCPClient, inventory: InventoryService):
        self.settings = settings
        self.mcp = mcp
        self.inventory = inventory
        self.root = settings.data_dir / "lsp"
        self.evidence_root = self.root / "evidence"
        self.snapshot_root = self.root / "snapshots"
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_lock = asyncio.Lock()

    # ------------------------------------------------------------------ helpers
    def _snapshot_id(self, prefix: str = "lsp") -> str:
        return f"{prefix}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{hashlib.sha1(str(time.time()).encode()).hexdigest()[:6]}"

    def _resolve_source(self, snapshot: InventorySnapshot, value: str) -> dict[str, Any]:
        raw = str(value or "").strip()
        if not raw:
            raise LspValidationError("Cần nhập hostname/IP thiết bị nguồn")
        row = snapshot.by_name.get(raw)
        if row is None:
            folded = raw.casefold()
            row = next(
                (item for item in snapshot.devices if str(item.get("name", "")).casefold() == folded),
                None,
            )
        if row is None:
            row = next(
                (item for item in snapshot.devices if str(item.get("host", "")).strip() == raw),
                None,
            )
        if row is None:
            raise LspNotFound(f"Không có thiết bị '{raw}' trong inventory MCP")
        driver = str(row.get("device_type") or "")
        if driver and not (driver.startswith("juniper") or driver == "autodetect"):
            raise LspValidationError(
                f"LSP ViewPath hiện hỗ trợ Junos; '{row.get('name')}' có driver '{driver}'"
            )
        return row

    def _validate_lsp(self, value: str) -> str:
        name = str(value or "").strip()
        if not name:
            raise LspValidationError("Cần nhập tên LSP")
        if not LSP_NAME_RE.match(name):
            raise LspValidationError(
                "Tên LSP không hợp lệ (cho phép chữ, số, . _ : - > < + = @ ,; "
                "không có khoảng trắng hoặc ký tự điều khiển)"
            )
        return name

    def _mcp_timeout(self, command_count: int) -> float:
        read_timeout = int(getattr(self.settings, "lsp_read_timeout", 25))
        wanted = max(135, command_count * read_timeout + 45)
        return float(min(wanted, getattr(self.settings, "lsp_tool_timeout", 300)))

    # ------------------------------------------------------------------- MCP I/O
    def _read_output(self, output_id: str, *, max_bytes: int = 8 * 1024 * 1024) -> tuple[str, str]:
        chunks: list[str] = []
        offset = 0
        used = 0
        while True:
            if used >= max_bytes:
                return "".join(chunks), "Dừng đọc ở giới hạn 8 MB mỗi lệnh"
            try:
                payload, _meta = self.mcp.call_tool(
                    "ssh_read_output",
                    {"output_id": output_id, "offset": offset, "limit": 1000},
                    timeout=getattr(self.settings, "mcp_output_timeout", 45),
                )
            except MCPError as exc:
                return "".join(chunks), f"Không đọc được output_id {output_id}: {exc}"
            text = payload.get("text")
            if not isinstance(text, str):
                return "".join(chunks), "MCP trả output không hợp lệ"
            chunks.append(text)
            used += len(text.encode("utf-8"))
            if not payload.get("more"):
                return "".join(chunks), ""
            next_offset = payload.get("next_offset")
            if not isinstance(next_offset, int) or next_offset <= offset:
                return "".join(chunks), "MCP báo còn dữ liệu nhưng offset không tăng"
            offset = next_offset

    def _run_commands(
        self,
        *,
        snapshot_id: str,
        device: dict[str, Any],
        commands: list[str],
        read_timeout: int | None = None,
        index_offset: int = 0,
    ) -> dict[str, Any]:
        """Run one read-only batch and persist every raw output. Never raises for CLI errors."""
        name = str(device.get("name") or "")
        timeout = self._mcp_timeout(len(commands))
        payload: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        error: str | None = None
        try:
            if not self.mcp.ping(timeout=5):
                self.mcp.ensure_ready()
            payload, meta = self.mcp.call_tool(
                "ssh_execute_many",
                {
                    "target": name,
                    "commands": commands,
                    "device_type": device.get("device_type") or "juniper_junos",
                    "read_timeout": int(read_timeout or getattr(self.settings, "lsp_read_timeout", 25)),
                    "continue_on_error": True,
                },
                timeout=timeout,
            )
        except (MCPTimeout, MCPUnavailable, MCPCallError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            log.warning("LSP collection failed for %s: %s", name, exc)
        steps = payload.get("results")
        if not isinstance(steps, list):
            steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
        steps = [step for step in steps if isinstance(step, dict)]
        by_index: dict[int, dict[str, Any]] = {}
        for position, step in enumerate(steps):
            index = step.get("command_index")
            if not isinstance(index, int):
                index = position
            by_index[index] = step
        evidence: list[dict[str, Any]] = []
        outputs: dict[int, str] = {}
        command_status: dict[str, str] = {}
        device_dir = self.evidence_root / snapshot_id / _slug(name)
        device_dir.mkdir(parents=True, exist_ok=True)
        ok_count = 0
        for index, command in enumerate(commands):
            step = by_index.get(index) or {}
            command_index = index + index_offset
            text = ""
            note = ""
            output_id = step.get("output_id")
            if isinstance(step.get("output"), str) and step.get("output"):
                text = str(step["output"])
            elif output_id:
                text, note = self._read_output(str(output_id))
            elif step.get("preview"):
                text = str(step["preview"])
                note = "MCP chỉ trả preview; output chưa đầy đủ"
            ok = step.get("ok") is True
            if ok:
                ok_count += 1
            status = "SUCCESS" if ok else str(step.get("fault_status") or step.get("status") or "ERROR")
            if step.get("skipped") is True:
                status = "SKIPPED"
            if error and not step:
                status = "MCP_ERROR"
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            ev_id = "ev-" + hashlib.sha1(
                f"{snapshot_id}:{name}:{command_index}:{command}".encode("utf-8")
            ).hexdigest()[:12]
            filename = f"{command_index + 1:02d}-{_slug(command.split('|')[0].strip()[:48])}.txt"
            path = device_dir / filename
            try:
                self._atomic_write(path, text)
                output_ref = str(path.relative_to(self.root)).replace("\\", "/")
            except OSError as exc:
                output_ref = None
                note = (note + " | " if note else "") + f"Không ghi được evidence: {exc}"
            evidence.append(
                {
                    "id": ev_id,
                    "device": name,
                    "command": command,
                    "timestamp": _iso(),
                    "status": status,
                    "output_complete": step.get("output_complete"),
                    "data_state": step.get("data_state"),
                    "error_reason": step.get("error_reason"),
                    "error_category": step.get("error_category"),
                    "message": step.get("message"),
                    "lines": len(text.splitlines()),
                    "bytes": len(text.encode("utf-8")),
                    "output_sha256": digest,
                    "output_ref": output_ref,
                    "note": note or None,
                }
            )
            outputs[command_index] = text
            command_status[command] = status
        total = len(commands)
        status = "SUCCESS" if total and ok_count == total else ("PARTIAL" if ok_count else "ERROR")
        return {
            "device": name,
            "host": device.get("host"),
            "device_type": device.get("device_type"),
            "status": status,
            "fault_status": payload.get("fault_status") or payload.get("status") or status,
            "error": error,
            "evidence": evidence,
            "outputs": outputs,
            "commands": commands,
            "command_status": command_status,
            "command_count": total,
            "session_reused": bool(payload.get("session_reused")) or any(
                bool(step.get("session_reused")) for step in steps
            ),
            "elapsed_ms": payload.get("elapsed_ms"),
            "queried": True,
        }

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8", newline="\n")
        temporary.replace(path)

    @staticmethod
    def _merge_collected(items: list[dict[str, Any]], commands: list[str]) -> dict[str, Any]:
        evidence: list[dict[str, Any]] = []
        outputs: dict[int, str] = {}
        command_status: dict[str, str] = {}
        statuses: list[str] = []
        errors: list[str] = []
        elapsed = 0
        session_reused = False
        first = items[0] if items else {}
        for item in items:
            evidence.extend(item.get("evidence") or [])
            outputs.update(item.get("outputs") or {})
            command_status.update(item.get("command_status") or {})
            statuses.append(str(item.get("status") or "ERROR"))
            if item.get("error"):
                errors.append(str(item["error"]))
            elapsed += int(item.get("elapsed_ms") or 0)
            session_reused = session_reused or bool(item.get("session_reused"))
        if statuses and all(status == "SUCCESS" for status in statuses):
            status = "SUCCESS"
        elif any(status in {"SUCCESS", "PARTIAL"} for status in statuses):
            status = "PARTIAL"
        else:
            status = "ERROR"
        return {
            **first,
            "status": status,
            "fault_status": first.get("fault_status") or status,
            "error": " | ".join(errors) or None,
            "evidence": evidence,
            "outputs": outputs,
            "commands": commands,
            "command_status": command_status,
            "command_count": len(commands),
            "session_reused": session_reused,
            "elapsed_ms": elapsed,
            "queried": True,
        }

    # ---------------------------------------------------------------- discover
    async def discover(
        self, source: str, lsp: str = "", *, refresh: bool = False
    ) -> dict[str, Any]:
        try:
            snapshot = await asyncio.to_thread(self.inventory.get, force=refresh)
        except InventoryUnavailable as exc:
            raise LspValidationError(f"Inventory MCP không khả dụng: {exc}") from exc
        row = self._resolve_source(snapshot, source)
        discovery_id = self._snapshot_id("discover")
        device = {
            "name": row["name"],
            "host": row.get("host"),
            "device_type": row.get("device_type"),
        }
        collected = await asyncio.to_thread(
            self._run_commands,
            snapshot_id=discovery_id,
            device=device,
            commands=DISCOVER_COMMANDS,
        )
        config = parse_config_set(collected["outputs"].get(0, ""))
        mpls = parse_mpls_lsp_extensive(collected["outputs"].get(1, ""))
        rsvp = parse_rsvp_session_extensive(collected["outputs"].get(2, ""))
        entries = self._lsp_entries(config, mpls, rsvp, lsp)
        corpus = {
            "source": row["name"],
            "generated_at": _iso(),
            "devices": {
                row["name"]: {
                    **collected,
                    "name": row["name"],
                    "evidence_ids": {
                        "lsp_config": collected["evidence"][0]["id"] if len(collected["evidence"]) > 0 else None,
                        "lsp_operational": collected["evidence"][1]["id"] if len(collected["evidence"]) > 1 else None,
                        "rsvp_session": collected["evidence"][2]["id"] if len(collected["evidence"]) > 2 else None,
                    },
                }
            },
            "config": config,
            "mpls": mpls,
            "rsvp": rsvp,
            "rsvp_interfaces": [],
            "evidence": collected["evidence"],
        }
        result = {
            "discovery_id": discovery_id,
            "source": row["name"],
            "host": row.get("host"),
            "generated_at": corpus["generated_at"],
            "source_status": collected["status"],
            "source_error": collected["error"],
            "evidence": collected["evidence"],
            "lsps": entries,
            "total": len(entries),
            "warnings": [
                *config.get("warnings", []),
                *mpls.get("warnings", []),
            ],
        }
        async with self._cache_lock:
            self._cache[discovery_id] = {
                "created_at": time.time(),
                "source": row["name"],
                "lsp": lsp,
                "corpus": corpus,
            }
            self._prune_cache()
        return result

    @staticmethod
    def _lsp_entries(
        config: dict[str, Any],
        mpls: dict[str, Any],
        rsvp: dict[str, Any],
        requested: str = "",
    ) -> list[dict[str, Any]]:
        by_name: dict[str, dict[str, Any]] = {}
        for item in config.get("lsps") or []:
            by_name[str(item.get("name"))] = {
                "name": item.get("name"),
                "destination": item.get("to"),
                "configured": True,
                "primary": item.get("primary"),
                "secondary": item.get("secondary") or [],
                "backup": item.get("backup") or [],
                "no_cspf": bool(item.get("no_cspf")),
                "operational": False,
                "state": "UNKNOWN",
                "active_path": None,
                "paths": [],
            }
        for session in mpls.get("sessions") or []:
            name = str(session.get("lspname") or "")
            if not name:
                continue
            if session.get("direction", "ingress") != "ingress":
                continue
            entry = by_name.setdefault(
                name,
                {
                    "name": name,
                    "destination": session.get("to"),
                    "configured": False,
                    "primary": None,
                    "secondary": [],
                    "backup": [],
                    "no_cspf": False,
                },
            )
            entry.update(
                {
                    "operational": True,
                    "state": str(session.get("state") or "UNKNOWN").upper(),
                    "active_path": session.get("active_path"),
                    "destination": entry.get("destination") or session.get("to"),
                    "paths": [
                        {
                            "name": path.get("name"),
                            "role": path.get("role"),
                            "state": path.get("oper_state") or path.get("state"),
                            "active": bool(path.get("active")),
                            "standby": bool(path.get("standby")),
                            "rro": [hop.get("ip") for hop in path.get("rro") or []],
                        }
                        for path in session.get("paths") or []
                    ],
                }
            )
        for session in rsvp.get("sessions") or []:
            name = str(session.get("lspname") or "")
            if not name or name in by_name:
                continue
            if session.get("direction", "ingress") != "ingress":
                continue
            by_name[name] = {
                "name": name,
                "destination": session.get("to"),
                "configured": False,
                "primary": None,
                "secondary": [],
                "backup": [],
                "no_cspf": False,
                "operational": True,
                "state": str(session.get("state") or "UNKNOWN").upper(),
                "active_path": None,
                "paths": [],
            }
        items = list(by_name.values())
        if requested:
            items = [item for item in items if str(item["name"]).casefold() == requested.casefold()]
        items.sort(key=lambda item: str(item.get("name") or "").casefold())
        return items

    def _prune_cache(self) -> None:
        ttl = getattr(self.settings, "lsp_cache_ttl_seconds", 180)
        cutoff = time.time() - ttl
        for key in [key for key, item in self._cache.items() if item["created_at"] < cutoff]:
            self._cache.pop(key, None)

    # ------------------------------------------------------------------- trace
    async def trace(
        self,
        source: str,
        lsp: str,
        *,
        discovery_id: str | None = None,
        label: str = "",
        snapshot_type: str = "CAPTURE",
        refresh: bool = False,
    ) -> dict[str, Any]:
        lsp = self._validate_lsp(lsp)
        try:
            snapshot = await asyncio.to_thread(self.inventory.get, force=refresh)
        except InventoryUnavailable as exc:
            raise LspValidationError(f"Inventory MCP không khả dụng: {exc}") from exc
        row = self._resolve_source(snapshot, source)
        snapshot_id = self._snapshot_id("lsp")
        corpus: dict[str, Any] | None = None
        source_device = {
            "name": row["name"],
            "host": row.get("host"),
            "device_type": row.get("device_type"),
        }
        if corpus is None:
            commands = [command.format(lsp=lsp) for command in TRACE_COMMANDS]
            first_commands = commands[:5]
            second_commands = commands[5:]
            first_batch = await asyncio.to_thread(
                self._run_commands,
                snapshot_id=snapshot_id,
                device=source_device,
                commands=first_commands,
                index_offset=0,
            )
            second_batch = await asyncio.to_thread(
                self._run_commands,
                snapshot_id=snapshot_id,
                device=source_device,
                commands=second_commands,
                index_offset=len(first_commands),
            )
            collected = self._merge_collected([first_batch, second_batch], commands)
            config = parse_config_set(collected["outputs"].get(0, ""))
            config_lsp = parse_config_set(collected["outputs"].get(1, ""))
            if config_lsp.get("lsps"):
                # Keep the full view but ensure the filtered command's LSP is present.
                known = {item.get("name") for item in config.get("lsps") or []}
                config["lsps"].extend(
                    item for item in config_lsp["lsps"] if item.get("name") not in known
                )
            config["paths"].update(config_lsp.get("paths") or {})
            mpls = parse_mpls_lsp_extensive(collected["outputs"].get(2, ""))
            rsvp = parse_rsvp_session_extensive(collected["outputs"].get(3, ""))
            rsvp_interfaces = parse_rsvp_interface(collected["outputs"].get(4, ""))
            isis = parse_isis_adjacency(collected["outputs"].get(5, ""))
            lldp = parse_lldp_neighbors(collected["outputs"].get(6, ""))
            descriptions = parse_interface_descriptions(collected["outputs"].get(7, ""))
            interfaces = parse_interfaces_terse(collected["outputs"].get(8, ""))
            corpus = {
                "source": row["name"],
                "generated_at": _iso(),
                "devices": {
                    row["name"]: {
                        **collected,
                        "name": row["name"],
                        "evidence_ids": {
                            "lsp_config": collected["evidence"][0]["id"] if len(collected["evidence"]) > 0 else None,
                            "lsp_config_filtered": collected["evidence"][1]["id"] if len(collected["evidence"]) > 1 else None,
                            "lsp_operational": collected["evidence"][2]["id"] if len(collected["evidence"]) > 2 else None,
                            "rsvp_session": collected["evidence"][3]["id"] if len(collected["evidence"]) > 3 else None,
                            "rsvp_interfaces": collected["evidence"][4]["id"] if len(collected["evidence"]) > 4 else None,
                            "isis": collected["evidence"][5]["id"] if len(collected["evidence"]) > 5 else None,
                            "lldp": collected["evidence"][6]["id"] if len(collected["evidence"]) > 6 else None,
                            "descriptions": collected["evidence"][7]["id"] if len(collected["evidence"]) > 7 else None,
                            "interfaces": collected["evidence"][8]["id"] if len(collected["evidence"]) > 8 else None,
                        },
                        "interfaces": interfaces,
                        "descriptions": descriptions,
                        "lldp": lldp,
                        "isis": isis,
                        "config_interfaces": [],
                    }
                },
                "config": config,
                "mpls": mpls,
                "rsvp": rsvp,
                "rsvp_interfaces": rsvp_interfaces,
                "evidence": list(collected["evidence"]),
            }
        else:
            corpus = json.loads(json.dumps(corpus))
            corpus["generated_at"] = corpus.get("generated_at") or _iso()

        # Verify the candidate path nodes with the minimum number of SSH targets.
        await asyncio.to_thread(
            self._verify_candidates,
            snapshot_id=snapshot_id,
            snapshot=snapshot,
            corpus=corpus,
            lsp=lsp,
        )

        warnings: list[str] = []
        for device_data in (corpus.get("devices") or {}).values():
            if device_data.get("error"):
                warnings.append(f"{device_data.get('name')}: {device_data['error']}")
            for ev in device_data.get("evidence") or []:
                if ev.get("status") not in {"SUCCESS"}:
                    warnings.append(
                        f"{ev.get('device')}: {ev.get('command')} → {ev.get('status')}"
                        + (f" ({ev.get('error_reason')})" if ev.get("error_reason") else "")
                    )
                if ev.get("note"):
                    warnings.append(f"{ev.get('device')}: {ev.get('note')}")
        planned = None
        topology = build_topology(
            source=row["name"],
            lsp_name=lsp,
            inventory=snapshot.devices,
            corpus=corpus,
            config=corpus["config"],
            mpls=corpus["mpls"],
            rsvp=corpus["rsvp"],
            rsvp_interfaces=corpus.get("rsvp_interfaces") or [],
            evidence=corpus.get("evidence") or [],
            warnings=warnings,
            discovery_id=snapshot_id,
            planned=planned,
        )
        record = {
            "id": snapshot_id,
            "created_at": _iso(),
            "label": (label or "").strip()[:120] or f"{row['name']} · {lsp}",
            "snapshot_type": (snapshot_type or "CAPTURE").upper(),
            "source": row["name"],
            "lsp": lsp,
            "topology": topology,
        }
        await asyncio.to_thread(self._save_snapshot, record)
        topology["snapshot"] = {
            "id": record["id"],
            "label": record["label"],
            "snapshot_type": record["snapshot_type"],
            "created_at": record["created_at"],
        }
        return topology

    # ------------------------------------------------------ candidate verification
    def _verify_candidates(
        self,
        *,
        snapshot_id: str,
        snapshot: InventorySnapshot,
        corpus: dict[str, Any],
        lsp: str,
    ) -> None:
        devices = corpus["devices"]
        by_name = {str(row.get("name")).casefold(): row for row in snapshot.devices}
        hop_ips = self._hop_ips(corpus, lsp)
        destination = self._destination(corpus, lsp)
        if destination:
            hop_ips.add(destination)
        max_nodes = max(1, int(getattr(self.settings, "lsp_max_verify_nodes", 8)))
        queried = {str(name) for name, data in devices.items() if data.get("queried")}
        attempts = 0
        while len(queried) < max_nodes and attempts < max_nodes * 2:
            hop_ips = self._hop_ips(corpus, lsp)
            if destination:
                hop_ips.add(destination)
            resolved_ips = {
                str(item.get("local_ip"))
                for data in devices.values()
                for item in data.get("interfaces") or []
                if item.get("local_ip")
            }
            active_hops = self._active_hop_ips(corpus, lsp)
            target_hops = active_hops if active_hops - resolved_ips else hop_ips
            if target_hops and target_hops <= resolved_ips:
                break
            ranked = self._ranked_candidates(corpus, by_name, target_hops, exclude=queried)
            if not ranked:
                break
            best = ranked[0][0]
            batch = [
                name
                for priority, name in ranked
                if priority == best and name not in queried
            ][: max(1, min(3, max_nodes - len(queried)))]
            if not batch:
                break
            results: dict[str, dict[str, Any]] = {}
            with ThreadPoolExecutor(max_workers=min(4, len(batch))) as pool:
                futures = {
                    pool.submit(
                        self._run_commands,
                        snapshot_id=snapshot_id,
                        device=by_name[name.casefold()],
                        commands=VERIFY_COMMANDS,
                    ): name
                    for name in batch
                }
                for future, name in futures.items():
                    try:
                        results[name] = future.result()
                    except Exception as exc:  # defensive: one node must not stop trace
                        log.warning("LSP verification failed for %s: %s", name, exc)
                        results[name] = {
                            "device": name,
                            "status": "ERROR",
                            "error": str(exc),
                            "evidence": [],
                            "outputs": {},
                            "commands": VERIFY_COMMANDS,
                            "command_status": {},
                            "command_count": len(VERIFY_COMMANDS),
                            "queried": True,
                        }
            for name, collected in results.items():
                attempts += 1
                if name in queried:
                    continue
                queried.add(name)
                row = by_name[name.casefold()]
                evidence = collected.get("evidence") or []
                devices[name] = {
                    **collected,
                    "name": name,
                    "host": row.get("host"),
                    "device_type": row.get("device_type"),
                    "evidence_ids": {
                        "interfaces": evidence[0]["id"] if len(evidence) > 0 else None,
                        "descriptions": evidence[1]["id"] if len(evidence) > 1 else None,
                        "lldp": evidence[2]["id"] if len(evidence) > 2 else None,
                        "isis": evidence[3]["id"] if len(evidence) > 3 else None,
                        "config_interfaces": evidence[4]["id"] if len(evidence) > 4 else None,
                    },
                    "interfaces": parse_interfaces_terse((collected.get("outputs") or {}).get(0, "")),
                    "descriptions": parse_interface_descriptions((collected.get("outputs") or {}).get(1, "")),
                    "lldp": parse_lldp_neighbors((collected.get("outputs") or {}).get(2, "")),
                    "isis": parse_isis_adjacency((collected.get("outputs") or {}).get(3, "")),
                    "config_interfaces": parse_config_interfaces_set((collected.get("outputs") or {}).get(4, "")),
                }
                corpus.setdefault("evidence", []).extend(evidence)
            # Re-evaluate unresolved hops and follow the neighbour chain.
            hop_ips = self._hop_ips(corpus, lsp)
            if destination:
                hop_ips.add(destination)

    def _hop_ips(self, corpus: dict[str, Any], lsp: str) -> set[str]:
        ips: set[str] = set()
        config = corpus.get("config") or {}
        mpls = corpus.get("mpls") or {}
        rsvp = corpus.get("rsvp") or {}
        config_lsp = next(
            (item for item in config.get("lsps") or [] if str(item.get("name", "")).casefold() == lsp.casefold()),
            None,
        )
        session = next(
            (
                item
                for item in mpls.get("sessions") or []
                if str(item.get("lspname", "")).casefold() == lsp.casefold()
                and item.get("direction", "ingress") == "ingress"
            ),
            None,
        )
        rsvp_session = next(
            (
                item
                for item in rsvp.get("sessions") or []
                if str(item.get("lspname", "")).casefold() == lsp.casefold()
                and item.get("direction", "ingress") == "ingress"
            ),
            None,
        )
        names = set()
        if config_lsp:
            if config_lsp.get("primary"):
                names.add(config_lsp["primary"])
            names.update(item.get("name") for item in config_lsp.get("secondary") or [])
            names.update(item.get("name") for item in config_lsp.get("backup") or [])
        if session:
            names.update(path.get("name") for path in session.get("paths") or [])
        paths = config.get("paths") or {}
        for name in names:
            for hop in (paths.get(name) or {}).get("hops") or []:
                if hop.get("ip"):
                    ips.add(str(hop["ip"]))
        for session_data in (session, rsvp_session):
            for path in (session_data or {}).get("paths") or []:
                for hop in (path.get("rro") or path.get("oper_path") or []):
                    if hop.get("ip"):
                        ips.add(str(hop["ip"]))
            for hop in (session_data or {}).get("path") or []:
                if hop.get("ip"):
                    ips.add(str(hop["ip"]))
            for hop in (session_data or {}).get("rro") or []:
                if hop.get("ip"):
                    ips.add(str(hop["ip"]))
        return ips

    def _active_hop_ips(self, corpus: dict[str, Any], lsp: str) -> set[str]:
        mpls = corpus.get("mpls") or {}
        session = next(
            (
                item
                for item in mpls.get("sessions") or []
                if str(item.get("lspname", "")).casefold() == lsp.casefold()
                and item.get("direction", "ingress") == "ingress"
            ),
            None,
        )
        if not session:
            return set()
        active_name = session.get("active_path")
        paths = session.get("paths") or []
        active = next(
            (path for path in paths if str(path.get("name") or "") == str(active_name or "") and active_name),
            None,
        )
        if active is None:
            active = next((path for path in paths if path.get("active")), None)
        if active is None:
            active = next(
                (path for path in paths if str(path.get("oper_state") or path.get("state") or "").upper() == "UP"),
                None,
            )
        if not active:
            return set()
        return {
            str(hop.get("ip"))
            for key in ("rro", "ero", "computed_ero", "oper_path")
            for hop in active.get(key) or []
            if hop.get("ip")
        }

    @staticmethod
    def _destination(corpus: dict[str, Any], lsp: str) -> str | None:
        config = corpus.get("config") or {}
        for item in config.get("lsps") or []:
            if str(item.get("name", "")).casefold() == lsp.casefold():
                return item.get("to")
        for item in (corpus.get("mpls") or {}).get("sessions") or []:
            if (
                str(item.get("lspname", "")).casefold() == lsp.casefold()
                and item.get("direction", "ingress") == "ingress"
            ):
                return item.get("to")
        for item in (corpus.get("rsvp") or {}).get("sessions") or []:
            if (
                str(item.get("lspname", "")).casefold() == lsp.casefold()
                and item.get("direction", "ingress") == "ingress"
            ):
                return item.get("to")
        return None

    def _candidate_neighbors(
        self,
        corpus: dict[str, Any],
        by_name: dict[str, dict[str, Any]],
        hop_ips: set[str],
        *,
        exclude: set[str],
    ) -> list[str]:
        return [
            name
            for _priority, name in self._ranked_candidates(corpus, by_name, hop_ips, exclude=exclude)
        ]

    @staticmethod
    def _if_matches(left: str | None, right: str | None) -> bool:
        if not left or not right:
            return False
        if left == right:
            return True
        return left.split(".", 1)[0] == right.split(".", 1)[0]

    def _ranked_candidates(
        self,
        corpus: dict[str, Any],
        by_name: dict[str, dict[str, Any]],
        hop_ips: set[str],
        *,
        exclude: set[str],
    ) -> list[tuple[int, str]]:
        """Rank only devices that can plausibly resolve the next hop.

        Priority 0: a hop IP is directly connected to a queried device (or is
        its own interface) and the LLDP/IS-IS neighbour on that interface is
        known. Priority 1: any other neighbour of a device already on the
        path. Priority 2: inventory host match. Priority 3: remaining
        neighbours. This prevents spending the SSH budget on unrelated LLDP
        neighbours while walking a long LSP.
        """
        devices = corpus.get("devices") or {}
        resolved_ips: set[str] = set()
        for data in devices.values():
            for item in data.get("interfaces") or []:
                if item.get("local_ip"):
                    resolved_ips.add(str(item["local_ip"]))
        unresolved = {ip for ip in hop_ips if ip and ip not in resolved_ips}
        ranked: dict[str, int] = {}

        def resolve_name(value: str | None) -> str | None:
            if not value:
                return None
            for candidate in _name_variants(value):
                row = by_name.get(candidate.casefold())
                if row:
                    return str(row.get("name"))
            return None

        def add(value: str | None, priority: int) -> None:
            name = resolve_name(value)
            if not name or name in exclude:
                return
            row = by_name.get(name.casefold()) or {}
            driver = str(row.get("device_type") or "")
            if driver and not (driver.startswith("juniper") or driver == "autodetect"):
                return
            if name not in ranked or priority < ranked[name]:
                ranked[name] = priority

        def neighbours(data: dict[str, Any]) -> list[tuple[str | None, str | None, str | None]]:
            rows: list[tuple[str | None, str | None, str | None]] = []
            for item in data.get("lldp") or []:
                rows.append(
                    (
                        item.get("local_interface"),
                        item.get("parent_interface"),
                        item.get("system_name"),
                    )
                )
            for item in data.get("isis") or []:
                rows.append((item.get("interface"), None, item.get("system")))
            return rows

        path_devices: set[str] = set()
        for name, data in devices.items():
            if not data.get("queried"):
                continue
            interfaces = [
                item for item in data.get("interfaces") or [] if item.get("local_ip")
            ]
            for item in interfaces:
                ip = str(item.get("local_ip"))
                prefix = item.get("prefix")
                if ip in hop_ips:
                    path_devices.add(name)
                if prefix is None:
                    continue
                try:
                    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                except ValueError:
                    continue
                for hop in unresolved:
                    try:
                        if ipaddress.ip_address(hop) in network:
                            path_devices.add(name)
                    except ValueError:
                        continue
                for local_if, parent_if, remote in neighbours(data):
                    if not remote:
                        continue
                    for hop in unresolved:
                        try:
                            if ipaddress.ip_address(hop) not in network:
                                continue
                        except ValueError:
                            continue
                        if local_if == item.get("interface"):
                            add(remote, 0)
                        elif self._if_matches(parent_if, item.get("interface")):
                            add(remote, 1)
        # Inventory management IP exactly equal to a hop IP.
        for row in by_name.values():
            host = str(row.get("host") or "").strip()
            if host and host in unresolved:
                add(str(row.get("name")), 0)
        # Neighbours of devices already proven to be on the path.
        for name in path_devices:
            for _local, _parent, remote in neighbours(devices.get(name) or {}):
                add(remote, 1)
        # Last resort: neighbours of any queried device (still bounded).
        for name, data in devices.items():
            if not data.get("queried"):
                continue
            for _local, _parent, remote in neighbours(data):
                add(remote, 3)
        return sorted(((priority, name) for name, priority in ranked.items()), key=lambda item: (item[0], item[1]))

    # --------------------------------------------------------------- snapshots
    def _snapshot_path(self, snapshot_id: str) -> Path:
        if not re.match(r"^(lsp|discover)_[A-Za-z0-9TZ_-]+$", str(snapshot_id or "")):
            raise LspNotFound("Snapshot id không hợp lệ")
        return self.snapshot_root / f"{snapshot_id}.json"

    def _save_snapshot(self, record: dict[str, Any]) -> None:
        path = self._snapshot_path(record["id"])
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
        temporary.replace(path)

    def list_snapshots(self, limit: int = 50) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(self.snapshot_root.glob("lsp_*.json"), reverse=True)[: max(1, limit)]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            topology = data.get("topology") or {}
            items.append(
                {
                    "id": data.get("id"),
                    "label": data.get("label"),
                    "snapshot_type": data.get("snapshot_type"),
                    "created_at": data.get("created_at"),
                    "source": data.get("source"),
                    "lsp": data.get("lsp"),
                    "overall_status": topology.get("overall_status"),
                    "active_path": (topology.get("lsp") or {}).get("active_path"),
                    "primary_path": (topology.get("lsp") or {}).get("primary_path"),
                    "node_count": len(topology.get("nodes") or []),
                    "edge_count": len(topology.get("edges") or []),
                }
            )
        return items

    def get_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        path = self._snapshot_path(snapshot_id)
        if not path.is_file():
            raise LspNotFound("Không tìm thấy snapshot LSP")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LspNotFound(f"Snapshot LSP bị lỗi: {exc}") from exc

    def delete_snapshot(self, snapshot_id: str) -> bool:
        path = self._snapshot_path(snapshot_id)
        if not path.is_file():
            return False
        path.unlink()
        shutil.rmtree(self.evidence_root / snapshot_id, ignore_errors=True)
        return True

    def delete_raw(self, snapshot_id: str) -> int:
        """Delete raw evidence for one snapshot; keep the snapshot metadata."""
        self._snapshot_path(snapshot_id)
        target = self.evidence_root / snapshot_id
        if not target.is_dir():
            return 0
        count = sum(1 for item in target.rglob("*") if item.is_file())
        shutil.rmtree(target, ignore_errors=True)
        return count

    def cleanup_raw(self, *, include_discovery: bool = True) -> dict[str, int]:
        """Remove raw evidence directories that no snapshot references."""
        referenced = {
            path.stem
            for path in self.snapshot_root.glob("lsp_*.json")
        }
        removed_dirs = 0
        removed_files = 0
        for directory in self.evidence_root.iterdir() if self.evidence_root.is_dir() else []:
            if not directory.is_dir():
                continue
            name = directory.name
            if name in referenced:
                continue
            if name.startswith("discover_") and not include_discovery:
                continue
            removed_files += sum(1 for item in directory.rglob("*") if item.is_file())
            shutil.rmtree(directory, ignore_errors=True)
            removed_dirs += 1
        return {"directories": removed_dirs, "files": removed_files}

    def delete_all_snapshots(self) -> dict[str, int]:
        deleted = 0
        for path in list(self.snapshot_root.glob("lsp_*.json")):
            snapshot_id = path.stem
            path.unlink(missing_ok=True)
            shutil.rmtree(self.evidence_root / snapshot_id, ignore_errors=True)
            deleted += 1
        cleanup = self.cleanup_raw(include_discovery=True)
        return {"snapshots": deleted, **cleanup}

    def classify_snapshot(
        self, snapshot_id: str, *, label: str = "", snapshot_type: str = ""
    ) -> dict[str, Any]:
        record = self.get_snapshot(snapshot_id)
        if label:
            record["label"] = label.strip()[:120]
        if snapshot_type:
            value = snapshot_type.upper()
            if value not in {"BEFORE", "AFTER", "PLANNED", "CAPTURE"}:
                raise LspValidationError("snapshot_type phải là BEFORE, AFTER, PLANNED hoặc CAPTURE")
            record["snapshot_type"] = value
            if "topology" in record and isinstance(record["topology"], dict):
                record["topology"].setdefault("snapshot", {})["snapshot_type"] = value
        self._save_snapshot(record)
        return record

    def compare(self, before_id: str, after_id: str) -> dict[str, Any]:
        before = self.get_snapshot(before_id)
        after = self.get_snapshot(after_id)
        before_topo = before.get("topology") or {}
        after_topo = after.get("topology") or {}
        before_lsp = before_topo.get("lsp") or {}
        after_lsp = after_topo.get("lsp") or {}

        def path_map(topology: dict[str, Any]) -> dict[str, dict[str, Any]]:
            return {
                f"{path.get('role')}:{path.get('name')}": path
                for path in topology.get("paths") or []
            }

        def hop_keys(topology: dict[str, Any]) -> dict[str, set[str]]:
            result: dict[str, set[str]] = {}
            for path in topology.get("paths") or []:
                key = f"{path.get('role')}:{path.get('name')}"
                result[key] = {
                    str(hop.get("ip"))
                    for hop in path.get("hops") or []
                    if hop.get("ip")
                }
            return result

        before_paths = path_map(before_topo)
        after_paths = path_map(after_topo)
        before_hops = hop_keys(before_topo)
        after_hops = hop_keys(after_topo)
        added_hops: list[dict[str, Any]] = []
        removed_hops: list[dict[str, Any]] = []
        for key in sorted(set(before_hops) | set(after_hops)):
            added = sorted(after_hops.get(key, set()) - before_hops.get(key, set()))
            removed = sorted(before_hops.get(key, set()) - after_hops.get(key, set()))
            added_hops.extend({"path": key, "ip": ip} for ip in added)
            removed_hops.extend({"path": key, "ip": ip} for ip in removed)
        status_changes: list[dict[str, Any]] = []
        for key in sorted(set(before_paths) | set(after_paths)):
            old = before_paths.get(key) or {}
            new = after_paths.get(key) or {}
            if (old.get("state"), old.get("display_role")) != (new.get("state"), new.get("display_role")):
                status_changes.append(
                    {
                        "path": key,
                        "before": old.get("display_role") or "MISSING",
                        "after": new.get("display_role") or "MISSING",
                    }
                )
        primary_changed = (before_lsp.get("primary_path") or None) != (after_lsp.get("primary_path") or None)
        active_changed = (before_lsp.get("active_path") or None) != (after_lsp.get("active_path") or None)
        secondary_changed = (before_lsp.get("secondary_paths") or []) != (after_lsp.get("secondary_paths") or [])
        backup_changed = (before_lsp.get("backup_paths") or []) != (after_lsp.get("backup_paths") or [])
        return {
            "before": before,
            "after": after,
            "diff": {
                "primary_changed": primary_changed,
                "active_path_changed": active_changed,
                "secondary_changed": secondary_changed,
                "backup_changed": backup_changed,
                "before_primary": before_lsp.get("primary_path"),
                "after_primary": after_lsp.get("primary_path"),
                "before_active": before_lsp.get("active_path"),
                "after_active": after_lsp.get("active_path"),
                "before_status": before_topo.get("overall_status"),
                "after_status": after_topo.get("overall_status"),
                "added_hops": added_hops,
                "removed_hops": removed_hops,
                "status_changes": status_changes,
                "changed": bool(
                    primary_changed
                    or active_changed
                    or secondary_changed
                    or backup_changed
                    or added_hops
                    or removed_hops
                    or status_changes
                ),
            },
        }

    # --------------------------------------------------------------- planned
    def plan(self, ticket: str, *, source: str = "", lsp: str = "") -> dict[str, Any]:
        if not str(ticket or "").strip():
            raise LspValidationError("Cần dán nội dung ticket (các dòng set/delete)")
        result = parse_planned_ticket(ticket)
        result["source"] = source or None
        result["lsp"] = lsp or (result.get("lsp_names") or [None])[0]
        return result

    # --------------------------------------------------------------- evidence
    def read_evidence(self, snapshot_id: str, evidence_id: str) -> dict[str, Any]:
        record = self.get_snapshot(snapshot_id)
        topology = record.get("topology") or {}
        evidence = next(
            (item for item in topology.get("evidence") or [] if item.get("id") == evidence_id),
            None,
        )
        if evidence is None:
            raise LspNotFound("Không tìm thấy evidence trong snapshot")
        ref = evidence.get("output_ref")
        if not ref:
            raise LspNotFound("Evidence không có file raw")
        candidate = (self.root / ref).resolve()
        if self.root.resolve() not in candidate.parents:
            raise LspNotFound("Đường dẫn evidence không hợp lệ")
        if not candidate.is_file():
            raise LspNotFound("File raw evidence không còn tồn tại")
        return {
            "snapshot_id": snapshot_id,
            "evidence": evidence,
            "text": candidate.read_text(encoding="utf-8", errors="replace"),
            "path": ref,
        }

    def refresh(self) -> None:
        self._cache.clear()
