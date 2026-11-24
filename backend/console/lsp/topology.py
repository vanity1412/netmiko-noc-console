"""Build a verifiable LSP topology from parsed Junos data.

The builder is deliberately conservative:

* a node is only labelled with a hostname when an IP/interface or LLDP/ISIS
  neighbour maps it to the MCP inventory or a device whose CLI was read;
* a physical link is only drawn with interfaces/IPs when LLDP or IS-IS proves
  the adjacency;
* consecutive hops from ERO/RRO are drawn as logical path segments and marked
  UNVERIFIED when no adjacency evidence exists;
* configured, explicit and operational paths are kept separate.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Iterable

from .parser import normalize_state


def _short_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _norm_name(value: str | None) -> str:
    return str(value or "").strip().casefold()


def _base_name(value: str | None) -> str:
    text = _norm_name(value)
    return text.split(".", 1)[0] if text else ""


def _valid_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _status_style(state_label: str, role: str) -> dict[str, str]:
    label = (state_label or "").upper()
    if label in {"ACTIVE", "UP", "PRIMARY ACTIVE", "SECONDARY ACTIVE"}:
        return {"color": "#2dd4a7", "dash": "none", "tone": "ok"}
    if label == "PRIMARY STANDBY":
        return {"color": "#fbbf24", "dash": "10 6", "tone": "warn"}
    if label == "DOWN":
        return {"color": "#fb7185", "dash": "none", "tone": "bad"}
    if label == "STANDBY":
        return {
            "color": "#fbbf24" if role == "secondary" else "#60a5fa",
            "dash": "10 6",
            "tone": "warn",
        }
    if label in {"CONFIGURED", "BACKUP CONFIGURED"} or label.endswith("CONFIGURED"):
        return {"color": "#60a5fa", "dash": "10 6", "tone": "warn"}
    return {"color": "#8597ae", "dash": "6 5", "tone": "muted"}


class _Indexes:
    def __init__(self, inventory: Iterable[dict[str, Any]], corpus: dict[str, Any]):
        self.inventory_rows = [row for row in inventory if isinstance(row, dict)]
        self.by_name = {_norm_name(row.get("name")): row for row in self.inventory_rows}
        self.by_host = {
            str(row.get("host") or "").strip(): row
            for row in self.inventory_rows
            if row.get("host")
        }
        self.corpus = corpus
        self.devices: dict[str, dict[str, Any]] = corpus.get("devices") or {}
        self.ip_index: dict[str, list[dict[str, Any]]] = {}
        self.loopbacks: dict[str, str] = {}
        self.interfaces_by_device: dict[str, dict[str, dict[str, Any]]] = {}
        self._build_interfaces()
        self.adjacency = self._build_adjacency()

    # ------------------------------------------------------------------ names
    def resolve_device_name(self, value: str | None) -> str | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        candidates: list[str] = []
        base = raw.split("(")[0].strip()
        for item in (raw, raw.split(".")[0], base, base.split(".")[0]):
            candidates.append(item)
            stripped = re.sub(r"-re\d+$", "", item, flags=re.I)
            if stripped:
                candidates.append(stripped)
        for candidate in candidates:
            key = _norm_name(candidate)
            if key in self.by_name:
                return str(self.by_name[key].get("name"))
            if key in self.devices:
                return str(self.devices[key].get("name") or key)
        # Match a known device whose hostname is a prefix of an FQDN neighbour.
        for key, row in self.by_name.items():
            if raw.casefold().startswith(key + "."):
                return str(row.get("name"))
        return None

    def inventory_row(self, device: str | None) -> dict[str, Any] | None:
        return self.by_name.get(_norm_name(device))

    # --------------------------------------------------------------- interfaces
    def _add_ip(
        self,
        ip: str | None,
        device: str,
        interface: str,
        *,
        source: str,
        admin: str | None = None,
        link: str | None = None,
        prefix: int | None = None,
        evidence_id: str | None = None,
    ) -> None:
        if not ip or not _valid_ip(ip):
            return
        bucket = self.ip_index.setdefault(ip, [])
        if any(item["device"] == device and item["interface"] == interface for item in bucket):
            return
        bucket.append(
            {
                "ip": ip,
                "device": device,
                "interface": interface,
                "source": source,
                "admin": admin,
                "link": link,
                "prefix": prefix,
                "evidence_id": evidence_id,
            }
        )

    def _build_interfaces(self) -> None:
        for row in self.inventory_rows:
            host = str(row.get("host") or "").strip()
            name = str(row.get("name") or "")
            if host and _valid_ip(host):
                self._add_ip(host, name, "mgmt", source="inventory")
        for device, data in self.devices.items():
            name = str(data.get("name") or device)
            by_if: dict[str, dict[str, Any]] = {}
            evidence = data.get("evidence_ids") or {}
            for item in data.get("interfaces") or []:
                if not isinstance(item, dict):
                    continue
                interface = str(item.get("interface") or "")
                if not interface:
                    continue
                entry = by_if.setdefault(
                    interface,
                    {
                        "interface": interface,
                        "admin": item.get("admin"),
                        "link": item.get("link"),
                        "ips": [],
                        "source": "show interfaces terse",
                        "evidence_id": evidence.get("interfaces"),
                    },
                )
                if item.get("local_ip"):
                    entry["ips"].append(
                        {"ip": item["local_ip"], "prefix": item.get("prefix")}
                    )
                    self._add_ip(
                        item["local_ip"],
                        name,
                        interface,
                        source="show interfaces terse",
                        admin=item.get("admin"),
                        link=item.get("link"),
                        prefix=item.get("prefix"),
                        evidence_id=evidence.get("interfaces"),
                    )
                if item.get("remote_ip"):
                    self._add_ip(
                        item["remote_ip"],
                        name,
                        interface,
                        source="show interfaces terse (remote)",
                        evidence_id=evidence.get("interfaces"),
                    )
            for item in data.get("config_interfaces") or []:
                if not isinstance(item, dict):
                    continue
                interface = str(item.get("interface") or "")
                if not interface:
                    continue
                entry = by_if.setdefault(
                    interface,
                    {
                        "interface": interface,
                        "admin": None,
                        "link": None,
                        "ips": [],
                        "source": "show configuration interfaces",
                        "evidence_id": evidence.get("config_interfaces"),
                    },
                )
                ip = item.get("local_ip")
                if ip and not any(existing.get("ip") == ip for existing in entry["ips"]):
                    entry["ips"].append({"ip": ip, "prefix": item.get("prefix")})
                self._add_ip(
                    ip,
                    name,
                    interface,
                    source="show configuration interfaces",
                    prefix=item.get("prefix"),
                    evidence_id=evidence.get("config_interfaces"),
                )
            for interface, entry in by_if.items():
                if interface.startswith("lo0") and entry["ips"]:
                    usable = [
                        item
                        for item in entry["ips"]
                        if item.get("ip") and not str(item["ip"]).startswith("127.")
                    ]
                    if usable:
                        self.loopbacks.setdefault(name, usable[0]["ip"])
            self.interfaces_by_device[name] = by_if

    def interface_entry(self, device: str | None, interface: str | None) -> dict[str, Any] | None:
        if not device or not interface:
            return None
        return (self.interfaces_by_device.get(device) or {}).get(interface)

    def lookup_ip(self, ip: str | None) -> dict[str, Any] | None:
        if not ip:
            return None
        matches = self.ip_index.get(str(ip)) or []
        if not matches:
            return None
        # Prefer a non-mgmt interface because loopbacks/interfaces prove the
        # actual node, not just the management address.
        ordered = sorted(
            matches,
            key=lambda item: (0 if item.get("interface") != "mgmt" else 1, item["device"]),
        )
        return ordered[0]

    # --------------------------------------------------------------- adjacency
    def _build_adjacency(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for device, data in self.devices.items():
            name = str(data.get("name") or device)
            evidence = data.get("evidence_ids") or {}
            for item in data.get("lldp") or []:
                if not isinstance(item, dict):
                    continue
                remote_name = self.resolve_device_name(item.get("system_name"))
                records.append(
                    {
                        "a_device": name,
                        "b_device": remote_name,
                        "b_label": item.get("system_name"),
                        "a_interface": item.get("local_interface"),
                        "b_interface": None
                        if str(item.get("port_info") or "").strip() in {"", "-"}
                        else str(item.get("port_info")),
                        "source": "LLDP",
                        "state": "Up",
                        "chassis_id": item.get("chassis_id"),
                        "raw": item.get("raw"),
                        "evidence_id": evidence.get("lldp"),
                    }
                )
            for item in data.get("isis") or []:
                if not isinstance(item, dict):
                    continue
                remote_name = self.resolve_device_name(item.get("system"))
                records.append(
                    {
                        "a_device": name,
                        "b_device": remote_name,
                        "b_label": item.get("system"),
                        "a_interface": item.get("interface"),
                        "b_interface": None,
                        "source": f"ISIS-L{item.get('level')}",
                        "state": item.get("state"),
                        "chassis_id": None,
                        "raw": item.get("raw"),
                        "evidence_id": evidence.get("isis"),
                    }
                )
        # Fill the reverse interface from the peer's own LLDP when available.
        for record in records:
            if record["b_device"] and record["b_interface"] is None:
                for peer in records:
                    if (
                        peer["a_device"] == record["b_device"]
                        and peer["b_device"] == record["a_device"]
                        and peer["source"] == "LLDP"
                    ):
                        record["b_interface"] = peer["a_interface"]
                        break
        return records

    def adjacency_between(
        self, device_a: str | None, device_b: str | None
    ) -> list[dict[str, Any]]:
        if not device_a or not device_b:
            return []
        return [
            record
            for record in self.adjacency
            if {record.get("a_device"), record.get("b_device")} == {device_a, device_b}
        ]


def _path_hops_from_config(path_entry: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not path_entry:
        return []
    return [
        {"ip": hop.get("ip"), "strict": hop.get("strict"), "origin": "config-ero"}
        for hop in path_entry.get("hops") or []
        if hop.get("ip")
    ]


def _dedupe_hops(hops: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for hop in hops:
        ip = str(hop.get("ip") or "").strip()
        if not ip:
            continue
        if result and result[-1]["ip"] == ip:
            continue
        result.append({**hop, "ip": ip})
    return result


def _find_operational_path(mpls_session: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if not mpls_session:
        return None
    for path in mpls_session.get("paths") or []:
        if _norm_name(path.get("name")) == _norm_name(name):
            return path
    return None


def _find_rsvp_session(rsvp: dict[str, Any], lsp_name: str) -> dict[str, Any] | None:
    candidates = [
        session
        for session in rsvp.get("sessions") or []
        if _norm_name(session.get("lspname")) == _norm_name(lsp_name)
    ]
    for session in candidates:
        if session.get("direction", "ingress") == "ingress":
            return session
    return candidates[0] if candidates else None


def _find_mpls_session(mpls: dict[str, Any], lsp_name: str) -> dict[str, Any] | None:
    candidates = [
        session
        for session in mpls.get("sessions") or []
        if _norm_name(session.get("lspname")) == _norm_name(lsp_name)
    ]
    for session in candidates:
        if session.get("direction", "ingress") == "ingress":
            return session
    return candidates[0] if candidates else None


def build_topology(
    *,
    source: str,
    lsp_name: str,
    inventory: Iterable[dict[str, Any]],
    corpus: dict[str, Any],
    config: dict[str, Any],
    mpls: dict[str, Any],
    rsvp: dict[str, Any],
    rsvp_interfaces: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    warnings: list[str] | None = None,
    discovery_id: str | None = None,
    planned: dict[str, Any] | None = None,
) -> dict[str, Any]:
    warnings = list(warnings or [])
    indexes = _Indexes(inventory, corpus)
    devices = corpus.get("devices") or {}
    source_corpus = devices.get(source) or {}

    # ------------------------------------------------------------- config LSP
    config_lsp = next(
        (item for item in config.get("lsps") or [] if _norm_name(item.get("name")) == _norm_name(lsp_name)),
        None,
    )
    mpls_session = _find_mpls_session(mpls, lsp_name)
    rsvp_session = _find_rsvp_session(rsvp, lsp_name)
    if config_lsp is None and mpls_session is None and rsvp_session is None:
        raise KeyError(lsp_name)
    if mpls_session is None and rsvp_session is not None:
        # RSVP Bypass LSPs are not returned by "show mpls lsp name"; build the
        # operational path from the RSVP session's explicit/record route.
        rsvp_state = rsvp_session.get("state") or "Unknown"
        rsvp_path = {
            "name": "RSVP bypass path",
            "role": (rsvp_session.get("path_role") or "primary").lower(),
            "state": rsvp_state,
            "active": True,
            "standby": False,
            "oper_state": rsvp_state,
            "oper_path": [],
            "ero": rsvp_session.get("path") or [],
            "computed_ero": [],
            "rro": rsvp_session.get("rro") or [],
            "bandwidth": None,
            "path_type": None,
            "no_cspf": False,
        }
        mpls_session = {
            "lspname": lsp_name,
            "from": rsvp_session.get("from"),
            "to": rsvp_session.get("to"),
            "state": rsvp_state,
            "active_path": "RSVP bypass path",
            "direction": "ingress",
            "paths": [rsvp_path],
            "synthetic": "rsvp_bypass",
        }
        warnings.append(
            "LSP không có trong show mpls lsp name (RSVP Bypass); topology dùng RSVP session/Record route"
        )

    destination = (
        (config_lsp or {}).get("to")
        or (mpls_session or {}).get("to")
        or (rsvp_session or {}).get("to")
    )
    active_path_name = (mpls_session or {}).get("active_path")
    if not active_path_name:
        for path in (mpls_session or {}).get("paths") or []:
            if path.get("active"):
                active_path_name = path.get("name")
                break

    config_paths = config.get("paths") or {}
    path_specs: list[dict[str, Any]] = []
    if config_lsp:
        if config_lsp.get("primary"):
            path_specs.append(
                {"role": "primary", "name": config_lsp["primary"], "standby": False, "configured": True}
            )
        for item in config_lsp.get("secondary") or []:
            path_specs.append(
                {
                    "role": "secondary",
                    "name": item.get("name"),
                    "standby": bool(item.get("standby")),
                    "configured": True,
                }
            )
        for item in config_lsp.get("backup") or []:
            path_specs.append(
                {
                    "role": "backup",
                    "name": item.get("name"),
                    "standby": bool(item.get("standby")),
                    "configured": True,
                }
            )
    # Operational path names that are not in the configuration (e.g. dynamic or
    # a previous config generation) are still shown, but marked unconfigured.
    for oper in (mpls_session or {}).get("paths") or []:
        if not oper.get("name"):
            continue
        if any(_norm_name(item["name"]) == _norm_name(oper["name"]) for item in path_specs):
            continue
        path_specs.append(
            {
                "role": (oper.get("role") or "primary").lower(),
                "name": oper.get("name"),
                "standby": bool(oper.get("standby")),
                "configured": False,
                "operational_only": True,
            }
        )

    evidence_by_command = {
        str(item.get("id")): item for item in evidence if item.get("id")
    }
    source_evidence = source_corpus.get("evidence_ids") or {}

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_pairs: dict[tuple[str, str], int] = {}
    paths: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []

    # Create the ingress node before path building so every path starts at the
    # source device (the first configured hop is normally the next node).
    ingress_key = f"device:{_norm_name(source)}"
    ingress_row = indexes.inventory_row(source)
    ingress_node: dict[str, Any] = {
        "id": _short_id("n", ingress_key),
        "key": ingress_key,
        "hostname": source,
        "label": source,
        "ip": indexes.loopbacks.get(source) or (ingress_row or {}).get("host"),
        "loopback_ip": indexes.loopbacks.get(source),
        "mgmt_ip": (ingress_row or {}).get("host"),
        "device_type": (ingress_row or {}).get("device_type"),
        "device_role": (ingress_row or {}).get("function") or None,
        "role": "INGRESS",
        "role_label": "Ingress PE",
        "resolved": True,
        "verification": "verified" if source_corpus.get("status") == "SUCCESS" else "partial",
        "status": "VERIFIED" if source_corpus.get("status") == "SUCCESS" else "PARTIAL",
        "matched_interface": "lo0.0" if indexes.loopbacks.get(source) else None,
        "matched_source": "source CLI/inventory",
        "evidence_ids": [item for item in source_evidence.values() if item],
        "query_status": source_corpus.get("status"),
    }
    nodes[ingress_key] = ingress_node

    def node_key_for_hop(hop: dict[str, Any], *, role: str) -> tuple[str, dict[str, Any]]:
        ip = str(hop.get("ip") or "")
        match = indexes.lookup_ip(ip)
        if match:
            device = match["device"]
            key = f"device:{_norm_name(device)}"
            node = nodes.get(key)
            if node is None:
                row = indexes.inventory_row(device)
                device_corpus = devices.get(device) or {}
                query_status = device_corpus.get("status")
                node = {
                    "id": _short_id("n", key),
                    "key": key,
                    "hostname": device,
                    "label": device,
                    "ip": ip,
                    "loopback_ip": indexes.loopbacks.get(device),
                    "mgmt_ip": (row or {}).get("host") if row else None,
                    "device_type": (row or {}).get("device_type"),
                    "device_role": (row or {}).get("function") or (row or {}).get("description") or None,
                    "role": "TRANSIT",
                    "role_label": "Transit",
                    "resolved": True,
                    "verification": "verified" if query_status == "SUCCESS" else "inventory",
                    "status": "VERIFIED" if query_status == "SUCCESS" else "PARTIAL",
                    "matched_interface": match.get("interface"),
                    "matched_source": match.get("source"),
                    "evidence_ids": [
                        item
                        for item in (device_corpus.get("evidence_ids") or {}).values()
                        if item
                    ],
                    "query_status": query_status,
                }
                nodes[key] = node
            if not node.get("matched_interface") and match.get("interface"):
                node["matched_interface"] = match.get("interface")
            return key, node
        key = f"ip:{ip}"
        node = nodes.get(key)
        if node is None:
            node = {
                "id": _short_id("n", key),
                "key": key,
                "hostname": None,
                "label": ip,
                "ip": ip,
                "loopback_ip": None,
                "mgmt_ip": None,
                "device_type": None,
                "device_role": None,
                "role": "UNRESOLVED",
                "role_label": "Unresolved hop",
                "resolved": False,
                "verification": "unresolved",
                "status": "UNRESOLVED",
                "matched_interface": None,
                "matched_source": None,
                "evidence_ids": [],
                "query_status": None,
            }
            nodes[key] = node
            unresolved.append({"ip": ip, "path": role, "reason": "Không map được IP tới thiết bị/interface trong inventory hoặc CLI đã đọc"})
        return key, node

    def add_edge(
        *,
        path_id: str,
        path_name: str,
        path_role: str,
        path_state_label: str,
        hop_a: dict[str, Any],
        hop_b: dict[str, Any],
        node_a: dict[str, Any],
        node_b: dict[str, Any],
        index: int,
    ) -> dict[str, Any]:
        pair = (node_a["id"], node_b["id"])
        parallel = edge_pairs.get(pair, 0)
        edge_pairs[pair] = parallel + 1
        adjacency = indexes.adjacency_between(node_a.get("hostname"), node_b.get("hostname"))
        verified = False
        link_status = "UNVERIFIED"
        local_interface = None
        remote_interface = None
        local_ip = None
        remote_ip = None
        link_sources: list[str] = []
        evidence_ids: list[str] = []
        conflict: dict[str, Any] | None = None
        # Direction: use the adjacency record that starts at node_a when possible.
        directed = [record for record in adjacency if record.get("a_device") == node_a.get("hostname")] or adjacency
        if directed:
            up = [record for record in directed if str(record.get("state") or "").lower() == "up"]
            if up:
                verified = True
                link_status = "UP"
            for record in directed:
                link_sources.append(str(record.get("source")))
                if record.get("evidence_id"):
                    evidence_ids.append(str(record["evidence_id"]))
                if local_interface is None and record.get("a_interface"):
                    local_interface = record.get("a_interface")
                if remote_interface is None and record.get("b_interface"):
                    remote_interface = record.get("b_interface")
            # LLDP vs ISIS on the same local interface must agree.
            by_interface: dict[str, set[str]] = {}
            for record in directed:
                if not record.get("a_interface"):
                    continue
                remote = _norm_name(record.get("b_label") or record.get("b_device"))
                if not remote:
                    continue
                by_interface.setdefault(str(record["a_interface"]), set()).add(remote)
            for interface, remotes in by_interface.items():
                if len(remotes) > 1:
                    conflict = {
                        "type": "LLDP_ISIS_CONFLICT",
                        "device": node_a.get("hostname"),
                        "interface": interface,
                        "remote_values": sorted(remotes),
                        "message": "LLDP và IS-IS không cùng neighbor trên interface này",
                    }
                    link_status = "CONFLICT"
                    verified = False
                    break
        local_entry = indexes.interface_entry(node_a.get("hostname"), local_interface)
        remote_entry = indexes.interface_entry(node_b.get("hostname"), remote_interface)
        if local_entry:
            local_ip = (local_entry.get("ips") or [{}])[0].get("ip")
        if remote_entry:
            remote_ip = (remote_entry.get("ips") or [{}])[0].get("ip")
        # LLDP vs operational RRO: if the active path says A -> B but A's only
        # LLDP neighbour is a different device, flag CONFLICT instead of
        # presenting the segment as verified.
        if not conflict and node_b.get("hostname") and "ACTIVE" in path_state_label:
            lldp_remotes = {
                record.get("b_device")
                for record in indexes.adjacency
                if record.get("a_device") == node_a.get("hostname")
                and record.get("source") == "LLDP"
                and record.get("b_device")
            }
            if len(lldp_remotes) == 1 and node_b["hostname"] not in lldp_remotes:
                remote = next(iter(lldp_remotes))
                conflict = {
                    "type": "LLDP_RRO_MISMATCH",
                    "device": node_a.get("hostname"),
                    "interface": local_interface,
                    "lldp": [remote],
                    "rro_next": node_b.get("hostname"),
                    "message": "LLDP neighbor không khớp hop kế tiếp trong RRO active path",
                }
                link_status = "CONFLICT"
                verified = False
        style = _status_style(path_state_label, path_role)
        edge = {
            "id": _short_id("e", f"{path_name}:{index}:{node_a['id']}:{node_b['id']}"),
            "path_id": path_id,
            "path_name": path_name,
            "path_role": path_role,
            "path_state": path_state_label,
            "source": node_a["id"],
            "target": node_b["id"],
            "source_label": node_a["label"],
            "target_label": node_b["label"],
            "kind": "physical" if verified else "logical",
            "verified": verified,
            "status": path_state_label,
            "style": "dashed" if style["dash"] != "none" else "solid",
            "dash": style["dash"],
            "color": style["color"],
            "tone": style["tone"],
            "local_interface": local_interface,
            "remote_interface": remote_interface,
            "local_ip": local_ip,
            "remote_ip": remote_ip,
            "from_hop_ip": hop_a.get("ip"),
            "to_hop_ip": hop_b.get("ip"),
            "bandwidth": None,
            "link_status": link_status,
            "link_sources": sorted(set(item for item in link_sources if item)),
            "strict": hop_a.get("strict"),
            "hop_origin": hop_a.get("origin"),
            "parallel_index": parallel,
            "evidence_ids": sorted(set(evidence_ids + [str(hop_a.get("evidence_id") or "")]) - {""}),
            "conflict": conflict,
            "label": f"{path_role.upper()} · {path_state_label}",
        }
        if conflict:
            conflicts.append(
                {
                    "id": _short_id("c", f"{path_name}:{index}:{local_interface}"),
                    "path": path_name,
                    "edge_id": edge["id"],
                    **conflict,
                }
            )
        edges.append(edge)
        return edge

    # --------------------------------------------------------------- build paths
    used_oper_paths: set[int] = set()
    for spec in path_specs:
        name = str(spec.get("name") or "")
        role = str(spec.get("role") or "primary").lower()
        path_id = _short_id("p", f"{lsp_name}:{name}:{role}")
        oper = _find_operational_path(mpls_session, name)
        if oper is None:
            # Junos often prints an unnamed "*Primary State: Up" block; match it
            # to the configured path by role/order instead of inventing a name.
            for candidate in (mpls_session or {}).get("paths") or []:
                if id(candidate) in used_oper_paths:
                    continue
                if str(candidate.get("role") or "").lower() == role:
                    oper = candidate
                    break
        if oper is not None:
            used_oper_paths.add(id(oper))
        elif name:
            for candidate in (mpls_session or {}).get("paths") or []:
                if id(candidate) not in used_oper_paths and _norm_name(candidate.get("name")) == _norm_name(name):
                    oper = candidate
                    used_oper_paths.add(id(oper))
                    break
        config_hops = _path_hops_from_config(config_paths.get(name))
        oper_state_raw = None
        if oper:
            oper_state_raw = oper.get("oper_state") or oper.get("state")
        if not oper_state_raw and mpls_session and len(mpls_session.get("paths") or []) == 1:
            oper_state_raw = mpls_session.get("state")
        state = normalize_state(oper_state_raw)
        active = _norm_name(active_path_name) == _norm_name(name) or bool((oper or {}).get("active"))
        if not active_path_name and state == "UP" and len(path_specs) == 1:
            active = True
        standby = bool(spec.get("standby")) or bool((oper or {}).get("standby"))
        if state == "UP" and not active:
            standby = True
        if active and state == "UP":
            state_label = "ACTIVE"
        elif state == "UP":
            state_label = "STANDBY"
        elif state == "DOWN":
            state_label = "DOWN"
        elif state == "UNKNOWN" and not oper:
            state_label = "CONFIGURED" if spec.get("configured") else "UNVERIFIED"
        else:
            state_label = "UNVERIFIED"
        if role == "primary" and state_label == "ACTIVE":
            display_role = "PRIMARY ACTIVE"
        elif role == "primary" and state_label == "STANDBY":
            display_role = "PRIMARY STANDBY"
        elif role == "secondary" and state_label == "ACTIVE":
            display_role = "SECONDARY ACTIVE"
        elif role == "secondary":
            display_role = "SECONDARY STANDBY" if standby else "SECONDARY CONFIGURED"
        elif role == "backup":
            display_role = "BACKUP CONFIGURED" if state_label != "ACTIVE" else "BACKUP ACTIVE"
        elif role == "primary" and state_label in {"CONFIGURED", "UNVERIFIED"}:
            display_role = "PRIMARY CONFIGURED"
        elif state_label == "DOWN":
            display_role = "DOWN"
        elif state_label == "ACTIVE":
            display_role = "PRIMARY ACTIVE"
        else:
            display_role = "UNKNOWN"
        if state_label == "DOWN":
            display_role = "DOWN"
        if state_label == "UNVERIFIED" and display_role not in {"PRIMARY CONFIGURED"}:
            display_role = "UNKNOWN"
        hop_source = "config-ero"
        hops: list[dict[str, Any]] = []
        if oper and oper.get("rro"):
            hops = [{"ip": item["ip"], "strict": None, "origin": "operational-rro"} for item in oper["rro"]]
            hop_source = "operational-rro"
        elif oper and oper.get("ero"):
            hops = [
                {"ip": item["ip"], "strict": item.get("strict"), "origin": "operational-ero"}
                for item in oper["ero"]
            ]
            hop_source = "operational-ero"
        elif oper and oper.get("computed_ero"):
            hops = [
                {"ip": item["ip"], "strict": item.get("strict"), "origin": "computed-ero"}
                for item in oper["computed_ero"]
            ]
            hop_source = "computed-ero"
        elif oper and oper.get("oper_path"):
            hops = [
                {"ip": item["ip"], "strict": item.get("strict"), "origin": "lsp-path"}
                for item in oper["oper_path"]
            ]
            hop_source = "lsp-path"
        else:
            hops = config_hops
        hops = _dedupe_hops(hops)
        if destination and _valid_ip(destination):
            if not hops or hops[-1]["ip"] != destination:
                hops.append({"ip": destination, "strict": None, "origin": "lsp-destination"})
        if not hops:
            warnings.append(f"Path {name}: không có hop nào trong config/ERO/RRO")
        # Attach the source evidence for the path and its configuration.
        path_evidence = [
            source_evidence.get("lsp_operational"),
            source_evidence.get("lsp_config"),
            source_evidence.get("rsvp_session"),
            source_evidence.get("paths_config"),
        ]
        path_evidence = [item for item in path_evidence if item]
        annotated_hops: list[dict[str, Any]] = []
        destination_ips: list[str] = []
        previous_node: dict[str, Any] | None = ingress_node
        previous_hop: dict[str, Any] | None = {
            "ip": ingress_node.get("ip"),
            "strict": None,
            "origin": "ingress",
            "evidence_id": path_evidence[0] if path_evidence else None,
        }
        for hop_index, hop in enumerate(hops):
            key, node = node_key_for_hop(hop, role=role)
            hop["node_id"] = node["id"]
            hop["node_key"] = key
            hop["hostname"] = node.get("hostname")
            hop["resolved"] = bool(node.get("resolved"))
            hop["strict"] = hop.get("strict")
            hop["evidence_id"] = path_evidence[0] if path_evidence else None
            if previous_node is not None and previous_node["id"] == node["id"] and annotated_hops:
                # Destination/loopback IP can resolve to the same egress node as
                # the last RRO hop; keep the IP on the node instead of drawing a
                # duplicate hop/self-edge.
                destination_ips.append(str(hop.get("ip")))
                annotated_hops[-1].setdefault("destination_ips", []).append(str(hop.get("ip")))
                continue
            annotated_hops.append(hop)
            if previous_node is not None and previous_hop is not None and previous_node["id"] != node["id"]:
                add_edge(
                    path_id=path_id,
                    path_name=name,
                    path_role=role,
                    path_state_label=display_role,
                    hop_a=previous_hop,
                    hop_b=hop,
                    node_a=previous_node,
                    node_b=node,
                    index=hop_index - 1,
                )
            previous_node, previous_hop = node, hop
        paths.append(
            {
                "id": path_id,
                "name": name or "(unnamed)",
                "role": role,
                "state": state_label,
                "display_role": display_role,
                "active": active,
                "standby": standby,
                "configured": bool(spec.get("configured")),
                "operational_only": bool(spec.get("operational_only")),
                "no_cspf": bool((oper or {}).get("no_cspf") or (config_lsp or {}).get("no_cspf")),
                "hop_source": hop_source,
                "rro": (oper or {}).get("rro") or [],
                "ero": (oper or {}).get("ero") or config_hops,
                "configured_hops": config_hops,
                "hops": annotated_hops,
                "destination_ip": destination_ips[-1] if destination_ips else destination,
                "destination_ips": destination_ips,
                "edge_ids": [
                    edge["id"]
                    for edge in edges
                    if edge["path_id"] == path_id
                ],
                "evidence_ids": path_evidence,
                "style": _status_style(display_role, role),
                "warning": (
                    "RRO không có trong output; đường đang dùng ERO/cấu hình và chưa xác minh từng adjacency"
                    if display_role in {"PRIMARY ACTIVE", "SECONDARY ACTIVE"} and hop_source != "operational-rro"
                    else None
                ),
            }
        )

    # ------------------------------------------------------------- node roles
    ingress_node["role"] = "INGRESS"
    ingress_node["role_label"] = "Ingress PE"
    if destination:
        destination_match = indexes.lookup_ip(destination)
        if destination_match:
            egress_node = nodes.get(f"device:{_norm_name(destination_match['device'])}")
            if egress_node and egress_node["id"] != ingress_node["id"]:
                egress_node["role"] = "EGRESS"
                egress_node["role_label"] = "Egress PE"
    for node in nodes.values():
        if node["role"] == "TRANSIT":
            node["role_label"] = "Transit P/PE"

    # ------------------------------------------------------- conflict summary
    # Compare LLDP and ISIS for every interface on every queried device, even
    # if the conflicting neighbour is not on the selected LSP.
    for device, data in devices.items():
        by_if: dict[str, dict[str, set[str]]] = {}
        for item in data.get("lldp") or []:
            interface = str(item.get("local_interface") or "")
            if interface:
                by_if.setdefault(interface, {"LLDP": set(), "ISIS": set()})["LLDP"].add(
                    _norm_name(item.get("system_name"))
                )
        for item in data.get("isis") or []:
            interface = str(item.get("interface") or "")
            if interface:
                by_if.setdefault(interface, {"LLDP": set(), "ISIS": set()})["ISIS"].add(
                    _norm_name(item.get("system"))
                )
        for interface, sources in by_if.items():
            if sources["LLDP"] and sources["ISIS"] and sources["LLDP"] != sources["ISIS"]:
                record = {
                    "id": _short_id("c", f"{device}:{interface}:global"),
                    "type": "LLDP_ISIS_CONFLICT",
                    "device": device,
                    "interface": interface,
                    "lldp": sorted(sources["LLDP"]),
                    "isis": sorted(sources["ISIS"]),
                    "message": "LLDP và IS-IS không cùng neighbor trên interface này",
                    "evidence_ids": [
                        item
                        for item in (
                            (data.get("evidence_ids") or {}).get("lldp"),
                            (data.get("evidence_ids") or {}).get("isis"),
                        )
                        if item
                    ],
                }
                if not any(
                    item.get("device") == device and item.get("interface") == interface
                    for item in conflicts
                ):
                    conflicts.append(record)

    # Attach device/interface conflicts to affected edges so the canvas can
    # show CONFLICT instead of a generic green/verified link.
    for edge in edges:
        if edge.get("conflict"):
            continue
        for conflict in conflicts:
            if conflict.get("device") == edge.get("source_label") and (
                not conflict.get("interface")
                or not edge.get("local_interface")
                or conflict.get("interface") == edge.get("local_interface")
            ):
                edge["conflict"] = conflict
                edge["verified"] = False
                edge["link_status"] = "CONFLICT"
                break

    # ------------------------------------------------------------ overall state
    active_paths = [path for path in paths if path["state"] == "ACTIVE"]
    down_paths = [path for path in paths if path["state"] == "DOWN"]
    if down_paths and not active_paths:
        overall_status = "DOWN"
    elif active_paths:
        if any(not hop["resolved"] for path in active_paths for hop in path["hops"]):
            overall_status = "PARTIAL"
        elif conflicts:
            overall_status = "CONFLICT"
        elif any(path["hop_source"] != "operational-rro" for path in active_paths):
            overall_status = "PARTIAL"
        else:
            overall_status = "UP"
    else:
        overall_status = "UNVERIFIED"

    if conflicts and overall_status == "UP":
        overall_status = "CONFLICT"

    # ------------------------------------------------------------- summaries
    lsp_summary = {
        "name": lsp_name,
        "ingress": source,
        "egress": None,
        "destination": destination,
        "primary_path": (config_lsp or {}).get("primary"),
        "secondary_paths": [
            {"name": item.get("name"), "standby": bool(item.get("standby"))}
            for item in (config_lsp or {}).get("secondary") or []
        ],
        "backup_paths": [
            {"name": item.get("name"), "standby": bool(item.get("standby"))}
            for item in (config_lsp or {}).get("backup") or []
        ],
        "no_cspf": bool((config_lsp or {}).get("no_cspf")),
        "configured": config_lsp is not None,
        "operational": mpls_session is not None or rsvp_session is not None,
        "operational_state": normalize_state(
            (mpls_session or {}).get("state") or (rsvp_session or {}).get("state")
        ),
        "active_path": active_path_name,
        "rsvp_state": normalize_state((rsvp_session or {}).get("state")),
        "lsp_type": (mpls_session or {}).get("lsp_type"),
        "paths": [
            {
                "name": path["name"],
                "role": path["role"],
                "state": path["state"],
                "display_role": path["display_role"],
                "hop_source": path["hop_source"],
                "hops": [hop["ip"] for hop in path["hops"]],
            }
            for path in paths
        ],
    }
    for node in nodes.values():
        if node["role"] == "EGRESS":
            lsp_summary["egress"] = node["hostname"] or node["ip"]
            break
    if not lsp_summary["egress"] and destination:
        lsp_summary["egress"] = indexes.lookup_ip(destination).get("device") if indexes.lookup_ip(destination) else None

    # Explicit path vs operational RRO divergence is a warning, not a CONFLICT.
    for path in paths:
        if path["state"] == "ACTIVE" and path["rro"]:
            rro_ips = [hop["ip"] for hop in path["rro"]]
            configured_ips = [hop["ip"] for hop in path["configured_hops"]]
            if configured_ips and rro_ips[: len(configured_ips)] != configured_ips:
                path["divergence"] = {
                    "type": "RRO_DIFFERS_FROM_EXPLICIT_PATH",
                    "configured": configured_ips,
                    "rro": rro_ips,
                    "message": "RRO operational khác explicit path trong cấu hình",
                }
                warnings.append(
                    f"Path {path['name']}: RRO operational khác explicit path cấu hình; "
                    "topology dùng RRO cho đường thực tế."
                )

    if planned and planned.get("applied") is False:
        warnings.append(
            "Ticket chỉ là PLANNED — NOT APPLIED; không dùng các dòng set/delete làm bằng chứng cấu hình hiện tại"
        )

    style_counts: dict[str, int] = {}
    for path in paths:
        style_counts[path["display_role"]] = style_counts.get(path["display_role"], 0) + 1

    return {
        "schema_version": 1,
        "discovery_id": discovery_id,
        "generated_at": corpus.get("generated_at"),
        "source": source,
        "lsp": lsp_summary,
        "overall_status": overall_status,
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": paths,
        "unresolved": unresolved,
        "conflicts": conflicts,
        "warnings": warnings,
        "evidence": evidence,
        "devices_queried": [
            {
                "name": device,
                "status": data.get("status"),
                "commands": data.get("command_count"),
                "session_reused": data.get("session_reused"),
                "role": "source" if device == source else "verification",
            }
            for device, data in devices.items()
            if data.get("queried")
        ],
        "rsvp_interfaces": rsvp_interfaces,
        "path_style_counts": style_counts,
        "cache": corpus.get("cache"),
        "query": {
            "source": source,
            "lsp": lsp_name,
            "evidence_complete": all(
                item.get("output_complete") is not False for item in evidence
            ),
        },
    }
