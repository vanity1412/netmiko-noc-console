"""Tolerant parsers for the Junos ``show`` output used by LSP ViewPath.

The parsers never infer a path from a device/path name. They only extract
facts that are present in the CLI text and keep the original line references so
the topology can point back to evidence. Unknown or ambiguous values become
``None`` / ``UNVERIFIED`` instead of a guess.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

IP_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?:/\d{1,2})?")
SESSION_LINE_RE = re.compile(r"^\s*From:\s*(?P<from>\S+?)(?:,|$)")
LSP_NAME_RE = re.compile(r"\bLSPname:\s*(?P<name>\S+)")
STATE_RE = re.compile(r"\b(?:LSP)?state:\s*(?P<state>[A-Za-z]+)", re.I)
PATH_HEADER_RE = re.compile(
    r"^\s*(?P<active>\*)?\s*(?P<role>Primary|Secondary|Backup|Standby)\s+"
    r"(?P<name>[^\s]+)\s+(?:State:\s*(?P<state>\S+))",
    re.I,
)
PATH_HEADER_NO_NAME_RE = re.compile(
    r"^\s*(?P<active>\*)?\s*(?P<role>Primary|Secondary|Backup|Standby)\s+"
    r"State:\s*(?P<state>\S+)",
    re.I,
)
PATH_HEADER_ALT_RE = re.compile(
    r"^\s*(?P<active>\*)?\s*(?P<role>Primary|Secondary|Backup|Standby)\s+"
    r"(?P<name>[^\s]+)\s*$",
    re.I,
)
ERO_RE = re.compile(r"\bERO:\s*(?P<body>.*)$", re.I)
RRO_RE = re.compile(r"\bRRO:\s*(?P<body>.*)$", re.I)
RECEIVED_RRO_RE = re.compile(r"^\s*Received\s+RRO.*?:\s*(?P<body>.*)$", re.I)
COMPUTED_ERO_RE = re.compile(r"^\s*Computed\s+ERO.*?:\s*(?P<body>.*)$", re.I)
EXPLICIT_ROUTE_RE = re.compile(r"^\s*Explct\s+route:\s*(?P<body>.*)$", re.I)
RECORD_ROUTE_RE = re.compile(r"^\s*Record\s+route:\s*(?P<body>.*)$", re.I)
PATH_RE = re.compile(r"^\s*Path:\s*(?P<body>.*)$", re.I)
BANDWIDTH_RE = re.compile(r"^\s*Bandwidth:\s*(?P<value>\S+)", re.I)
OPER_STATE_RE = re.compile(r"^\s*(?:Oper\s+)?State:\s*(?P<value>[A-Za-z]+)", re.I)
PATH_TYPE_RE = re.compile(r"Path type:\s*(?P<value>\S+)", re.I)

_HOP_WITH_MARK_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:\s*\((?P<mark>[SL])\))?"
    r"(?:\s+(?P<kind>strict|loose))?",
    re.I,
)

PROMPT_RE = re.compile(r"^\s*[^\s@]+@[^\s>]+\>\s*$")
COMMAND_ECHO_RE = re.compile(
    r"^\s*(show|display|set|delete|clear|ping|traceroute)\s+\S+", re.I
)


def clean_lines(text: str | None) -> list[str]:
    if not text:
        return []
    lines: list[str] = []
    for raw in str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if "\x1b" in line:
            line = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line)
        lines.append(line)
    # Drop a leading echoed command and trailing prompt without touching content.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _split_ip(value: str) -> tuple[str, int | None] | None:
    match = IP_RE.search(value or "")
    if not match:
        return None
    ip = match.group(1)
    prefix = None
    suffix = (value or "")[match.end(1) : match.end(1) + 3]
    pref = re.match(r"/(\d{1,2})", suffix)
    if pref:
        prefix = int(pref.group(1))
    return ip, prefix


def _hop_from_token(token: str, *, default_strict: bool = False) -> dict[str, Any] | None:
    token = token.strip().strip("(),")
    match = _HOP_WITH_MARK_RE.search(token)
    if not match:
        return None
    ip = match.group("ip")
    mark = (match.group("mark") or "").upper()
    kind = (match.group("kind") or "").lower()
    if mark == "S" or kind == "strict":
        strict: bool | None = True
    elif mark == "L" or kind == "loose":
        strict = False
    else:
        strict = True if default_strict else False
    return {"ip": ip, "strict": strict}


def _parse_hop_list(body: str, *, default_strict: bool = False) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    last: dict[str, Any] | None = None
    for part in re.split(r"[,\s]+", body or ""):
        token = part.strip().strip("(),")
        if token.upper() in {"S", "L"} and last is not None:
            last["strict"] = token.upper() == "S"
            continue
        hop = _hop_from_token(part, default_strict=default_strict)
        if hop and all(existing["ip"] != hop["ip"] for existing in hops):
            hops.append(hop)
            last = hop
    return hops


def _collect_continuation(lines: list[str], start: int, first_body: str) -> tuple[str, int]:
    """Join an ERO/RRO body that wraps over several indented lines."""
    body = first_body
    index = start + 1
    if body.count("(") > body.count(")"):
        while index < len(lines) and lines[index].strip():
            piece = lines[index].strip()
            if re.match(r"^[A-Za-z][A-Za-z0-9 _-]*:", piece):
                break
            body += " " + piece
            index += 1
            if body.count("(") <= body.count(")"):
                break
    while index < len(lines):
        piece = lines[index].strip()
        if not piece:
            break
        if not re.match(r"^[\(]?\s*(?:\d{1,3}\.){3}\d{1,3}", piece):
            break
        body += " " + piece
        index += 1
    return body, index


# --------------------------------------------------------------------- config
def parse_config_set(text: str | None) -> dict[str, Any]:
    """Parse ``show configuration ... | display set`` for MPLS/RSVP config."""
    lsps: dict[str, dict[str, Any]] = {}
    paths: dict[str, dict[str, Any]] = {}
    mpls_interfaces: list[dict[str, Any]] = []
    rsvp_interfaces: list[dict[str, Any]] = []
    unrelated_rsvp: list[str] = []
    raw_lines = [line.strip() for line in clean_lines(text) if line.strip().startswith("set ")]

    def lsp(name: str) -> dict[str, Any]:
        entry = lsps.setdefault(
            name,
            {
                "name": name,
                "to": None,
                "primary": None,
                "secondary": [],
                "backup": [],
                "no_cspf": False,
                "priority": None,
                "bandwidth": None,
                "standby": False,
                "raw_lines": [],
            },
        )
        return entry

    for line in raw_lines:
        text_line = " ".join(line.split())
        match = re.match(r"^set protocols mpls label-switched-path (\S+)\s+(.+)$", text_line)
        if match:
            name, rest = match.group(1), match.group(2)
            entry = lsp(name)
            entry["raw_lines"].append(text_line)
            to_match = re.match(r"^to\s+(\S+)", rest)
            primary_match = re.match(r"^primary\s+(\S+)", rest)
            secondary_match = re.match(r"^secondary\s+(\S+)(?:\s+(.*))?$", rest)
            backup_match = re.match(r"^backup\s+(\S+)(?:\s+(.*))?$", rest)
            if to_match:
                entry["to"] = to_match.group(1)
            elif primary_match:
                entry["primary"] = primary_match.group(1)
            elif secondary_match:
                secondary = {
                    "name": secondary_match.group(1),
                    "standby": "standby" in (secondary_match.group(2) or "").split(),
                    "raw": text_line,
                }
                entry["secondary"] = [
                    item for item in entry["secondary"] if item["name"] != secondary["name"]
                ] + [secondary]
                entry["standby"] = entry["standby"] or secondary["standby"]
            elif backup_match:
                entry["backup"].append(
                    {
                        "name": backup_match.group(1),
                        "standby": "standby" in (backup_match.group(2) or "").split(),
                        "raw": text_line,
                    }
                )
            elif rest.startswith("no-cspf"):
                entry["no_cspf"] = True
            elif rest.startswith("standby"):
                entry["standby"] = True
            else:
                priority = re.match(r"^priority\s+(\d+)\s+(\d+)", rest)
                bandwidth = re.match(r"^bandwidth\s+(\S+)", rest)
                if priority:
                    entry["priority"] = f"{priority.group(1)} {priority.group(2)}"
                elif bandwidth:
                    entry["bandwidth"] = bandwidth.group(1)
            continue
        path_match = re.match(
            r"^set protocols mpls path (\S+)\s+((?:\d{1,3}\.){3}\d{1,3})(?:\s+(strict|loose))?$",
            text_line,
        )
        if path_match:
            name, ip, kind = path_match.group(1), path_match.group(2), path_match.group(3)
            entry = paths.setdefault(name, {"name": name, "hops": [], "raw_lines": []})
            entry["hops"].append(
                {"ip": ip, "strict": (kind or "").lower() != "loose", "kind": kind or "default"}
            )
            entry["raw_lines"].append(text_line)
            continue
        mpls_if = re.match(r"^set protocols mpls (?:interface|admin-groups)\s+(\S+)", text_line)
        if mpls_if:
            mpls_interfaces.append({"interface": mpls_if.group(1), "raw": text_line})
            continue
        rsvp_if = re.match(r"^set rsvp interface (\S+)(?:\s+(.*))?$", text_line)
        if rsvp_if:
            rest = rsvp_if.group(2) or ""
            bandwidth = re.search(r"bandwidth\s+(\S+)", rest)
            rsvp_interfaces.append(
                {
                    "interface": rsvp_if.group(1),
                    "bandwidth": bandwidth.group(1) if bandwidth else None,
                    "raw": text_line,
                }
            )
            continue
        if re.match(r"^set rsvp ", text_line):
            unrelated_rsvp.append(text_line)

    # Junos display set emits explicit deactivate statements. A deactivated
    # whole LSP or path is not an effective configured path; keep the audit
    # record but remove it from the effective model.
    for raw in clean_lines(text):
        line = " ".join(raw.split())
        match = re.match(
            r"^deactivate protocols mpls label-switched-path (\S+)(?:\s+(.*))?$", line
        )
        if not match:
            continue
        name, rest = match.group(1), (match.group(2) or "").strip()
        entry = lsps.get(name)
        if entry is None:
            continue
        entry.setdefault("deactivated_items", []).append(line)
        if not rest:
            entry["deactivated"] = True
            entry["deactivated_primary"] = entry.get("primary")
            entry["deactivated_secondary"] = list(entry.get("secondary") or [])
            entry["deactivated_backup"] = list(entry.get("backup") or [])
            entry["primary"] = None
            entry["secondary"] = []
            entry["backup"] = []
            continue
        primary = re.match(r"^primary\s+(\S+)", rest)
        secondary = re.match(r"^secondary\s+(\S+)", rest)
        backup = re.match(r"^backup\s+(\S+)", rest)
        if primary:
            if entry.get("primary") == primary.group(1):
                entry["deactivated_primary"] = entry.get("primary")
                entry["primary"] = None
        elif secondary:
            entry["deactivated_secondary"] = (
                list(entry.get("deactivated_secondary") or [])
                + [item for item in entry.get("secondary") or [] if item.get("name") == secondary.group(1)]
            )
            entry["secondary"] = [
                item for item in entry.get("secondary") or [] if item.get("name") != secondary.group(1)
            ]
        elif backup:
            entry["deactivated_backup"] = (
                list(entry.get("deactivated_backup") or [])
                + [item for item in entry.get("backup") or [] if item.get("name") == backup.group(1)]
            )
            entry["backup"] = [
                item for item in entry.get("backup") or [] if item.get("name") != backup.group(1)
            ]

    return {
        "lsps": list(lsps.values()),
        "paths": paths,
        "mpls_interfaces": mpls_interfaces,
        "rsvp_interfaces": rsvp_interfaces,
        "other_rsvp_lines": unrelated_rsvp,
        "raw_lines": raw_lines,
    }


# ---------------------------------------------------------------- LSP extensive
def _new_path(role: str, name: str) -> dict[str, Any]:
    return {
        "role": role.lower(),
        "name": name,
        "state": None,
        "active": False,
        "standby": role.lower() == "standby",
        "oper_path": [],
        "ero": [],
        "computed_ero": [],
        "rro": [],
        "bandwidth": None,
        "oper_state": None,
        "path_type": None,
        "no_cspf": False,
        "raw_lines": [],
    }


def parse_mpls_lsp_extensive(text: str | None) -> dict[str, Any]:
    """Parse ``show mpls lsp [name X] extensive``."""
    lines = clean_lines(text)
    sessions: list[dict[str, Any]] = []
    warnings: list[str] = []
    current: dict[str, Any] | None = None
    path: dict[str, Any] | None = None
    path_lines: list[str] = []
    index = 0

    def finish_path() -> None:
        nonlocal path, path_lines
        if path is not None and current is not None:
            current["paths"].append(path)
        path = None
        path_lines = []

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue

        is_session = bool(re.match(r"^\s*From:", line))
        if is_session:
            finish_path()
            current = {
                "from": None,
                "to": None,
                "lspname": None,
                "state": None,
                "active_path": None,
                "lsp_type": None,
                "direction": "transit" if "LSPstate" in line else "ingress",
                "paths": [],
                "raw_lines": [line],
            }
            sessions.append(current)
            from_match = re.search(r"\bFrom:\s*(\S+?)(?:,|$)", line)
            if from_match:
                current["from"] = from_match.group(1).rstrip(",")
            lsp_match = LSP_NAME_RE.search(line)
            if lsp_match:
                current["lspname"] = lsp_match.group(1).rstrip(",")
            state_match = STATE_RE.search(line)
            if state_match and not path:
                current["state"] = state_match.group("state")
            to_match = re.search(r"\bTo:\s*(\S+?)(?:,|$)", line)
            if to_match:
                current["to"] = to_match.group(1).rstrip(",")
            index += 1
            continue

        if current is None:
            index += 1
            continue

        if re.match(r"^\s*ActivePath:\s*", line):
            value = line.split(":", 1)[1].strip()
            name = value.split("(")[0].strip() if value else ""
            current["active_path"] = name or None
            current["raw_lines"].append(line)
            index += 1
            continue
        if re.match(r"^\s*LSPtype:\s*", line):
            current["lsp_type"] = line.split(":", 1)[1].strip()
            current["raw_lines"].append(line)
            index += 1
            continue
        if re.match(r"^\s*LSPname:\s*", line) and not current.get("lspname"):
            lsp_match = re.match(r"^\s*LSPname:\s*(\S+)", line, re.I)
            if lsp_match:
                current["lspname"] = lsp_match.group(1).rstrip(",")
            path_role = re.search(r"\bLSPpath:\s*(\S+)", line, re.I)
            if path_role:
                current["path_role"] = path_role.group(1).rstrip(",")
            current["raw_lines"].append(line)
            index += 1
            continue
        if re.match(r"^\s*To:\s*", line) and not current.get("to"):
            current["to"] = line.split(":", 1)[1].strip().rstrip(",")
            index += 1
            continue

        header = PATH_HEADER_RE.match(line)
        if not header:
            header = PATH_HEADER_NO_NAME_RE.match(line)
        if not header:
            # A header without a State on the same line is still useful when the
            # block contains an "Oper State" line.
            header = PATH_HEADER_ALT_RE.match(line)
        if header:
            finish_path()
            path_name = header.groupdict().get("name") or ""
            path = _new_path(header.group("role"), path_name)
            path["state"] = (header.groupdict().get("state") or None)
            path["active"] = bool(header.group("active"))
            if path["role"] == "standby":
                path["standby"] = True
            else:
                path["standby"] = False
            path["raw_lines"] = [line]
            index += 1
            continue

        if path is not None:
            if re.match(r"^\s*Standby\b", line, re.I):
                path["standby"] = True
            if re.match(r"^\s*No-?CSPF\b", line, re.I):
                path["no_cspf"] = True
            state_match = OPER_STATE_RE.match(line)
            if state_match:
                path["oper_state"] = state_match.group("value")
            type_match = PATH_TYPE_RE.search(line)
            if type_match:
                path["path_type"] = type_match.group("value")
            bandwidth = BANDWIDTH_RE.match(line)
            if bandwidth:
                path["bandwidth"] = bandwidth.group("value")
            body_match = PATH_RE.match(line)
            if body_match:
                path["oper_path"] = _parse_hop_list(body_match.group("body"))
            ero_match = ERO_RE.search(line)
            if ero_match:
                body, next_index = _collect_continuation(lines, index, ero_match.group("body"))
                path["ero"] = _parse_hop_list(body, default_strict=True)
                path["raw_lines"].append(line)
                index = next_index
                continue
            computed_ero = COMPUTED_ERO_RE.search(line)
            if computed_ero:
                body, next_index = _collect_continuation(lines, index, computed_ero.group("body"))
                path["computed_ero"] = _parse_hop_list(body, default_strict=True)
                path["raw_lines"].append(line)
                index = next_index
                continue
            received_rro = RECEIVED_RRO_RE.search(line)
            if received_rro:
                body, next_index = _collect_continuation(lines, index, received_rro.group("body"))
                path["rro"] = _parse_hop_list(body)
                path["raw_lines"].append(line)
                index = next_index
                continue
            rro_match = RRO_RE.search(line)
            if rro_match:
                body, next_index = _collect_continuation(lines, index, rro_match.group("body"))
                path["rro"] = _parse_hop_list(body)
                path["raw_lines"].append(line)
                index = next_index
                continue
            path_lines.append(line)
            path["raw_lines"].append(line)
            index += 1
            continue

        current["raw_lines"].append(line)
        index += 1

    finish_path()

    for session in sessions:
        if not session.get("lspname"):
            warnings.append("Một RSVP/MPLS session không có LSPname trong output")
        if not session.get("paths") and session.get("direction") != "transit":
            warnings.append(
                f"LSP {session.get('lspname') or session.get('from') or '?'}: "
                "không có operational path block"
            )
    return {"sessions": sessions, "warnings": warnings}


# --------------------------------------------------------------- RSVP session
def parse_rsvp_session_extensive(text: str | None) -> dict[str, Any]:
    lines = clean_lines(text)
    sessions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section = "ingress"
    index = 0
    while index < len(lines):
        line = lines[index]
        if re.match(r"^\s*Ingress RSVP:", line, re.I):
            section = "ingress"
        elif re.match(r"^\s*Transit RSVP:", line, re.I):
            section = "transit"
        elif re.match(r"^\s*Egress RSVP:", line, re.I):
            section = "egress"
        if re.match(r"^\s*From:", line):
            destination = None
            if index > 0:
                previous = lines[index - 1].strip()
                if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", previous):
                    destination = previous
            current = {
                "from": None,
                "to": destination,
                "lspname": None,
                "path_role": None,
                "state": None,
                "direction": section,
                "path": [],
                "rro": [],
                "style": None,
                "raw_lines": [line],
            }
            sessions.append(current)
            from_match = re.search(r"\bFrom:\s*(\S+?)(?:,|$)", line)
            if from_match:
                current["from"] = from_match.group(1).rstrip(",")
            lsp_match = LSP_NAME_RE.search(line)
            if lsp_match:
                current["lspname"] = lsp_match.group(1).rstrip(",")
            path_role = re.search(r"\bLSPpath:\s*(\S+)", line, re.I)
            if path_role:
                current["path_role"] = path_role.group(1).rstrip(",")
            to_match = re.search(r"\bTo:\s*(\S+?)(?:,|$)", line)
            if to_match:
                current["to"] = to_match.group(1).rstrip(",")
            state = STATE_RE.search(line)
            if state:
                current["state"] = state.group("state")
            index += 1
            continue
        if current is not None:
            if re.match(r"^\s*To:\s*", line) and not current.get("to"):
                current["to"] = line.split(":", 1)[1].strip().rstrip(",")
            lsp_match = re.match(r"^\s*LSPname:\s*(\S+)", line, re.I)
            if lsp_match:
                current["lspname"] = lsp_match.group(1).rstrip(",")
            path_role = re.search(r"\bLSPpath:\s*(\S+)", line, re.I)
            if path_role:
                current["path_role"] = path_role.group(1).rstrip(",")
            state = STATE_RE.search(line)
            if state and not current.get("state"):
                current["state"] = state.group("state")
            if re.match(r"^\s*(?:Resv\s+)?Style:\s*", line, re.I):
                current["style"] = line.split(":", 1)[1].strip()
            path_match = re.match(r"^\s*(?:Path|Explct\s+route):\s*(.*)$", line, re.I)
            if path_match:
                current["path"] = _parse_hop_list(path_match.group(1))
            record_match = RECORD_ROUTE_RE.search(line)
            if record_match:
                body = record_match.group("body").replace("<self>", " ")
                body = body.replace("...incomplete", " ")
                current["rro"] = _parse_hop_list(body)
            rro_match = RRO_RE.search(line)
            if rro_match:
                body, next_index = _collect_continuation(lines, index, rro_match.group(1))
                current["rro"] = _parse_hop_list(body)
                current["raw_lines"].append(line)
                index = next_index
                continue
            current["raw_lines"].append(line)
        index += 1
    return {"sessions": sessions}


# --------------------------------------------------------------- RSVP interface
def parse_rsvp_interface(text: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in clean_lines(text):
        stripped = line.strip()
        if not stripped or not re.match(r"^\S+\s+(Up|Down)\b", stripped, re.I):
            continue
        parts = re.split(r"\s{2,}|\s+", stripped)
        if len(parts) < 2:
            continue
        interface = parts[0]
        state = parts[1]
        if not re.match(r"^(Up|Down)$", state, re.I):
            continue
        numbers = [int(p) for p in parts[2:] if p.isdigit()]
        rows.append(
            {
                "interface": interface,
                "state": state.capitalize(),
                "active": numbers[0] if numbers else None,
                "total": numbers[1] if len(numbers) > 1 else None,
                "hello": numbers[2] if len(numbers) > 2 else None,
                "subscription": parts[3] if len(parts) > 3 else None,
                "static_bandwidth": parts[4] if len(parts) > 4 else None,
                "available_bandwidth": parts[5] if len(parts) > 5 else None,
                "reserved_bandwidth": parts[6] if len(parts) > 6 else None,
                "highwater": parts[7] if len(parts) > 7 else None,
                "raw": line,
            }
        )
    return rows


# --------------------------------------------------------------- ISIS / LLDP
def parse_isis_adjacency(text: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in clean_lines(text):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("interface", "isis")):
            continue
        match = re.match(
            r"^(?P<interface>\S+)\s+(?P<system>\S+)\s+(?P<level>\d)\s+"
            r"(?P<state>Up|Down|Init)\s+(?P<hold>\d+)(?:\s+(?P<snpa>\S+))?",
            stripped,
            re.I,
        )
        if match:
            rows.append(
                {
                    "interface": match.group("interface"),
                    "system": match.group("system"),
                    "level": match.group("level"),
                    "state": match.group("state").capitalize(),
                    "hold": int(match.group("hold")),
                    "snpa": match.group("snpa"),
                    "raw": line,
                }
            )
    return rows


def parse_lldp_neighbors(text: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lines = clean_lines(text)
    header_seen = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if "Local Interface" in stripped and "System Name" in stripped:
            header_seen = True
            continue
        if stripped.lower().startswith(("local interface", "lldp")):
            continue
        if not header_seen:
            # Some Junos builds omit the header when filtering; fall back to a
            # row that starts with a physical/ae interface and has 4+ columns.
            if not re.match(r"^(?:[a-z]+-\d+/\d+/\d+|ae\d+|ge-\d+|xe-\d+|et-\d+|irb|vlan)\S*", stripped):
                continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 4:
            parts = re.split(r"\s+", stripped)
        if len(parts) < 4:
            continue
        local = parts[0]
        parent = parts[1]
        chassis = parts[2]
        port = parts[3]
        system = " ".join(parts[4:]).strip() if len(parts) > 4 else ""
        if not system:
            continue
        rows.append(
            {
                "local_interface": local,
                "parent_interface": parent,
                "chassis_id": chassis,
                "port_info": port,
                "system_name": system,
                "raw": line,
            }
        )
    return rows


# ------------------------------------------------------------- interface data
def parse_interface_descriptions(text: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in clean_lines(text):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("interface"):
            continue
        match = re.match(
            r"^(?P<interface>\S+)\s+(?P<admin>up|down|admin-down)\s+"
            r"(?P<link>up|down)\s*(?P<description>.*)$",
            stripped,
            re.I,
        )
        if match:
            rows.append(
                {
                    "interface": match.group("interface"),
                    "admin": match.group("admin").lower(),
                    "link": match.group("link").lower(),
                    "description": match.group("description").strip(),
                    "raw": line,
                }
            )
    return rows


def parse_interfaces_terse(text: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in clean_lines(text):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("interface"):
            continue
        match = re.match(
            r"^(?P<interface>\S+)\s+(?P<admin>up|down)\s+(?P<link>up|down)"
            r"(?:\s+(?P<proto>\S+))?(?:\s+(?P<local>[0-9a-fA-F:.]+(?:/\d{1,3})?))?"
            r"(?:\s+(?P<remote>\S+(?:\s+\S+)?))?\s*$",
            stripped,
            re.I,
        )
        if not match:
            continue
        proto = (match.group("proto") or "").lower()
        local = match.group("local")
        if proto not in {"inet", "inet6", "iso", "mpls", "aenet", "eth", "rn", ""}:
            # The token in the proto column is actually the first data value.
            local = match.group("proto")
            proto = ""
        local_parts = _split_ip(local or "") if local else None
        remote_parts = _split_ip(match.group("remote") or "") if match.group("remote") else None
        rows.append(
            {
                "interface": match.group("interface"),
                "admin": match.group("admin").lower(),
                "link": match.group("link").lower(),
                "proto": proto or None,
                "local_ip": local_parts[0] if local_parts else None,
                "prefix": local_parts[1] if local_parts else None,
                "remote_ip": remote_parts[0] if remote_parts else None,
                "raw": line,
            }
        )
    return rows


def parse_config_interfaces_set(text: str | None) -> list[dict[str, Any]]:
    """Extract ``set interfaces ... family inet address`` from display set."""
    rows: list[dict[str, Any]] = []
    for line in clean_lines(text):
        stripped = line.strip()
        match = re.match(
            r"^set interfaces (?P<interface>\S+) unit (?P<unit>\d+) family inet "
            r"address (?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<prefix>\d{1,2}))?",
            stripped,
        )
        if match:
            rows.append(
                {
                    "interface": f"{match.group('interface')}.{match.group('unit')}",
                    "base_interface": match.group("interface"),
                    "unit": int(match.group("unit")),
                    "local_ip": match.group("ip"),
                    "prefix": int(match.group("prefix")) if match.group("prefix") else None,
                    "raw": line,
                }
            )
    return rows


# -------------------------------------------------------------- planned ticket
def parse_planned_ticket(text: str | None) -> dict[str, Any]:
    """Parse ``set/delete protocols mpls ...`` lines from a change ticket.

    The result is explicitly *planned*: it is never treated as configured or
    operational evidence. Lines are kept verbatim for audit.
    """
    lines = clean_lines(text)
    actions: list[dict[str, Any]] = []
    set_lines: list[str] = []
    lsp_names: set[str] = set()
    warnings: list[str] = []

    for line in lines:
        stripped = line.strip()
        match = re.match(r"^(delete|set)\s+(protocols\s+mpls\s+.+)$", stripped)
        if not match:
            continue
        action, body = match.group(1), match.group(2)
        actions.append({"action": action, "body": body, "raw": stripped})
        if action == "set":
            set_lines.append("set " + body)
        lsp_match = re.match(
            r"^protocols mpls label-switched-path (\S+)", body
        )
        if lsp_match:
            lsp_names.add(lsp_match.group(1))

    parsed = parse_config_set("\n".join(set_lines)) if set_lines else {
        "lsps": [],
        "paths": {},
        "mpls_interfaces": [],
        "rsvp_interfaces": [],
        "other_rsvp_lines": [],
        "raw_lines": [],
    }
    deleted_primary: list[dict[str, Any]] = []
    deleted_secondary: list[dict[str, Any]] = []
    deleted_backup: list[dict[str, Any]] = []
    for action in actions:
        if action["action"] != "delete":
            continue
        body = action["body"]
        primary = re.match(
            r"^protocols mpls label-switched-path (\S+) primary (\S+)", body
        )
        secondary = re.match(
            r"^protocols mpls label-switched-path (\S+) secondary (\S+)", body
        )
        backup = re.match(
            r"^protocols mpls label-switched-path (\S+) backup (\S+)", body
        )
        if primary:
            deleted_primary.append(
                {"lsp": primary.group(1), "path": primary.group(2), "raw": action["raw"]}
            )
        elif secondary:
            deleted_secondary.append(
                {"lsp": secondary.group(1), "path": secondary.group(2), "raw": action["raw"]}
            )
        elif backup:
            deleted_backup.append(
                {"lsp": backup.group(1), "path": backup.group(2), "raw": action["raw"]}
            )
    if actions and not parsed["lsps"]:
        warnings.append(
            "Ticket không chứa dòng 'set protocols mpls' đầy đủ để dựng cấu hình dự kiến"
        )
    if not actions:
        warnings.append("Không tìm thấy dòng set/delete protocols mpls trong ticket")

    return {
        "applied": False,
        "label": "PLANNED — NOT APPLIED",
        "actions": actions,
        "planned_lsps": parsed["lsps"],
        "planned_paths": parsed["paths"],
        "deleted_primary": deleted_primary,
        "deleted_secondary": deleted_secondary,
        "deleted_backup": deleted_backup,
        "lsp_names": sorted(lsp_names),
        "warnings": warnings,
        "note": (
            "Các dòng set/delete trong ticket chỉ là thay đổi đề xuất/lịch sử thao tác; "
            "không phải bằng chứng cấu hình đang tồn tại."
        ),
    }


# --------------------------------------------------------------------- helpers
def normalize_state(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    upper = str(value).strip().upper()
    return {
        "UP": "UP",
        "DOWN": "DOWN",
        "DN": "DOWN",
        "INIT": "DOWN",
        "RESTART": "DOWN",
        "CS": "UNKNOWN",
    }.get(upper, "UNKNOWN")


def hop_key(hops: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(str(hop.get("ip")) for hop in hops if hop.get("ip"))
