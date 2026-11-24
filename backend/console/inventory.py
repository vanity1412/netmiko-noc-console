"""Inventory view built from MCP ``ssh_inventory`` plus read-only CSV metadata.

The MCP inventory is authoritative for aliases, hosts, drivers and profiles.
The existing ``input/device.csv`` is read only to expose operational metadata
(manufacturer, function, POP, zone) that the MCP tool does not return. Nothing
is copied into the Web Console data directory and no credentials are read.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .mcp_client import MCPError, StdioMCPClient
from .settings import Settings

log = logging.getLogger("netmiko_web.inventory")

VENDOR_LABELS = {
    "cisco": "Cisco",
    "juniper": "Juniper",
    "huawei": "Huawei",
    "vertiv": "Vertiv",
    "linux": "Linux",
    "other": "Khác",
}
VENDOR_ORDER = ["cisco", "juniper", "huawei", "vertiv", "linux", "other"]
CATEGORY_LABELS = {"oob": "OOB", "bras": "BRAS"}
DEVICE_TYPE_LABELS = {
    "cisco_ios": "Cisco IOS",
    "cisco_xr": "Cisco XR",
    "cisco_nxos": "Cisco NX-OS",
    "juniper_junos": "Juniper Junos",
    "huawei": "Huawei VRP",
    "generic_termserver": "Generic termserver",
    "linux": "Linux",
    "autodetect": "Autodetect",
}


class InventoryUnavailable(RuntimeError):
    def __init__(self, message: str, *, cached: bool = False):
        super().__init__(message)
        self.cached = cached


def _decode_csv(raw: bytes) -> tuple[str, str]:
    for encoding in ("utf-8-sig", "utf-8", "cp1258", "cp1252"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1"), "latin-1"


def load_csv_metadata(path: Path) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    """Parse the existing inventory CSV defensively; never fail the whole UI."""
    meta: dict[str, dict[str, str]] = {}
    info: dict[str, Any] = {"path": str(path), "loaded": False, "rows": 0, "duplicates": 0}
    if not path.is_file():
        info["error"] = "Không tìm thấy file inventory CSV"
        return meta, info
    try:
        text, encoding = _decode_csv(path.read_bytes())
        reader = csv.DictReader(io.StringIO(text))
        fields = {str(name or "").strip().casefold() for name in (reader.fieldnames or [])}
        if not {"name", "ip"}.issubset(fields):
            raise ValueError("CSV cần cột name và ip")
        rows = 0
        for row in reader:
            name = (row.get("name") or "").strip()
            if not name:
                continue
            key = name.casefold()
            if key in meta:
                info["duplicates"] += 1
                continue
            rows += 1
            meta[key] = {
                "manufacturer": (row.get("manufacturer") or "").strip(),
                "function": (row.get("function") or "").strip(),
                "room": (row.get("room") or "").strip(),
                "rack": (row.get("rack") or "").strip(),
                "pop": (row.get("pop") or "").strip(),
                "zone": (row.get("serviceZoneName") or "").strip(),
                "description": (row.get("description") or "").strip(),
                "csv_profile": (row.get("profile") or "").strip(),
            }
        info.update(loaded=True, rows=rows, encoding=encoding)
    except Exception as exc:
        info["error"] = f"Không đọc được inventory CSV: {exc}"
        log.warning("inventory csv error: %s", exc)
    return meta, info


def normalize_vendor(manufacturer: str, device_type: str) -> str:
    value = (manufacturer or "").strip().casefold()
    if value in VENDOR_LABELS:
        return value
    if value in {"server", "linux server", "unix"}:
        return "linux"
    dtype = (device_type or "").strip().casefold()
    if dtype.startswith("cisco"):
        return "cisco"
    if dtype.startswith("juniper"):
        return "juniper"
    if dtype.startswith("huawei"):
        return "huawei"
    if dtype.startswith("linux") or dtype.startswith("generic_"):
        return "linux" if dtype.startswith("linux") else "other"
    return "other"


def categorize(function: str) -> list[str]:
    text = (function or "").casefold()
    result = []
    if "oob" in text or "out of band" in text:
        result.append("oob")
    if "bras" in text:
        result.append("bras")
    return result


def _split_values(values: Iterable[str] | None) -> set[str]:
    result: set[str] = set()
    for value in values or []:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                result.add(part)
    return result


QUERY_SEPARATORS = re.compile(r"[\r\n,;|]+")


def split_query_entries(q: str) -> list[str]:
    """Split the search box into individual entries, keeping original casing."""
    if not (q or "").strip():
        return []
    return [part.strip() for part in QUERY_SEPARATORS.split(q) if part.strip()]


def parse_query_terms(q: str) -> list[tuple[str, ...]]:
    """Split a search box value into OR-groups of AND tokens.

    Operators can paste a device list (one alias per line, or comma/semicolon
    separated) and each entry becomes an independent alternative. A single
    entry without separators keeps the original substring behaviour, while
    whitespace inside an entry still requires every token to be present.
    """
    groups: list[tuple[str, ...]] = []
    for entry in split_query_entries(q):
        tokens = tuple(token for token in entry.casefold().split() if token)
        if tokens:
            groups.append(tokens)
    return groups


class InventorySnapshot:
    def __init__(self, devices: list[dict[str, Any]], *, cached_at: float, meta: dict[str, Any]):
        self.devices = devices
        self.cached_at = cached_at
        self.meta = meta
        self.by_name = {row["name"]: row for row in devices}

    def query(
        self,
        *,
        q: str = "",
        vendors: Iterable[str] | None = None,
        device_types: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        pops: Iterable[str] | None = None,
        zones: Iterable[str] | None = None,
        profiles: Iterable[str] | None = None,
        functions: Iterable[str] | None = None,
        page: int = 1,
        limit: int = 100,
        sort: str = "name",
        direction: str = "asc",
    ) -> dict[str, Any]:
        filters = {
            "q": parse_query_terms(q),
            "vendor": {v.casefold() for v in _split_values(vendors)},
            "device_type": _split_values(device_types),
            "category": {v.casefold() for v in _split_values(categories)},
            "pop": _split_values(pops),
            "zone": _split_values(zones),
            "profile": _split_values(profiles),
            "function": _split_values(functions),
        }
        rows = [row for row in self.devices if self._matches(row, filters)]
        sort_key = {
            "name": lambda row: row["name"].casefold(),
            "host": lambda row: row["host"].casefold(),
            "vendor": lambda row: (VENDOR_ORDER.index(row["vendor"]) if row["vendor"] in VENDOR_ORDER else 99, row["name"].casefold()),
            "device_type": lambda row: (row["device_type"].casefold(), row["name"].casefold()),
            "pop": lambda row: (row["pop"].casefold(), row["name"].casefold()),
            "function": lambda row: (row["function"].casefold(), row["name"].casefold()),
        }.get(sort, lambda row: row["name"].casefold())
        rows.sort(key=sort_key, reverse=(direction == "desc"))
        total = len(rows)
        page = max(1, int(page))
        limit = max(1, min(int(limit), 2000))
        start = (page - 1) * limit
        page_rows = rows[start : start + limit]
        return {
            "rows": page_rows,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": max(1, (total + limit - 1) // limit),
            "facets": self._facets(filters),
            "inventory": self.meta,
            "query_terms": len(filters["q"]),
            "unmatched_terms": self._unmatched_terms(split_query_entries(q)),
        }

    def _unmatched_terms(self, entries: list[str]) -> list[str]:
        """Report pasted entries that match no device so typos stay visible."""
        if len(entries) < 2:
            return []
        unmatched = []
        for entry in entries:
            tokens = tuple(token for token in entry.casefold().split() if token)
            if not tokens:
                continue
            if not any(
                all(token in (row.get("_search") or "") for token in tokens)
                for row in self.devices
            ):
                unmatched.append(entry)
        return unmatched[:50]

    def names(self, **kwargs: Any) -> list[str]:
        kwargs.pop("page", None)
        kwargs.pop("limit", None)
        result = self.query(**kwargs, page=1, limit=10000)
        if result["total"] <= 10000:
            return [row["name"] for row in result["rows"]]
        # Collect all matching names without paging the response payload per page.
        filters = {
            "q": parse_query_terms(kwargs.get("q") or ""),
            "vendor": {v.casefold() for v in _split_values(kwargs.get("vendors"))},
            "device_type": _split_values(kwargs.get("device_types")),
            "category": {v.casefold() for v in _split_values(kwargs.get("categories"))},
            "pop": _split_values(kwargs.get("pops")),
            "zone": _split_values(kwargs.get("zones")),
            "profile": _split_values(kwargs.get("profiles")),
            "function": _split_values(kwargs.get("functions")),
        }
        return [row["name"] for row in self.devices if self._matches(row, filters)]

    @staticmethod
    def _matches(row: dict[str, Any], filters: dict[str, Any], skip: str | None = None) -> bool:
        if skip != "q" and filters["q"]:
            haystack = row.get("_search") or ""
            if not any(all(token in haystack for token in group) for group in filters["q"]):
                return False
        if skip != "vendor" and filters["vendor"] and row["vendor"] not in filters["vendor"]:
            return False
        if skip != "device_type" and filters["device_type"] and row["device_type"] not in filters["device_type"]:
            return False
        if skip != "category" and filters["category"] and not (set(row["categories"]) & filters["category"]):
            return False
        if skip != "pop" and filters["pop"] and row["pop"] not in filters["pop"]:
            return False
        if skip != "zone" and filters["zone"] and row["zone"] not in filters["zone"]:
            return False
        if skip != "profile" and filters["profile"] and row["profile"] not in filters["profile"]:
            return False
        if skip != "function" and filters["function"] and row["function"] not in filters["function"]:
            return False
        return True

    def _facets(self, filters: dict[str, Any]) -> dict[str, Any]:
        counters: dict[str, Counter] = {key: Counter() for key in
                                        ("vendor", "device_type", "category", "pop", "zone", "profile", "function")}
        for row in self.devices:
            for key in counters:
                if not self._matches(row, filters, skip=key):
                    continue
                if key == "vendor":
                    counters[key][row["vendor"]] += 1
                elif key == "device_type":
                    counters[key][row["device_type"]] += 1
                elif key == "category":
                    for value in row["categories"]:
                        counters[key][value] += 1
                elif key == "zone":
                    counters[key][row["zone"]] += 1
                elif key == "profile":
                    counters[key][row["profile"]] += 1
                elif key == "pop":
                    counters[key][row["pop"]] += 1
                else:
                    counters[key][row["function"]] += 1

        def ordered(counter: Counter, *, preferred: list[str] | None = None) -> list[dict[str, Any]]:
            items = [(value, count) for value, count in counter.items() if value]
            if preferred:
                items.sort(key=lambda item: (
                    preferred.index(item[0]) if item[0] in preferred else 999,
                    -item[1], item[0].casefold()))
            else:
                items.sort(key=lambda item: (-item[1], item[0].casefold()))
            return [{"value": value, "count": count} for value, count in items]

        vendors = ordered(counters["vendor"], preferred=VENDOR_ORDER)
        for item in vendors:
            item["label"] = VENDOR_LABELS.get(item["value"], item["value"])
        device_types = ordered(counters["device_type"])
        for item in device_types:
            item["label"] = DEVICE_TYPE_LABELS.get(item["value"], item["value"])
        categories = ordered(counters["category"], preferred=["oob", "bras"])
        for item in categories:
            item["label"] = CATEGORY_LABELS.get(item["value"], item["value"])
        return {
            "vendor": vendors,
            "device_type": device_types,
            "category": categories,
            "pop": ordered(counters["pop"]),
            "zone": ordered(counters["zone"]),
            "profile": ordered(counters["profile"]),
            "function": ordered(counters["function"]),
        }


class InventoryService:
    def __init__(self, settings: Settings, mcp: StdioMCPClient, *, ttl: int | None = None):
        self.settings = settings
        self.mcp = mcp
        self.ttl = ttl if ttl is not None else settings.inventory_ttl_seconds
        self._lock = threading.Lock()
        self._snapshot: InventorySnapshot | None = None
        self._csv: dict[str, dict[str, str]] | None = None
        self._csv_meta: dict[str, Any] | None = None
        self._last_error: str | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._snapshot = None

    def get(self, *, force: bool = False) -> InventorySnapshot:
        with self._lock:
            now = time.time()
            if force:
                # A forced refresh must also re-read the read-only metadata CSV.
                self._csv = None
                self._csv_meta = None
            if (
                not force
                and self._snapshot is not None
                and now - self._snapshot.cached_at < self.ttl
            ):
                return self._snapshot
            try:
                snapshot = self._load()
            except Exception as exc:
                self._last_error = str(exc)
                if self._snapshot is not None:
                    # Keep serving the last verified inventory, but report staleness.
                    self._snapshot.meta["stale"] = True
                    self._snapshot.meta["error"] = str(exc)
                    return self._snapshot
                raise InventoryUnavailable(str(exc)) from exc
            self._snapshot = snapshot
            self._last_error = None
            return snapshot

    def _load(self) -> InventorySnapshot:
        if not self.mcp.ping(timeout=5):
            try:
                self.mcp.ensure_ready()
            except MCPError as exc:
                raise InventoryUnavailable(f"MCP không sẵn sàng: {exc}") from exc
        payload, meta = self.mcp.call_tool(
            "ssh_inventory",
            {"limit": 0},
            timeout=self.settings.mcp_inventory_timeout,
        )
        devices = payload.get("devices") or []
        if not isinstance(devices, list):
            raise InventoryUnavailable("MCP ssh_inventory trả về dữ liệu không hợp lệ")
        if not self._csv or self._csv_meta is None:
            self._csv, self._csv_meta = load_csv_metadata(self.settings.inventory_csv)
        merged = []
        matched = 0
        device_type_counts: Counter[str] = Counter()
        for item in devices:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            host = str(item.get("host") or name).strip()
            if not name:
                continue
            device_type = str(item.get("device_type") or "autodetect")
            extra = self._csv.get(name.casefold(), {})
            if extra:
                matched += 1
            manufacturer = extra.get("manufacturer", "")
            vendor = normalize_vendor(manufacturer, device_type)
            function = extra.get("function", "")
            row = {
                "name": name,
                "host": host,
                "device_type": device_type,
                "device_type_label": DEVICE_TYPE_LABELS.get(device_type, device_type),
                "profile": extra.get("csv_profile", "") or "default",
                "vendor": vendor,
                "vendor_label": VENDOR_LABELS.get(vendor, vendor),
                "manufacturer": manufacturer,
                "function": function,
                "pop": extra.get("pop", ""),
                "zone": extra.get("zone", ""),
                "room": extra.get("room", ""),
                "rack": extra.get("rack", ""),
                "description": extra.get("description", ""),
                "categories": categorize(function),
                "in_csv": bool(extra),
                "in_mcp": True,
                "tags": item.get("tags") or [],
            }
            row["_search"] = " ".join(
                str(row.get(key) or "")
                for key in ("name", "host", "description", "function", "pop", "zone", "room", "rack", "manufacturer")
            ).casefold()
            merged.append(row)
            device_type_counts[device_type] += 1
        merged.sort(key=lambda row: row["name"].casefold())
        mcp_names = {row["name"].casefold() for row in merged}
        csv_only = [name for name in self._csv if name not in mcp_names]
        warnings = list(payload.get("warnings") or [])
        if self._csv_meta.get("error"):
            warnings.append(self._csv_meta["error"])
        if csv_only:
            warnings.append(
                f"{len(csv_only)} alias trong CSV không có trong MCP inventory nên không hiển thị"
            )
        meta = {
            "mcp_total": payload.get("total"),
            "mcp_returned": payload.get("returned"),
            "aliases": len(merged),
            "device_types": dict(sorted(device_type_counts.items())),
            "csv": dict(self._csv_meta),
            "csv_enriched": matched,
            "csv_missing": len(merged) - matched,
            "csv_only": len(csv_only),
            "source": "MCP ssh_inventory + input/device.csv (read-only)",
            "warnings": warnings[:20],
            "stale": False,
            "fetched_at": time.time(),
            "fetch_ms": meta.get("duration_ms"),
        }
        return InventorySnapshot(merged, cached_at=time.time(), meta=meta)

    @property
    def last_error(self) -> str | None:
        return self._last_error
