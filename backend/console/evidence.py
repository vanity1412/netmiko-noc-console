"""Evidence access for the raw output viewer, search and copy."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

from .history import HistoryStore
from .settings import Settings


class EvidenceNotFound(LookupError):
    pass


class EvidenceStore:
    def __init__(self, settings: Settings, history: HistoryStore):
        self.settings = settings
        self.history = history

    def _row(self, run_id: str, name: str) -> dict[str, Any]:
        row = self.history.device(run_id, name)
        if row is None:
            raise EvidenceNotFound("Không tìm thấy thiết bị trong run")
        return row

    def path(self, run_id: str, name: str) -> Path:
        row = self._row(run_id, name)
        filename = row.get("output_file")
        if not filename or Path(filename).name != filename:
            raise EvidenceNotFound("Thiết bị không có raw output (lỗi kết nối hoặc chưa lưu)")
        path = self.settings.runs_dir / run_id / filename
        if not path.is_file():
            raise EvidenceNotFound("File raw output không còn trên đĩa")
        return path

    def json_path(self, run_id: str, name: str) -> Path | None:
        row = self._row(run_id, name)
        filename = row.get("json_file")
        if not filename or Path(filename).name != filename:
            return None
        path = self.settings.runs_dir / run_id / filename
        return path if path.is_file() else None

    def page(
        self, run_id: str, name: str, *, offset: int = 0, limit: int | None = None
    ) -> dict[str, Any]:
        row = self._row(run_id, name)
        path = self.path(run_id, name)
        offset = max(0, int(offset))
        limit = max(1, min(int(limit or self.settings.output_page_lines), 10000))
        size = path.stat().st_size
        total_lines = int(row.get("output_lines") or 0)
        chunks: list[str] = []
        count = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index < offset:
                    continue
                chunks.append(line)
                count += 1
                if count >= limit:
                    break
        text = "".join(chunks)
        return {
            "run_id": run_id,
            "name": name,
            "text": text,
            "offset": offset,
            "next_offset": offset + count,
            "returned_lines": count,
            "total_lines": total_lines,
            "total_bytes": size,
            "more": offset + count < total_lines,
            "sha256": row.get("output_sha256"),
        }

    def read_all(self, run_id: str, name: str) -> str:
        path = self.path(run_id, name)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def lines(self, run_id: str, name: str) -> Iterator[str]:
        path = self.path(run_id, name)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            yield from handle

    def search(
        self,
        run_id: str,
        name: str,
        query: str,
        *,
        regex: bool = False,
        limit: int = 200,
        ignore_case: bool = True,
    ) -> dict[str, Any]:
        query = (query or "").strip()
        if not query:
            raise ValueError("Cần nhập từ khóa tìm kiếm")
        if len(query) > 300:
            raise ValueError("Từ khóa tối đa 300 ký tự")
        flags = re.IGNORECASE if ignore_case else 0
        try:
            pattern = re.compile(query if regex else re.escape(query), flags)
        except re.error as exc:
            raise ValueError(f"Regex không hợp lệ: {exc}") from exc
        path = self.path(run_id, name)
        limit = max(1, min(int(limit), 500))
        matches = []
        total = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                found = pattern.search(line)
                if found:
                    total += 1
                    if len(matches) < limit:
                        text = line.rstrip("\n")
                        matches.append(
                            {
                                "line": number,
                                "text": text[:3000],
                                "start": max(0, found.start()),
                            }
                        )
        return {
            "run_id": run_id,
            "name": name,
            "query": query,
            "regex": regex,
            "total_matches": total,
            "shown_matches": len(matches),
            "matches": matches,
            "truncated": total > len(matches),
        }
