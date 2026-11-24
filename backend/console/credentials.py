"""Credential profile management for the Web Console.

This module edits the *existing* MCP credential JSON in place. It never copies
secrets into the Web data directory, never logs them and never returns them in
the profile list. Revealing a secret is an explicit, token-protected action.

Security model: loopback-only Web Console + per-start random token. The file is
the Web Console's own credential file. Changes take effect only after the Web
Console MCP is restarted.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from .inventory import InventoryUnavailable, InventoryService
from .settings import Settings

CREDENTIAL_FIELDS = {
    "username",
    "password",
    "secret",
    "use_keys",
    "key_file",
    "allow_agent",
    "passphrase",
}
PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class CredentialError(ValueError):
    pass


class CredentialStore:
    def __init__(self, settings: Settings, inventory: InventoryService):
        self.settings = settings
        self.inventory = inventory
        self.path = settings.credentials_path
        self.shared = False

    # ------------------------------------------------------------------ shared
    def _display_path(self) -> str:
        try:
            return self.path.relative_to(self.settings.root).as_posix()
        except ValueError:
            return self.path.name

    def info(self) -> dict[str, Any]:
        exists = self.path.is_file()
        stat = None
        if exists:
            try:
                stat = self.path.stat()
            except OSError:
                stat = None
        return {
            "path": str(self.path),
            "display_path": self._display_path(),
            "exists": exists,
            "shared": self.shared,
            "size": stat.st_size if stat else 0,
            "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)) if stat else None,
            "warning": (
                "File credential riêng của Web Console/MCP. "
                "Không đưa file này vào báo cáo, ZIP phát hành hoặc chia sẻ ra ngoài."
            ),
        }

    def usage(self) -> dict[str, int]:
        try:
            snapshot = self.inventory.get()
        except Exception:
            return {}
        counts: Counter[str] = Counter()
        for device in snapshot.devices:
            counts[(device.get("profile") or "default")] += 1
        return dict(counts)

    # ------------------------------------------------------------------- read
    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise CredentialError(f"credential JSON lỗi: {exc}") from exc
        except OSError as exc:
            raise CredentialError(f"Không đọc được credential: {exc}") from exc
        if not isinstance(data, dict) or set(data) != {"profiles"} or not isinstance(data["profiles"], dict):
            raise CredentialError("Credential file phải chỉ chứa object 'profiles'")
        profiles: dict[str, dict[str, Any]] = {}
        for name, profile in data["profiles"].items():
            if not isinstance(name, str) or not PROFILE_RE.fullmatch(name):
                raise CredentialError(f"Tên profile không hợp lệ: {name!r}")
            if not isinstance(profile, dict) or set(profile) - CREDENTIAL_FIELDS:
                raise CredentialError(f"Profile {name} chứa field không hỗ trợ")
            self._validate_profile(name, profile)
            profiles[name] = dict(profile)
        return profiles

    def _validate_profile(self, name: str, profile: dict[str, Any]) -> None:
        username = profile.get("username", "")
        if not isinstance(username, str) or not username.strip():
            raise CredentialError(f"Profile {name}: thiếu username")
        for key in ("password", "secret", "key_file", "passphrase"):
            value = profile.get(key, "")
            if value is not None and not isinstance(value, str):
                raise CredentialError(f"Profile {name}: {key} phải là chuỗi")
        for key in ("use_keys", "allow_agent"):
            value = profile.get(key, False)
            if not isinstance(value, bool):
                raise CredentialError(f"Profile {name}: {key} phải là boolean")
        if not any(
            (
                profile.get("password"),
                profile.get("key_file"),
                profile.get("use_keys"),
                profile.get("allow_agent"),
            )
        ):
            raise CredentialError(
                f"Profile {name}: cần password, key_file, use_keys hoặc allow_agent"
            )

    def list(self) -> dict[str, Any]:
        profiles = self._load()
        usage = self.usage()
        items = []
        for name, profile in profiles.items():
            password = str(profile.get("password") or "")
            key_file = str(profile.get("key_file") or "")
            use_keys = bool(profile.get("use_keys", False))
            allow_agent = bool(profile.get("allow_agent", False))
            if password:
                auth_type = "password"
            elif key_file or use_keys:
                auth_type = "key"
            elif allow_agent:
                auth_type = "agent"
            else:
                auth_type = "none"
            items.append(
                {
                    "name": name,
                    "username": str(profile.get("username") or ""),
                    "auth_type": auth_type,
                    "has_password": bool(password),
                    "has_secret": bool(profile.get("secret")),
                    "has_passphrase": bool(profile.get("passphrase")),
                    "key_file": key_file,
                    "use_keys": use_keys,
                    "allow_agent": allow_agent,
                    "secret_set": bool(profile.get("secret")),
                    "usage": usage.get(name, 0),
                }
            )
        return {
            "info": self.info(),
            "profiles": items,
            "total_profiles": len(items),
            "unused_profiles": [item["name"] for item in items if not item["usage"]],
        }

    def reveal(self, name: str) -> dict[str, Any]:
        profiles = self._load()
        if name not in profiles:
            raise CredentialError("Không tìm thấy profile")
        profile = profiles[name]
        return {
            "name": name,
            "username": profile.get("username", ""),
            "password": profile.get("password", ""),
            "secret": profile.get("secret", ""),
            "passphrase": profile.get("passphrase", ""),
            "key_file": profile.get("key_file", ""),
        }

    # ------------------------------------------------------------------ write
    def upsert(
        self,
        name: str,
        *,
        username: str,
        password: str | None = None,
        secret: str | None = None,
        passphrase: str | None = None,
        key_file: str | None = None,
        use_keys: bool | None = None,
        allow_agent: bool | None = None,
        clear_password: bool = False,
        clear_secret: bool = False,
        clear_passphrase: bool = False,
    ) -> dict[str, Any]:
        if not PROFILE_RE.fullmatch(name or ""):
            raise CredentialError("Tên profile chỉ gồm chữ, số, dấu . _ - (tối đa 64)")
        username = (username or "").strip()
        if not username:
            raise CredentialError("Username không được để trống")
        profiles = self._load()
        profile = dict(profiles.get(name, {}))
        profile["username"] = username
        if clear_password:
            profile["password"] = ""
        elif password is not None:
            profile["password"] = password
        if clear_secret:
            profile["secret"] = ""
        elif secret is not None:
            profile["secret"] = secret
        if clear_passphrase:
            profile["passphrase"] = ""
        elif passphrase is not None:
            profile["passphrase"] = passphrase
        if key_file is not None:
            profile["key_file"] = key_file.strip()
        if use_keys is not None:
            profile["use_keys"] = bool(use_keys)
        if allow_agent is not None:
            profile["allow_agent"] = bool(allow_agent)
        # Keep the file shape minimal, but preserve explicit false/empty values.
        for key in ("password", "secret", "passphrase", "key_file"):
            profile.setdefault(key, "")
        profile.setdefault("use_keys", False)
        profile.setdefault("allow_agent", False)
        self._validate_profile(name, profile)
        profiles[name] = profile
        self._write(profiles)
        return {"ok": True, "profile": name, "restart_required": True, "info": self.info()}

    def delete(self, name: str, *, force: bool = False) -> dict[str, Any]:
        profiles = self._load()
        if name not in profiles:
            raise CredentialError("Không tìm thấy profile")
        if name == "default" and not force:
            raise CredentialError("Không xóa profile 'default' khi chưa force")
        del profiles[name]
        self._write(profiles)
        return {"ok": True, "deleted": name, "restart_required": True, "info": self.info()}

    def _write(self, profiles: dict[str, dict[str, Any]]) -> None:
        for name, profile in profiles.items():
            if not PROFILE_RE.fullmatch(name):
                raise CredentialError(f"Tên profile không hợp lệ: {name!r}")
            if set(profile) - CREDENTIAL_FIELDS:
                raise CredentialError(f"Profile {name} chứa field không hỗ trợ")
            self._validate_profile(name, profile)
        payload = {"profiles": profiles}
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise CredentialError(f"Không ghi được credential file: {exc}") from exc
