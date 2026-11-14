"""User settings shared by the CLI and the GUI (~/.secret_scrub/settings.json)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

HOME = Path(os.environ.get("SECRET_SCRUB_HOME", Path.home() / ".secret_scrub"))
SETTINGS_FILE = HOME / "settings.json"

# Detector ids grouped for display. Provider ids come from detectors.PROVIDER_PATTERNS.
GROUPS: dict[str, list[tuple[str, str]]] = {
    "Credentials": [
        ("key_assign", "Values of sensitive-named keys (password=, api_key:, token => ...)"),
        ("url_cred", "Passwords in URLs (scheme://user:PASS@host)"),
        ("auth_header", "Bearer / Basic / Token auth headers"),
        ("conn_str", "Connection-string passwords (Password=...;)"),
        ("entropy", "High-entropy random-looking strings"),
    ],
    "Personal data": [
        ("email", "Email addresses"),
        ("ipv4", "IPv4 addresses"),
        ("ipv6", "IPv6 addresses"),
        ("mac", "MAC addresses"),
        ("phone", "Phone numbers"),
        ("card", "Credit card numbers (Luhn-checked)"),
        ("iban", "IBAN bank accounts"),
        ("ssn", "US Social Security numbers"),
        ("home_user", "Usernames in /home/<user> and C:\\Users\\<user> paths"),
        ("machine_ids", "This computer's username and hostname"),
    ],
    "Queries": [
        ("sql_string", "SQL inside string literals"),
        ("graphql", "GraphQL inside string literals"),
        ("raw_sql", "Raw SQL statements (.sql files, scripts)"),
    ],
}

IDENT_KINDS = ["VAR", "FUNC", "CLASS", "PARAM", "ATTR"]


def _default_detectors() -> dict[str, bool]:
    from .detectors import PROVIDER_PATTERNS
    d = {k: True for g in GROUPS.values() for k, _ in g}
    d.update({f"provider:{kind}": True for kind, _ in PROVIDER_PATTERNS})
    return d


@dataclass
class Settings:
    detectors: dict[str, bool] = field(default_factory=_default_detectors)
    entropy_threshold: float = 4.0
    entropy_min_len: int = 20
    min_secret_len: int = 3
    extra_keywords: list[str] = field(default_factory=list)       # extra sensitive key names
    custom_patterns: list[dict] = field(default_factory=list)     # {"name","kind","regex","enabled"}
    always_hide: list[str] = field(default_factory=list)
    never_hide: list[str] = field(default_factory=list)           # allowlist: values & identifier names
    trivial_ips: list[str] = field(default_factory=lambda: ["127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8", "8.8.4.4"])
    rename_identifiers: bool = True
    ident_kinds: dict[str, bool] = field(default_factory=lambda: {k: True for k in IDENT_KINDS})
    ident_min_len: int = 2
    rename_in_comments: bool = True
    rename_in_strings: bool = True
    reuse_vault_values: bool = True
    placeholder_prefix: str = "REDACTED"
    placeholder_digits: int = 4
    kind_in_placeholder: bool = True
    vault_path: str = str(HOME / "vault.json")
    # GUI only
    theme: str = "dark"
    font_family: str = "DejaVu Sans Mono"
    font_size: int = 11
    auto_copy: bool = True
    highlight: bool = True
    wrap: bool = False

    def enabled(self, det_id: str) -> bool:
        return self.detectors.get(det_id, True)

    @classmethod
    def load(cls, path: Path = SETTINGS_FILE) -> "Settings":
        s = cls()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return s
            for k, v in data.items():
                if hasattr(s, k):
                    if k in ("detectors", "ident_kinds"):
                        getattr(s, k).update(v)
                    else:
                        setattr(s, k, v)
        # legacy always_hide.txt
        legacy = HOME / "always_hide.txt"
        if legacy.exists():
            for line in legacy.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line not in s.always_hide:
                    s.always_hide.append(line)
        return s

    def save(self, path: Path = SETTINGS_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)
