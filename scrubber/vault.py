"""Local vault: placeholder <-> original value. Never leaves this machine."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

IDENT_KINDS = ("VAR", "FUNC", "CLASS", "PARAM", "ATTR")
DEFAULT_DIR = Path(os.environ.get("SECRET_SCRUB_HOME", Path.home() / ".secret_scrub"))


class Vault:
    def __init__(self, path: Path, prefix: str = "REDACTED", digits: int = 4, kind_in_name: bool = True):
        self.path = Path(path)
        self.prefix = re.sub(r"\W", "_", prefix) or "REDACTED"
        self.digits = max(2, min(int(digits), 8))
        self.kind_in_name = kind_in_name
        self.by_placeholder: dict[str, str] = {}
        self.kinds: dict[str, str] = {}
        self.by_value: dict[str, str] = {}
        self.counter = 0
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.by_placeholder = data.get("secrets", {})
            self.kinds = data.get("kinds", {})
            self.counter = data.get("counter", len(self.by_placeholder))
            self.by_value = {v: k for k, v in self.by_placeholder.items()}
            for ph in self.by_placeholder:  # legacy vaults without "kinds"
                if ph not in self.kinds:
                    m = re.match(r"[A-Za-z0-9]+_(.+)_\d+$", ph)
                    self.kinds[ph] = m.group(1) if m else "SECRET"

    def placeholder_for(self, value: str, kind: str) -> str:
        """Same value always gets the same placeholder (consistent across files/runs)."""
        if value in self.by_value:
            return self.by_value[value]
        while True:
            self.counter += 1
            mid = f"_{kind}" if self.kind_in_name else ""
            ph = f"{self.prefix}{mid}_{self.counter:0{self.digits}d}"
            if ph not in self.by_placeholder:
                break
        self.by_placeholder[ph] = value
        self.kinds[ph] = kind
        self.by_value[value] = ph
        return ph

    def kind_of(self, ph: str) -> str:
        return self.kinds.get(ph, "SECRET")

    def known_values(self) -> list[str]:
        """Previously hidden data values (identifier names / queries excluded)."""
        return [v for ph, v in self.by_placeholder.items() if self.kind_of(ph) not in IDENT_KINDS + ("QUERY",)]

    def remove(self, ph: str) -> None:
        v = self.by_placeholder.pop(ph, None)
        self.kinds.pop(ph, None)
        if v is not None and self.by_value.get(v) == ph:
            del self.by_value[v]

    def restore_regex(self) -> re.Pattern | None:
        if not self.by_placeholder:
            return None
        keys = sorted(self.by_placeholder, key=len, reverse=True)
        # no look-behind: a placeholder may directly follow another placeholder or a word char
        # (e.g. REDACTED_QUERY_0001REDACTED_EMAIL_0002); redact() guarantees no digit follows one
        return re.compile(r"(?:" + "|".join(map(re.escape, keys)) + r")(?![0-9])")

    def unknown_regex(self) -> re.Pattern:
        """Things that look like placeholders (any prefix used in this vault + current one)."""
        prefixes = {self.prefix} | {ph.split("_", 1)[0] for ph in self.by_placeholder}
        return re.compile(r"(?<![A-Za-z_])(?:" + "|".join(map(re.escape, prefixes)) + r")(?:_[A-Z0-9_]+?)?_\d{2,8}(?![0-9])")

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"counter": self.counter, "secrets": self.by_placeholder, "kinds": self.kinds}, f, indent=2)
        os.replace(tmp, self.path)

    @classmethod
    def from_settings(cls, cfg) -> "Vault":
        return cls(Path(cfg.vault_path).expanduser(), cfg.placeholder_prefix, cfg.placeholder_digits,
                   cfg.kind_in_placeholder)
