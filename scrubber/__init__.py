"""secret-scrub: redact credentials/PII/names/queries before sharing code with an AI, restore afterwards."""
from __future__ import annotations

import getpass
import socket

from .config import Settings
from .detectors import Finding, detect
from .vault import Vault

__all__ = ["redact", "restore", "Vault", "Finding", "detect", "Settings", "machine_identifiers"]


def machine_identifiers() -> list[str]:
    ids = []
    for fn in (getpass.getuser, socket.gethostname):
        try:
            v = fn()
            if v and len(v) >= 4 and v.lower() not in {"root", "localhost", "user"}:
                ids.append(v)
        except Exception:
            pass
    return ids


def redact(text: str, vault: Vault, cfg: Settings | None = None,
           extra_literals: list[str] | None = None) -> tuple[str, list[tuple[Finding, str, str]]]:
    """Stage 1: secrets / PII / queries -> placeholders. Stage 2: rename declared identifiers.

    Report entries: (Finding, original_value, placeholder). Identifier entries have start == -1.
    """
    cfg = cfg or Settings()
    literals = list(cfg.always_hide) + list(extra_literals or [])
    if cfg.enabled("machine_ids"):
        literals += machine_identifiers()
    if cfg.reuse_vault_values:
        literals += vault.known_values()
    literals = [l for l in dict.fromkeys(literals) if l not in cfg.never_hide]

    findings = _absorb_trailing_digits(text, detect(text, cfg, literals=literals))
    out, report, last = [], [], 0
    for f in findings:
        value = text[f.start:f.end]
        ph = vault.placeholder_for(value, f.kind)
        out.append(text[last:f.start])
        out.append(ph)
        report.append((f, value, ph))
        last = f.end
    out.append(text[last:])
    result = "".join(out)

    kinds = {k for k, v in cfg.ident_kinds.items() if v}
    if cfg.rename_identifiers and kinds:
        from .identifiers import rename
        result, idents = rename(result, vault.placeholder_for, kinds=kinds, min_len=cfg.ident_min_len,
                                comments=cfg.rename_in_comments, strings=cfg.rename_in_strings,
                                exclude=set(cfg.never_hide), protect=vault.unknown_regex())
        report += [(Finding(-1, -1, kind), name, ph) for kind, name, ph in idents]
    return result, report


def _absorb_trailing_digits(text: str, findings: list[Finding]) -> list[Finding]:
    """A placeholder must never be followed by a digit (REDACTED_X_0001 + "5" would read as
    REDACTED_X_00015). Grow such findings over the digits (and any finding they then touch)."""
    out: list[Finding] = []
    i = 0
    while i < len(findings):
        f = findings[i]
        start, end, kind = f.start, f.end, f.kind
        i += 1
        while True:
            while end < len(text) and text[end].isdigit():
                end += 1
            if i < len(findings) and findings[i].start < end:
                end = max(end, findings[i].end)
                i += 1
                continue
            break
        out.append(Finding(start, end, kind) if end != f.end else f)
    return out


def restore(text: str, vault: Vault) -> tuple[str, list[str], list[str]]:
    """Returns (restored_text, restored_placeholders, unknown_placeholders)."""
    restored: list[str] = []
    rx = vault.restore_regex()
    if rx is not None:
        def sub(m, depth=0):
            restored.append(m.group())
            value = vault.by_placeholder[m.group()]
            # a value can itself contain placeholders when already-redacted text was redacted again
            if depth < 10 and rx.search(value):
                value = rx.sub(lambda m2: sub(m2, depth + 1), value)
            return value
        out = rx.sub(sub, text)
    else:
        out = text
    known = set(vault.by_placeholder)
    unknown = [m.group() for m in vault.unknown_regex().finditer(text) if m.group() not in known]
    return out, restored, unknown
