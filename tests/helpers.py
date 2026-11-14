"""Shared test helpers. Every test runs against a throwaway SECRET_SCRUB_HOME so the
user's real ~/.secret_scrub (settings + vault) is never read or written."""
from __future__ import annotations

import os
import random
import string
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP_HOME = tempfile.mkdtemp(prefix="secret_scrub_test_home_")
os.environ["SECRET_SCRUB_HOME"] = _TMP_HOME          # must happen before importing scrubber
sys.path.insert(0, str(ROOT))

from scrubber import Settings, Vault, redact, restore  # noqa: E402,F401

TMP_HOME = Path(_TMP_HOME)


def make_cfg(**over) -> Settings:
    cfg = Settings()
    cfg.detectors["machine_ids"] = False   # keep results independent of the test machine
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def make_vault(tmpdir: str | Path, cfg: Settings | None = None) -> Vault:
    cfg = cfg or make_cfg()
    cfg.vault_path = str(Path(tmpdir) / "vault.json")
    return Vault.from_settings(cfg)


ALNUM = string.ascii_letters + string.digits


def rand_str(rng: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def strong_secret(rng: random.Random, n: int = 24) -> str:
    """Random mixed-class value guaranteed to contain a digit, lower and upper."""
    core = rand_str(rng, n - 3, ALNUM + "!%^*-_.")
    return rng.choice(string.ascii_lowercase) + core + rng.choice(string.digits) + rng.choice(string.ascii_uppercase)


def luhn_number(rng: random.Random, length: int = 16, prefix: str = "4") -> str:
    digits = [int(c) for c in prefix] + [rng.randint(0, 9) for _ in range(length - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)
