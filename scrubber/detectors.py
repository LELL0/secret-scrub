"""Language-agnostic secret detectors.

Each detector yields Finding(start, end, kind) spans pointing at the *value*
only (quotes, key names and surrounding syntax are left intact so the code
still parses and the AI can reason about it).

Over-redaction is harmless: everything is restored 1:1 later.
"""
from __future__ import annotations

import math
import re
from functools import lru_cache
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    kind: str  # becomes part of the placeholder, e.g. API_KEY


# --------------------------------------------------------------------------
# 1. Well-known provider token formats (match anywhere)
# --------------------------------------------------------------------------
PROVIDER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("GITLAB_TOKEN", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}(?![\w-])")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}(?![\w-])")),
    ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
    ("DISCORD_WEBHOOK", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![\w-])")),
    ("GOOGLE_OAUTH", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}(?![\w-])")),
    ("GOOGLE_OAUTH", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}(?![\w-])")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}(?![\w-])")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}(?![\w-])")),
    ("HUGGINGFACE_TOKEN", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PYPI_TOKEN", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}(?![\w-])")),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![\w-])")),
    ("TWILIO_KEY", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("MAILGUN_KEY", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("TELEGRAM_TOKEN", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![\w-])")),
    ("DISCORD_TOKEN", re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}(?![\w-])")),
    ("SHOPIFY_TOKEN", re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b")),
    ("DIGITALOCEAN_TOKEN", re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w-])")),
]

# --------------------------------------------------------------------------
# 2. Credentials embedded in URLs:  scheme://user:PASSWORD@host
# --------------------------------------------------------------------------
URL_CRED = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@\"'`]*:(?P<val>[^\s@/\"'`]+)@")

# Authorization headers / bearer tokens
AUTH_HEADER = re.compile(r"(?i)\b(?:Bearer|Basic|Token)\s+(?P<val>[A-Za-z0-9._~+/=-]{12,})")

# Connection-string fragments:  Password=xyz;  AccountKey=...;
CONN_STR = re.compile(
    r"(?i)\b(?:password|pwd|accountkey|sharedaccesskey|sharedsecret)=(?P<val>[^;\"'`\s<>]+)")

# --------------------------------------------------------------------------
# 3. Assignments whose key *name* looks sensitive (works for most languages,
#    plus JSON / YAML / TOML / INI / .env / XML / properties files)
# --------------------------------------------------------------------------
KEYWORDS = (
    r"passw(?:or)?d|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|priv[_-]?key|client[_-]?secret|credentials?|"
    r"auth[_-]?(?:key|token)|authorization|conn(?:ection)?[_-]?str(?:ing)?|"
    r"signing[_-]?key|encryption[_-]?key|enc[_-]?key|master[_-]?key|salt|"
    r"session[_-]?key|webhook(?:[_-]?url)?|dsn|bot[_-]?token|license[_-]?key"
)
KEY = rf"[\w.\-]*?(?:{KEYWORDS})[\w.\-]*"

# key = "value"   key: 'value'   "key": "value"   key => 'v'   key := "v"
# KEY["x"] = "v"  $password = "v"  @Value("v") String password = ...
QUOTED_ASSIGN = re.compile(
    rf"(?i)(?<![\w])(?P<key>{KEY})[\"'`]?\s*\]?"
    # optional type annotation:  name: string = "v"  (TS/Kotlin/Swift)   var name string = "v"  (Go)
    rf"(?:\s*:\s*[&*]*(?:'\w+\s+)?(?:mut\s+)?[A-Za-z_][\w.<>\[\]|?]*(?:\s*[|<>]\s*[\w.\[\]?]+)*\s*(?==)|[ \t]+[A-Za-z_][\w.\[\]*]*(?=\s*=))?"
    rf"\s*(?:=|:|:=|=>|->|\?\?=|\|\|=)\s*"
    rf"(?:new\s+String\s*\(\s*)?(?:[rRbBuUfF@$]{{0,2}})(?P<q>\"\"\"|'''|[\"'`])(?P<val>(?:\\.|(?!(?P=q))[^\n\\])+)(?P=q)"
)
# setSecret("api_key", "value")   headers.put("X-Api-Key", "value")
QUOTED_PAIR = re.compile(
    rf"(?i)(?P<kq>[\"'])(?P<key>{KEY})(?P=kq)\s*,\s*(?P<q>[\"'`])(?P<val>(?:\\.|(?!(?P=q))[^\n\\])+)(?P=q)"
)
# .env / ini / yaml / properties / toml unquoted:   API_KEY=abc123   token: abc123
UNQUOTED_ASSIGN = re.compile(
    rf"(?im)^[ \t]*(?:export[ \t]+|set[ \t]+|-[ \t]+)?(?P<key>{KEY})[ \t]*(?:=|:)[ \t]*(?P<val>[^\s\"'`#;,]+)[ \t]*(?:#.*)?$"
)
# <password>value</password>
XML_ELEM = re.compile(rf"(?i)<(?P<key>{KEY})(?:\s[^>]*)?>(?P<val>[^<]+)</(?P=key)>")

# Values that are clearly NOT secrets (references, templates, placeholders, types)
NON_SECRET_VALUE = re.compile(
    r"""(?ix)^(?:
        |true|false|null|nil|none|undefined|yes|no|on|off|
        string|str|int|bool|boolean|number|any|object|bytes|text|varchar|
        required|optional|password|secret|token|hidden|text/plain|
        \*+|x+|\.+|-+|
        REDACTED_[A-Z_]+_\d{4}
    )$"""
)
REFERENCE_VALUE = re.compile(
    r"""(?x)^(?:
        \$\{.*\}|\$\(.*\)|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{.*\}\}|<[^>]+>|
        (?:process\.env|os\.environ|os\.getenv|env|ENV|System\.getenv|config|settings|self|this)\b.*
    )$"""
)
LOOKS_LIKE_CODE = re.compile(r"[()\[\]{}]")


def _is_secret_value(val: str, *, unquoted: bool, key: str = "") -> bool:
    v = val.strip()
    if len(v) < 3:
        return False
    if NON_SECRET_VALUE.match(v) or REFERENCE_VALUE.match(v):
        return False
    if unquoted:
        if LOOKS_LIKE_CODE.search(v):
            return False
        # plain identifier / dotted member access (e.g. `token: myToken`, `pwd = user.pwd`)
        # -> only treat as secret when key is UPPER_CASE env-style or value has digits/symbols
        if re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*", v):
            env_style = key.isupper() or "_" in key and key.upper() == key
            has_digit = any(c.isdigit() for c in v)
            if not (env_style or has_digit):
                return False
    return True


# --------------------------------------------------------------------------
# 4. High-entropy quoted strings (catches unknown token formats)
# --------------------------------------------------------------------------
QUOTED_STRING = re.compile(r"(?P<q>[\"'`])(?P<val>[A-Za-z0-9+/=_\-.~:]{20,})(?P=q)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def _looks_random(s: str, threshold: float) -> bool:
    if "/" in s and s.count("/") > 2:  # paths / urls
        return False
    classes = sum([any(c.islower() for c in s), any(c.isupper() for c in s), any(c.isdigit() for c in s)])
    if classes < 2:
        return False
    return shannon_entropy(s) >= threshold


# --------------------------------------------------------------------------
# 5. Personal / infrastructure data (on by default, --no-pii disables)
# --------------------------------------------------------------------------
EMAIL = re.compile(r"(?<![\w.%+:/-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")
# Harmless, generic addresses that carry no information
TRIVIAL_IP = re.compile(r"^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+|1\.1\.1\.1|8\.8\.[48]\.[48])$")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![\w:])"
                  r"|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?:[0-9a-fA-F:]*)(?![\w:])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
PHONE = re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\w)"
                   r"|(?<![\w])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b")
US_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
# Usernames leaked through home-directory paths: keep path, hide the name
HOME_PATH = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)(?P<val>[^/\\\s\"'`]+)")
GENERIC_USERS = {"user", "username", "you", "me", "runner", "ubuntu", "admin", "public",
                 "default", "shared", "<user>", "$user", "%username%", "root"}


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


# --------------------------------------------------------------------------
# 6. Queries: SQL / GraphQL inside string literals, or raw SQL statements
# --------------------------------------------------------------------------
SQL_START = re.compile(
    r"""(?isx)^\s*\(?\s*(?:
        SELECT\b.+?\bFROM\b | INSERT\s+(?:OR\s+\w+\s+)?INTO\b | UPDATE\s+\S+\s+SET\b | DELETE\s+FROM\b |
        REPLACE\s+INTO\b | UPSERT\b | MERGE\s+INTO\b | TRUNCATE\s+(?:TABLE\s+)?\w |
        CREATE\s+(?:OR\s+REPLACE\s+)?(?:UNIQUE\s+)?(?:TEMP(?:ORARY)?\s+)?(?:TABLE|INDEX|VIEW|DATABASE|SCHEMA|PROCEDURE|FUNCTION|TRIGGER|USER|ROLE)\b |
        ALTER\s+(?:TABLE|USER|ROLE|DATABASE)\b | DROP\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA|USER)\b |
        GRANT\b.+\bON\b | REVOKE\b.+\bON\b | WITH\s+(?:RECURSIVE\s+)?\w+\s+AS\s*\( |
        EXEC(?:UTE)?\s+\w | CALL\s+\w+\s*\( |
        (?:query|mutation|subscription)\b[^{]*\{ | \{\s*\w+\s*(?:\([^)]*\))?\s*\{
    )""")
RAW_SQL = re.compile(
    r"""(?imx)^[ \t]*(?:SELECT\b[^;]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|
        CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|INDEX|VIEW|DATABASE|PROCEDURE|FUNCTION|TRIGGER)\b|ALTER\s+TABLE\b|
        DROP\s+(?:TABLE|DATABASE|INDEX|VIEW)\b|WITH\s+\w+\s+AS\s*\()[^;]*;""")


def detect_queries(text: str, sql: bool = True, graphql: bool = True, raw: bool = True) -> list[Finding]:
    from .lexer import blank_non_code, lex
    segs = lex(text)
    found = []
    for s in segs:
        if s.kind == "string" and s.cend - s.cstart >= 10:
            content = text[s.cstart:s.cend]
            # GraphQL '{ x {' form only when it really looks like a query (avoid JSON / format strings)
            is_gql = bool(re.match(r"\s*(?:query|mutation|subscription)\b[^{]*\{[\s\S]*\}", content))
            is_sql = (not is_gql and bool(SQL_START.match(content))
                      and not re.match(r"\s*\{\s*\w+\s*\{", content))
            if (is_sql and sql) or (is_gql and graphql):
                found.append(Finding(s.cstart, s.cend, "QUERY"))
    if raw:
        code = blank_non_code(text, segs)
        found += [Finding(m.start(), m.end(), "QUERY") for m in RAW_SQL.finditer(code)]
    return found


def _key_kind(key: str) -> str:
    k = key.lower()
    for word, kind in (("pass", "PASSWORD"), ("pwd", "PASSWORD"), ("private", "PRIVATE_KEY"),
                       ("api", "API_KEY"), ("token", "TOKEN"), ("secret", "SECRET"),
                       ("conn", "CONN_STRING"), ("dsn", "CONN_STRING"), ("webhook", "WEBHOOK")):
        if word in k:
            return kind
    return "SECRET"


@lru_cache(maxsize=16)
def _key_patterns(extra: tuple[str, ...]) -> tuple[re.Pattern, ...]:
    """Assignment patterns, optionally extended with user keywords."""
    if not extra:
        return QUOTED_ASSIGN, QUOTED_PAIR, UNQUOTED_ASSIGN, XML_ELEM
    kw = KEYWORDS + "|" + "|".join(re.escape(e) for e in extra)
    key = rf"[\w.\-]*?(?:{kw})[\w.\-]*"
    return tuple(re.compile(rx.pattern.replace(KEY, key), rx.flags)
                 for rx in (QUOTED_ASSIGN, QUOTED_PAIR, UNQUOTED_ASSIGN, XML_ELEM))


def _literal_rx(lit: str) -> str:
    # word-boundary aware so "admin" doesn't hit inside "administrator"
    pre = r"(?<![\w])" if re.match(r"\w", lit[0]) else ""
    post = r"(?![\w])" if re.match(r"\w", lit[-1]) else ""
    return pre + re.escape(lit) + post


def detect(text: str, cfg=None, literals: Iterable[str] = ()) -> list[Finding]:
    """cfg: scrubber.config.Settings (defaults when None)."""
    if cfg is None:
        from .config import Settings
        cfg = Settings()
    on = cfg.enabled
    # text that is already a placeholder (re-redacting redacted output) must stay as-is
    prefix = re.sub(r"\W", "_", getattr(cfg, "placeholder_prefix", "") or "REDACTED") or "REDACTED"
    placeholder = re.compile(rf"(?:{re.escape(prefix)}|REDACTED)(?:_[A-Z0-9_]+?)?_\d{{2,8}}")
    found: list[Finding] = detect_queries(text, sql=on("sql_string"), graphql=on("graphql"), raw=on("raw_sql"))

    for kind, rx in PROVIDER_PATTERNS:
        if on(f"provider:{kind}"):
            found += [Finding(m.start(), m.end(), kind) for m in rx.finditer(text)]

    for det, rx, kind in (("url_cred", URL_CRED, "URL_PASSWORD"), ("auth_header", AUTH_HEADER, "AUTH_TOKEN"),
                          ("conn_str", CONN_STR, "PASSWORD")):
        if on(det):
            for m in rx.finditer(text):
                if _is_secret_value(m["val"], unquoted=True, key="X_KEY"):
                    found.append(Finding(m.start("val"), m.end("val"), kind))

    if on("key_assign"):
        qa, qp, ua, xe = _key_patterns(tuple(k for k in cfg.extra_keywords if k))
        for rx, unquoted in ((qa, False), (qp, False), (ua, True), (xe, False)):
            for m in rx.finditer(text):
                val = m["val"]
                if placeholder.fullmatch(m["key"]):
                    continue
                # structured values: let URL_CRED / CONN_STR / AUTH_HEADER hide only the secret part
                if re.match(r"(?i)(?:Bearer|Basic|Token)\s", val) or "://" in val or (";" in val and "=" in val):
                    continue
                if _is_secret_value(val, unquoted=unquoted, key=m["key"]):
                    found.append(Finding(m.start("val"), m.end("val"), _key_kind(m["key"])))

    if on("entropy"):
        rx = re.compile(r"(?P<q>[\"'`])(?P<val>[A-Za-z0-9+/=_\-.~:]{%d,})(?P=q)" % max(8, cfg.entropy_min_len))
        for m in rx.finditer(text):
            if _looks_random(m["val"], cfg.entropy_threshold):
                found.append(Finding(m.start("val"), m.end("val"), "HIGH_ENTROPY"))

    simple = (("email", EMAIL, "EMAIL"), ("mac", MAC, "MAC"), ("phone", PHONE, "PHONE"),
              ("ssn", US_SSN, "SSN"), ("iban", IBAN, "IBAN"))
    for det, rx, kind in simple:
        if on(det):
            found += [Finding(m.start(), m.end(), kind) for m in rx.finditer(text)]
    trivial = set(cfg.trivial_ips)
    if on("ipv4"):
        found += [Finding(m.start(), m.end(), "IP") for m in IPV4.finditer(text)
                  if m.group() not in trivial and not m.group().startswith("255.255.")]
    if on("ipv6"):
        found += [Finding(m.start(), m.end(), "IP") for m in IPV6.finditer(text) if m.group() != "::1"]
    if on("card"):
        for m in CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if 13 <= len(digits) <= 19 and _luhn_ok(digits) and len(set(digits)) > 1:
                found.append(Finding(m.start(), m.end(), "CARD"))
    if on("home_user"):
        for m in HOME_PATH.finditer(text):
            if m["val"].lower() not in GENERIC_USERS:
                found.append(Finding(m.start("val"), m.end("val"), "USERNAME"))

    for pat in cfg.custom_patterns:
        if not pat.get("enabled", True) or not pat.get("regex"):
            continue
        try:
            rx = re.compile(pat["regex"], re.M)
        except re.error:
            continue
        kind = re.sub(r"[^A-Z0-9]+", "_", (pat.get("kind") or "CUSTOM").upper()).strip("_") or "CUSTOM"
        for m in rx.finditer(text):
            g = "val" if "val" in rx.groupindex else 0
            if m.end(g) > m.start(g):
                found.append(Finding(m.start(g), m.end(g), kind))

    for lit in literals:
        if len(lit) >= 4:
            found += [Finding(m.start(), m.end(), "SECRET") for m in re.finditer(_literal_rx(lit), text)]

    allow = set(cfg.never_hide)
    found = [f for f in found if f.end - f.start >= cfg.min_secret_len and text[f.start:f.end] not in allow
             and not placeholder.fullmatch(text[f.start:f.end])]
    return merge(found)


def merge(findings: list[Finding]) -> list[Finding]:
    """Resolve overlaps: keep the longest span; on ties keep the first-detected kind."""
    order = sorted(enumerate(findings), key=lambda p: (-(p[1].end - p[1].start), p[0]))
    kept: list[Finding] = []
    for _, f in order:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def iter_values(text: str, findings: list[Finding]) -> Iterator[tuple[Finding, str]]:
    for f in findings:
        yield f, text[f.start:f.end]
