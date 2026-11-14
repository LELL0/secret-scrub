"""Tiny language-agnostic lexer: splits text into code / string / comment segments.

Good enough for Python, JS/TS, Java, C/C++/C#, Go, Rust, PHP, Ruby, Kotlin, Swift,
shell, SQL, YAML/.env. Not a real parser - it only needs to know where strings and
comments are so identifiers and queries can be found reliably.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PY_LIKE = re.compile(r"(?m)^[ \t]*(?:def \w+\(|from [\w.]+ import |import [\w.]+\s*$|elif |class \w+.*:\s*$)"
                     r"|\A#!.*\b(?:python|bash|sh|zsh|ruby|perl)\b")


@dataclass
class Seg:
    kind: str          # "code" | "string" | "comment"
    start: int         # whole segment incl. quotes / comment markers
    end: int
    cstart: int = 0    # string content span (without quotes)
    cend: int = 0
    prefix: str = ""   # string prefix like f, r, b, $, @


def lex(text: str) -> list[Seg]:
    hash_comments_anywhere = bool(PY_LIKE.search(text))
    segs: list[Seg] = []
    n, i, code_start = len(text), 0, 0

    def flush(upto: int):
        if upto > code_start:
            segs.append(Seg("code", code_start, upto))

    while i < n:
        c = text[i]
        prev = text[i - 1] if i else "\n"
        nxt = text[i + 1] if i + 1 < n else ""

        # ---- comments -------------------------------------------------
        end = None
        if c == "#" and (hash_comments_anywhere or ((prev in " \t\n;") and (nxt in " \t\n!#" or nxt == ""))):
            end = text.find("\n", i)
        elif c == "/" and nxt == "/" and not hash_comments_anywhere and prev != ":":
            end = text.find("\n", i)
        elif c == "/" and nxt == "*" and not hash_comments_anywhere:
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
        elif c == "-" and nxt == "-" and prev in " \t\n" and text[i + 2:i + 3] in (" ", "\n", ""):
            end = text.find("\n", i)
        elif text.startswith("<!--", i):
            j = text.find("-->", i + 4)
            end = n if j == -1 else j + 3
        if end is not None:
            end = n if end == -1 else end
            flush(i)
            segs.append(Seg("comment", i, end))
            i = code_start = end
            continue

        # ---- strings --------------------------------------------------
        if c in "\"'`":
            triple = text[i:i + 3] if text[i:i + 3] in ('"""', "'''") else None
            if triple:
                j = text.find(triple, i + 3)
                close = n if j == -1 else j + 3
                cstart, cend = i + 3, (n if j == -1 else j)
            else:
                multiline = c == "`"
                j, close = i + 1, None
                while j < n:
                    ch = text[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == c:
                        close = j + 1
                        break
                    if ch == "\n" and not multiline:
                        break
                    j += 1
                if close is None:          # unmatched quote (apostrophe, lifetime...) -> code
                    i += 1
                    continue
                cstart, cend = i + 1, close - 1
            # string prefix (f"", r'', b"", $"", @"")
            p = i
            while p > code_start and text[p - 1] in "fFrRbBuU$@" and i - p < 2:
                p -= 1
            if p > 0 and (text[p - 1].isalnum() or text[p - 1] == "_"):
                p = i  # letters belong to an identifier, not a prefix
            flush(p)
            segs.append(Seg("string", p, close, cstart, cend, text[p:i]))
            i = code_start = close
            continue
        i += 1
    flush(n)
    return segs


def blank_non_code(text: str, segs: list[Seg]) -> str:
    """Same length as text; strings/comments replaced by spaces (newlines kept) so offsets match."""
    out = list(text)
    for s in segs:
        if s.kind != "code":
            for k in range(s.start, s.end):
                if out[k] != "\n":
                    out[k] = " "
    return "".join(out)
