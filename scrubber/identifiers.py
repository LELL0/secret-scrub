"""Rename user-defined identifiers (variables, functions, classes, params, attributes)
to placeholders like REDACTED_FUNC_0003.

Only names *declared in the given text* are renamed. Language keywords, builtins and
anything imported from libraries stay readable, so the AI still understands the code.
Renaming is consistent: code, comments and string interpolations ({name}, ${name},
#{name}, $name) all get the same placeholder.
"""
from __future__ import annotations

import re

from .lexer import Seg, blank_non_code, lex

KEYWORDS = set("""
abstract and as assert async await auto base begin bool boolean break byte case catch char chan class const
constexpr continue crate debugger declare def default defer del delete do double dyn elif else elsif end ensure
enum except explicit export extends extern false final finally float fn for foreach from func function get global
go goto if impl implements import in inline instanceof int interface internal is lambda let long loop match mod
module mut namespace native new nil none None nonlocal not null object of operator or out override package pass
private protected pub public raise readonly record ref register rescue return sealed select self Self set short
signed sizeof static struct super switch synchronized template then this throw throws trait transient True False
true try type typedef typename typeof uint union unless unsafe unsigned until use using val var virtual void
volatile when where while with yield echo print_r isset unset empty require require_once include include_once
fun data companion lateinit inner open sealed vararg tailrec suspend reified crossinline noinline init deinit
guard protocol extension fileprivate inout associatedtype subscript dim redim sub byval byref local my our sub
undef last next redo elseif fi esac done then foreach endforeach endif endwhile
string str bytes list dict tuple bool float int object any never unknown number bigint symbol i8 i16 i32 i64
u8 u16 u32 u64 usize isize f32 f64 rune error Error uint8 uint16 uint32 uint64 int8 int16 int32 int64 float32
float64 complex64 complex128 byte decimal var dynamic
""".split())

BUILTINS = set("""
print len range open input map filter zip sum min max abs round sorted reversed enumerate isinstance issubclass
hasattr getattr setattr delattr type id hash repr format iter next super property staticmethod classmethod
Exception ValueError TypeError KeyError IndexError RuntimeError OSError IOError StopIteration NotImplemented
args kwargs cls main __init__ __main__ __name__ __file__ __dict__
console window document require module exports process global globalThis Math JSON Object Array String Number
Boolean Promise Date RegExp Map Set WeakMap Symbol Error fetch setTimeout setInterval clearTimeout parseInt
parseFloat undefined NaN Infinity constructor prototype arguments React useState useEffect props state render
System Console Math Integer List ArrayList HashMap Map Set String StringBuilder Override Exception Thread
fmt std os io sys re json time math err ctx log errors http strings strconv println printf sprintf
puts p require_relative attr_accessor attr_reader attr_writer initialize
echo exit die count array_push strlen
SELECT FROM WHERE
""".split())

IMPORT_LINE = re.compile(r"(?m)^[ \t]*(?:import|from|using|use|package|extern\s+crate|#\s*include|require|"
                         r"require_once|include|library|load)\b.*$")
REQUIRE_ASSIGN = re.compile(r"(?:\b(?:const|let|var)\s+)?(?P<lhs>\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?"
                            r"(?:require|import|__import__|importlib\.import_module)\s*\(")
IDENT = r"[A-Za-z_][\w]*"

# ---- declaration patterns (run on code with strings/comments blanked) -------------
FUNC_KW = re.compile(rf"\b(?:def|function|func|fn|fun|sub|proc|procedure)\s*\*?\s+(?:\([^)]*\)\s*)?(?P<name>{IDENT})\s*(?:<[^>]*>)?\s*\((?P<params>[^()]*(?:\([^()]*\)[^()]*)*)\)")
FUNC_ASSIGN = re.compile(rf"(?<![\w$.])(?P<name>{IDENT})\s*[:=]\s*(?:async\s+)?(?:function\b[^(]*\((?P<params>[^()]*)\)|\((?P<params2>[^()]*)\)\s*(?::\s*[\w<>\[\]|, ]+)?\s*=>|(?P<p3>{IDENT})\s*=>)")
METHOD_C = re.compile(rf"(?m)^[ \t]*(?:(?:public|private|protected|internal|static|final|virtual|override|abstract|async|inline|extern|synchronized|unsafe|const|export|default|get|set|readonly)\s+)*"
                      rf"(?:(?P<type>[\w.]+(?:<[^<>;()]*(?:<[^<>;()]*>[^<>;()]*)*>)?(?:\[\])*[*&?]*)\s+)?(?P<name>{IDENT})\s*\((?P<params>[^;{{}}]*?)\)\s*(?:const\s*)?(?:throws\s+[\w., ]+)?(?::\s*[\w<>\[\]|?, ]+)?\s*\{{")
CLASS_KW = re.compile(rf"\b(?:class|struct|interface|enum|trait|record|union|protocol|typedef\s+struct)\s+(?P<name>{IDENT})"
                      rf"|(?m:^[ \t]*(?:export\s+)?type\s+(?P<name2>{IDENT})\s*(?:<[^>]*>)?\s*(?:=|struct|interface|\w))")
VAR_KW = re.compile(rf"\b(?:let|const|var|val|my|our|local|auto|dim|global|nonlocal|static|lateinit\s+var)\s+(?:mut\s+)?(?P<names>{IDENT}(?:\s*,\s*{IDENT})*)")
DESTRUCT = re.compile(r"\b(?:let|const|var|val)\s*(?P<body>[{\[][^=;]*?[}\]])\s*=")
ASSIGN = re.compile(rf"(?<![\w$.>:])\$?(?P<name>{IDENT})\s*(?:[-+*/%&|^]|\*\*|//|<<|>>|\?\?|\|\||&&)?=(?![=>~])")
MULTI_ASSIGN = re.compile(rf"(?m)^[ \t]*(?P<names>{IDENT}(?:\s*,\s*{IDENT})+)\s*(?::=|=)(?!=)")
TYPED_DECL = re.compile(rf"(?<![\w.])(?P<type>[A-Za-z_][\w.]*(?:<[^<>;()=]*(?:<[^<>;()=]*>)?[^<>;()=]*>)?(?:\[\])*)[ \t]*[*&]*[ \t]+[*&]*(?P<name>{IDENT})(?=\s*(?:=(?!=)|;|,|\)|:\s*\w|\[))")
FOR_VARS = re.compile(rf"\bfor\s*\(?\s*(?:(?:let|const|var|my|auto|val)\s+)?(?P<names>{IDENT}(?:\s*,\s*{IDENT})*)\s+(?:in|of)\b")
AS_VAR = re.compile(rf"\b(?:except|with)\b[^\n:]*?\bas\s+(?P<name>{IDENT})")
ATTR = re.compile(rf"(?:\b(?:self|this|cls)\s*(?:\.|->)|@)(?P<name>{IDENT})\s*(?:[-+*/]?=(?!=))")
ARROW = re.compile(rf"(?:\((?P<params>[^()]*)\)|(?<![\w$.])(?P<one>{IDENT}))\s*(?::\s*[\w<>\[\]|, ]+)?\s*=>")
LAMBDA = re.compile(rf"\blambda\s+(?P<params>[^:]*):|\|(?P<rs>[\w\s,:&]*)\|\s*[\w{{(]|\bdo\s*\|(?P<rb>[^|]*)\||\{{\s*\|(?P<rb2>[^|]*)\|")
DEF_OWNER = "\0def"
# TS/Java/C#/PHP class members with access modifiers:  private cache: Map = {};  public $name;
MEMBER_DECL = re.compile(rf"(?m)^[ \t]*(?:(?:public|private|protected|readonly|static|declare|override|var)\s+)+\$?(?P<name>{IDENT})\s*[?!]?\s*(?=[:=;])")
GO_SHORT = re.compile(rf"(?P<names>{IDENT}(?:\s*,\s*{IDENT})*)\s*:=")

KIND_PRIORITY = {"CLASS": 0, "FUNC": 1, "ATTR": 2, "VAR": 3, "PARAM": 4}


def _param_names(params: str, name_first: bool) -> list[str]:
    out = []
    depth, cur, parts = 0, "", []
    for ch in params:  # split on top-level commas only
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    for p in parts:
        p = p.split("=", 1)[0]
        p = re.sub(r"@\w+(?:\([^)]*\))?", " ", p)            # Java annotations
        p = p.replace("...", " ").strip(" \t\n*&$")
        if not p:
            continue
        if ":" in p:                                           # python/ts/rust/kotlin/swift: name: Type
            words = re.findall(IDENT, p.split(":")[0])
            if words:
                out.append(words[-1])
            continue
        words = [w for w in re.findall(IDENT, p) if w not in ("mut", "ref", "out", "in", "final", "const", "readonly", "public", "private", "protected")]
        if words:
            out.append(words[0] if name_first else words[-1])
    return out


def collect(code: str, min_len: int = 2, protect: "re.Pattern | None" = None) -> tuple[dict[str, str], set[str]]:
    """Return ({name: kind}, external_names) from blanked code."""
    names: dict[str, str] = {}
    external: set[str] = set()

    for m in IMPORT_LINE.finditer(code):
        external.update(re.findall(IDENT, m.group()))
    for m in REQUIRE_ASSIGN.finditer(code):
        external.update(re.findall(IDENT, m["lhs"]))

    def add(name: str, kind: str):
        if (not name or len(name) < max(1, min_len) or name in KEYWORDS or name in BUILTINS
                or name.startswith("REDACTED_") or (protect is not None and protect.fullmatch(name))
                or (name.startswith("__") and name.endswith("__")) or name == "_" or name.isdigit()):
            return
        old = names.get(name)
        if old is None or KIND_PRIORITY[kind] < KIND_PRIORITY[old]:
            names[name] = kind

    for m in CLASS_KW.finditer(code):
        add(m["name"] or m["name2"], "CLASS")
    for m in FUNC_KW.finditer(code):
        add(m["name"], "FUNC")
        go = code[m.start():m.start() + 4] == "func"
        for p in _param_names(m["params"], name_first=go or ":" in m["params"]):
            add(p, "PARAM")
    for m in FUNC_ASSIGN.finditer(code):
        add(m["name"], "FUNC")
        params = m["params"] or m["params2"] or m["p3"] or ""
        for p in _param_names(params, name_first=True):
            add(p, "PARAM")
    for m in METHOD_C.finditer(code):
        if m["name"] in KEYWORDS or (m["type"] and m["type"] in ("return", "new", "else", "throw", "case", "await", "yield", "delete", "typeof", "in", "is", "not", "and", "or")):
            continue
        add(m["name"], "FUNC")
        for p in _param_names(m["params"], name_first=":" in m["params"]):
            add(p, "PARAM")
    for m in ARROW.finditer(code):
        for p in ([m["one"]] if m["one"] else _param_names(m["params"], name_first=True)):
            add(p, "PARAM")
    for m in LAMBDA.finditer(code):
        params = m["params"] or m["rs"] or m["rb"] or m["rb2"] or ""
        for p in _param_names(params, name_first=True):
            add(p, "PARAM")
    for m in VAR_KW.finditer(code):
        for n in re.findall(IDENT, m["names"]):
            add(n, "VAR")
    for m in DESTRUCT.finditer(code):
        body = m["body"]
        # { a, b: alias, c = 1 } -> a, alias, c   (property names before ':' belong to the source object)
        for part in body.strip("{}[] ").split(","):
            part = part.split("=")[0]
            part = part.split(":")[-1]
            for n in re.findall(IDENT, part)[-1:]:
                add(n, "VAR")
    for m in FOR_VARS.finditer(code):
        for n in re.findall(IDENT, m["names"]):
            add(n, "VAR")
    for m in AS_VAR.finditer(code):
        add(m["name"], "VAR")
    for m in ATTR.finditer(code):
        add(m["name"], "ATTR")
    for m in MEMBER_DECL.finditer(code):
        add(m["name"], "ATTR")
    for m in GO_SHORT.finditer(code):
        for n in re.findall(IDENT, m["names"]):
            add(n, "VAR")
    for m in MULTI_ASSIGN.finditer(code):
        for n in re.findall(IDENT, m["names"]):
            add(n, "VAR")

    depth = _paren_depth(code)
    for m in ASSIGN.finditer(code):
        if depth[m.start("name")] == 0:            # skip keyword arguments f(timeout=5)
            add(m["name"], "VAR")
    for m in TYPED_DECL.finditer(code):
        t = m["type"]
        if t in KEYWORDS - {"int", "long", "short", "char", "float", "double", "bool", "boolean", "byte", "string",
                            "str", "var", "auto", "const", "uint", "void", "dynamic", "decimal"}:
            continue
        if t in BUILTINS and t not in ("String", "List", "Map", "Set", "Integer", "Object", "ArrayList", "HashMap"):
            continue
        add(m["name"], "VAR")

    for e in external:
        names.pop(e, None)
    return names, external


def _paren_depth(code: str) -> list[int]:
    depth, d = [0] * (len(code) + 1), 0
    for i, ch in enumerate(code):
        depth[i] = d
        if ch == "(":
            d += 1
        elif ch == ")":
            d = max(0, d - 1)
    depth[len(code)] = d
    return depth


def _callee_map(code: str) -> list[str | None]:
    """For every position: identifier that owns the innermost open '(' (or None)."""
    owners: list[str | None] = [None] * (len(code) + 1)
    stack: list[str | None] = []
    for i, ch in enumerate(code):
        owners[i] = stack[-1] if stack else None
        if ch == "(" and i + 1 < len(code):
            before = code[max(0, i - 80):i]
            if re.search(rf"\b(?:def|function|func|fn|fun|sub)\s+{IDENT}\s*(?:<[^>]*>)?\s*$", before):
                stack.append(DEF_OWNER)        # parameter list of a definition: defaults are ours
                continue
            m = re.search(rf"({IDENT})\s*$", before)
            stack.append(m.group(1) if m else None)
        elif ch == ")" and stack:
            stack.pop()
    return owners


TOKEN = re.compile(rf"(?<![\w$])(?P<dollar>\$?)(?P<name>{IDENT})")
MEMBER_BEFORE = re.compile(rf"(?P<obj>{IDENT}|\)|\]|@)?\s*(?:\.|->|::|\?\.)\s*$")


def rename(text: str, placeholder_for, *, kinds=None, min_len: int = 2, comments: bool = True,
           strings: bool = True, exclude=frozenset(), protect=None) -> tuple[str, list[tuple[str, str, str]]]:
    """placeholder_for(name, kind) -> placeholder. Returns (new_text, [(kind, name, placeholder)])."""
    segs = lex(text)
    code = blank_non_code(text, segs)
    names, _ = collect(code, min_len=min_len, protect=protect)
    names = {n: k for n, k in names.items() if (kinds is None or k in kinds) and n not in exclude}
    if not names:
        return text, []
    mapping = {n: placeholder_for(n, k) for n, k in names.items()}
    callee = _callee_map(code)
    word_rx = re.compile(r"(?<![\w$])(" + "|".join(sorted(map(re.escape, mapping), key=len, reverse=True)) + r")(?![\w])")

    def rename_code(seg: Seg) -> str:
        chunk = text[seg.start:seg.end]
        out, last = [], 0
        for m in TOKEN.finditer(chunk):
            name = m["name"]
            if name not in mapping:
                continue
            abs_pos = seg.start + m.start()
            before = text[max(0, abs_pos - 120):abs_pos]
            mem = MEMBER_BEFORE.search(before)
            if mem:  # obj.name  -> only rename when obj is ours (self/this/user var/class)
                obj = mem["obj"]
                if obj not in ("self", "this", "cls", "@", "Self") and obj not in mapping:
                    continue
            after = text[seg.start + m.end():seg.start + m.end() + 3]
            if re.match(r"\s*=(?!=)", after) and code[abs_pos - 1:abs_pos] != "." and callee[abs_pos]:
                owner = callee[abs_pos]  # keyword argument: rename only for our own functions
                if owner not in mapping and owner != DEF_OWNER:
                    continue
            out.append(chunk[last:m.start("name")])
            out.append(mapping[name])
            last = m.end("name")
        out.append(chunk[last:])
        return "".join(out)

    def rename_string(seg: Seg) -> str:
        s = text[seg.start:seg.end]
        interp = (seg.prefix.lower().count("f") > 0 or "$" in seg.prefix or text[seg.cstart - 1:seg.cstart] == "`")

        def sub_expr(m):
            return word_rx.sub(lambda w: mapping[w.group(1)], m.group())
        s = re.sub(r"\$\{[^}]*\}|#\{[^}]*\}", sub_expr, s)                       # ${x}  #{x}
        s = re.sub(r"\$(" + IDENT + r")", lambda m: "$" + mapping.get(m.group(1), m.group(1)), s)  # "$x"
        if interp:
            s = re.sub(r"(?<!\$)\{[^{}]*\}", sub_expr, s)                             # f"{x}"  $"{x}"
        return s

    pieces = []
    for seg in segs:
        if seg.kind == "code":
            pieces.append(rename_code(seg))
        elif seg.kind == "string":
            pieces.append(rename_string(seg) if strings else text[seg.start:seg.end])
        elif not comments:
            pieces.append(text[seg.start:seg.end])
        else:
            pieces.append(word_rx.sub(lambda w: mapping[w.group(1)], text[seg.start:seg.end]))
    report = [(names[n], n, ph) for n, ph in mapping.items()]
    return "".join(pieces), report
