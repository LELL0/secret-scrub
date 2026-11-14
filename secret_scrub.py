#!/usr/bin/env python3
"""secret-scrub - hide credentials, personal data, names and queries before pasting code
into an AI, then put the real values back into the AI's answer.

  redact   code -> safe code with REDACTED_<KIND>_0001 placeholders (originals saved in local vault)
  restore  AI answer with placeholders -> code with the real values back
  scan     list what would be hidden, change nothing
  vault    list / clear stored values
  gui      open the graphical interface (also: run with no arguments)

Input:  a file path, '-' for stdin, --clip for the clipboard.
Output: stdout, -o FILE, or --clip (copy result to clipboard).
Defaults come from ~/.secret_scrub/settings.json (edit via the GUI); flags override them.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scrubber import Settings, Vault, redact, restore  # noqa: E402
from scrubber import clipboard  # noqa: E402


def eprint(*a):
    print(*a, file=sys.stderr)


def mask(v: str) -> str:
    v = v.replace("\n", "\\n")
    if len(v) <= 6:
        return "*" * len(v)
    return f"{v[:2]}{'*' * min(len(v) - 4, 12)}{v[-2:]}"


def read_input(args) -> str:
    if args.clip:
        return clipboard.read()
    if args.input and args.input != "-":
        return Path(args.input).read_text(encoding="utf-8")
    if sys.stdin.isatty():
        eprint("Paste text, then press Ctrl-D on an empty line:")
    return sys.stdin.read()


def write_output(args, text: str) -> None:
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        eprint(f"-> written to {args.output}")
    elif args.clip or args.to_clip:
        clipboard.write(text)
        eprint("-> copied to clipboard")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def settings_from(args) -> Settings:
    cfg = Settings.load()
    if args.vault:
        cfg.vault_path = args.vault
    if args.no_pii:
        for k in ("email", "ipv4", "ipv6", "mac", "phone", "card", "iban", "ssn", "home_user", "machine_ids"):
            cfg.detectors[k] = False
    if args.no_entropy:
        cfg.detectors["entropy"] = False
    if args.keep_queries:
        for k in ("sql_string", "graphql", "raw_sql"):
            cfg.detectors[k] = False
    if args.keep_names:
        cfg.rename_identifiers = False
    if args.entropy_threshold is not None:
        cfg.entropy_threshold = args.entropy_threshold
    cfg.always_hide += args.hide or []
    return cfg


def print_report(report) -> None:
    data = [r for r in report if r[0].start >= 0]
    idents = [r for r in report if r[0].start < 0]
    eprint(f"Hidden {len(data)} sensitive item(s), renamed {len(idents)} identifier(s):")
    for f, value, ph in data:
        shown = mask(value) if f.kind != "QUERY" else mask(" ".join(value.split()[:3]))
        eprint(f"  {ph:<32} {f.kind:<16} {shown}")
    if idents:
        eprint("  identifiers: " + ", ".join(f"{n}->{ph}" for _, n, ph in idents))


def cmd_redact(args) -> None:
    cfg = settings_from(args)
    vault = Vault.from_settings(cfg)
    safe, report = redact(read_input(args), vault, cfg)
    vault.save()
    print_report(report)
    write_output(args, safe)


def cmd_scan(args) -> None:
    cfg = settings_from(args)
    vault = Vault.from_settings(cfg)  # read-only: not saved
    _, report = redact(read_input(args), vault, cfg)
    print_report(report)
    sys.exit(1 if report else 0)


def cmd_restore(args) -> None:
    cfg = settings_from(args)
    out, restored, unknown = restore(read_input(args), Vault.from_settings(cfg))
    eprint(f"Restored {len(restored)} placeholder(s).")
    if unknown:
        eprint(f"WARNING: {len(set(unknown))} placeholder(s) not in vault: " + ", ".join(sorted(set(unknown))))
    write_output(args, out)


def cmd_vault(args) -> None:
    cfg = Settings.load()
    if args.vault:
        cfg.vault_path = args.vault
    vault = Vault.from_settings(cfg)
    if args.vault_action == "list":
        for ph, v in vault.by_placeholder.items():
            print(f"{ph:<32} {vault.kind_of(ph):<14} {v if args.show else mask(v)}")
        eprint(f"{len(vault.by_placeholder)} entries in {vault.path}")
    elif input(f"Delete all {len(vault.by_placeholder)} stored values in {vault.path}? "
               "Already-redacted text can no longer be restored. Type 'yes': ") == "yes":
        vault.path.unlink(missing_ok=True)
        eprint("Vault cleared.")


def cmd_gui(_args=None) -> None:
    from gui import main as gui_main
    gui_main()


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("input", nargs="?", help="file path, or '-' for stdin")
    common.add_argument("-o", "--output", help="write result to file instead of stdout")
    common.add_argument("-c", "--clip", action="store_true", help="read from AND write to clipboard")
    common.add_argument("--to-clip", action="store_true", help="write result to clipboard")
    common.add_argument("--vault", help="vault file (default from settings)")
    common.add_argument("--hide", action="append", metavar="TEXT", help="extra literal to hide (repeatable)")
    common.add_argument("--no-pii", action="store_true", help="don't hide personal data")
    common.add_argument("--no-entropy", action="store_true", help="don't hide random-looking strings")
    common.add_argument("--keep-names", action="store_true", help="don't rename variables/functions/classes")
    common.add_argument("--keep-queries", action="store_true", help="don't hide SQL/GraphQL queries")
    common.add_argument("--entropy-threshold", type=float)

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("redact", parents=[common], help="hide sensitive data").set_defaults(fn=cmd_redact)
    sub.add_parser("restore", parents=[common], help="put real values back").set_defaults(fn=cmd_restore)
    sub.add_parser("scan", parents=[common], help="report only").set_defaults(fn=cmd_scan)
    v = sub.add_parser("vault", help="list/clear stored values")
    v.add_argument("vault_action", choices=["list", "clear"])
    v.add_argument("--show", action="store_true", help="print real values (careful)")
    v.add_argument("--vault")
    v.set_defaults(fn=cmd_vault)
    sub.add_parser("gui", help="open the GUI").set_defaults(fn=cmd_gui)
    return p


def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        cmd_gui()
        return
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    args.fn(args)


if __name__ == "__main__":
    main()
