#!/usr/bin/env python3
"""secret-scrub GUI (Tkinter, stdlib only).

Tabs:
  Work          input / output editors, Redact / Restore / Scan, findings table
  Detection     every detector toggle, thresholds, identifier + placeholder options
  Custom rules  always-hide list, allowlist, extra key names, custom regex patterns
  Vault         browse / search / delete / export / import stored values
  Appearance    theme, font, wrap, highlight, auto-copy
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scrubber import Settings, Vault, redact, restore  # noqa: E402
from scrubber import clipboard as sysclip  # noqa: E402
from scrubber.config import GROUPS, IDENT_KINDS  # noqa: E402
from scrubber.detectors import PROVIDER_PATTERNS  # noqa: E402

PERSONAL_KINDS = {"EMAIL", "IP", "MAC", "PHONE", "CARD", "IBAN", "SSN", "USERNAME"}

THEMES = {
    "dark": dict(bg="#1e1f24", panel="#26282e", field="#17181c", fg="#e4e6eb", muted="#9aa0aa",
                 accent="#5b8def", accent_fg="#ffffff", border="#3a3d45", select="#34495e",
                 data="#ff7b72", ident="#79c0ff", query="#d2a8ff", found="#5a3a1a", cursor="#ffffff"),
    "light": dict(bg="#f4f5f7", panel="#ffffff", field="#ffffff", fg="#1f2328", muted="#5f6670",
                  accent="#2f6fdf", accent_fg="#ffffff", border="#d0d4da", select="#cfe0ff",
                  data="#c62828", ident="#0b5cad", query="#7b3fbf", found="#ffe2b0", cursor="#000000"),
}
MONO_CANDIDATES = ["DejaVu Sans Mono", "JetBrains Mono", "Fira Code", "Fira Mono", "Source Code Pro",
                   "Ubuntu Mono", "Noto Sans Mono", "Liberation Mono", "Hack", "Cascadia Code",
                   "Consolas", "Menlo", "Courier New", "Monospace", "TkFixedFont"]


def category(kind: str) -> str:
    if kind in IDENT_KINDS:
        return "Identifier"
    if kind == "QUERY":
        return "Query"
    if kind in PERSONAL_KINDS:
        return "Personal"
    return "Secret"


def mask(v: str) -> str:
    v = v.replace("\n", "⏎")
    if len(v) <= 6:
        return "•" * len(v)
    return f"{v[:2]}{'•' * min(len(v) - 4, 12)}{v[-2:]}"


# ---------------------------------------------------------------------------
class ScrollFrame(ttk.Frame):
    """Vertical scrollable container; put widgets in .inner"""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        for w in (self.canvas, self.inner):
            w.bind("<Enter>", self._bind_wheel)
            w.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _e):
        self.canvas.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(-int(e.delta / 120), "units"))
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-3, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(3, "units"))

    def _unbind_wheel(self, _e):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.unbind_all(seq)


class Editor(ttk.Frame):
    """Text widget with scrollbars, line count and title."""

    def __init__(self, master, title: str, app: "App"):
        super().__init__(master)
        self.app = app
        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text=title, style="Head.TLabel").pack(side="left", padx=(2, 8), pady=(0, 4))
        self.info = ttk.Label(head, text="", style="Muted.TLabel")
        self.info.pack(side="right", padx=4)
        body = ttk.Frame(self, style="Border.TFrame", padding=1)
        body.pack(fill="both", expand=True)
        self.text = tk.Text(body, undo=True, wrap="none", borderwidth=0, padx=8, pady=6, tabs="4c")
        ys = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        xs = ttk.Scrollbar(body, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.text.bind("<<Modified>>", self._modified)
        self.text.bind("<Button-3>", self._context)

    def get(self) -> str:
        return self.text.get("1.0", "end-1c")

    def set(self, s: str) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", s)
        self.text.edit_modified(True)

    def _modified(self, _e=None):
        if self.text.edit_modified():
            s = self.get()
            self.info.configure(text=f"{s.count(chr(10)) + (1 if s else 0)} lines · {len(s)} chars")
            self.text.edit_modified(False)

    def _context(self, e):
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Cut", command=lambda: self.text.event_generate("<<Cut>>"))
        m.add_command(label="Copy", command=lambda: self.text.event_generate("<<Copy>>"))
        m.add_command(label="Paste", command=lambda: self.text.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="Select all", command=lambda: self.text.tag_add("sel", "1.0", "end"))
        if self.text.tag_ranges("sel"):
            m.add_separator()
            m.add_command(label="Always hide selection", command=self._hide_selection)
            m.add_command(label="Never hide selection", command=self._allow_selection)
        m.tk_popup(e.x_root, e.y_root)

    def _hide_selection(self):
        sel = self.text.get("sel.first", "sel.last").strip()
        if sel:
            self.app.add_to_list("always_hide", sel)

    def _allow_selection(self):
        sel = self.text.get("sel.first", "sel.last").strip()
        if sel:
            self.app.add_to_list("never_hide", sel)


# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("secret-scrub")
        self.geometry("1280x820")
        self.minsize(900, 600)
        self.cfg = Settings.load()
        self._save_job = None
        self.vars: list[tk.Variable] = []   # keep references alive
        self.show_values = tk.BooleanVar(value=False)
        self.last_report: list = []
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self._build_toolbar()
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self._build_work_tab()
        self._build_detection_tab()
        self._build_custom_tab()
        self._build_vault_tab()
        self._build_appearance_tab()
        self._build_help_tab()
        self.status = ttk.Label(self, text="Ready.", style="Status.TLabel", anchor="w", padding=(10, 4))
        self.status.pack(fill="x", side="bottom")
        self._bind_keys()
        self.apply_theme()
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh_vault() if self.nb.index("current") == 3 else None)

    # ------------------------------------------------------------ helpers
    def bvar(self, getter, setter) -> tk.BooleanVar:
        v = tk.BooleanVar(value=bool(getter()))
        v.trace_add("write", lambda *_: (setter(v.get()), self.schedule_save()))
        self.vars.append(v)
        return v

    def nvar(self, getter, setter, cls=tk.IntVar):
        v = cls(value=getter())

        def on(*_):
            try:
                setter(v.get())
                self.schedule_save()
            except (tk.TclError, ValueError):
                pass
        v.trace_add("write", on)
        self.vars.append(v)
        return v

    def svar(self, getter, setter) -> tk.StringVar:
        v = tk.StringVar(value=getter())
        v.trace_add("write", lambda *_: (setter(v.get()), self.schedule_save()))
        self.vars.append(v)
        return v

    def schedule_save(self):
        if self._save_job:
            self.after_cancel(self._save_job)
        self._save_job = self.after(400, self._save_now)

    def _save_now(self):
        self._save_job = None
        try:
            self.cfg.save()
        except OSError as e:
            self.set_status(f"Could not save settings: {e}", error=True)

    def set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, style="StatusErr.TLabel" if error else "Status.TLabel")

    def vault(self) -> Vault:
        return Vault.from_settings(self.cfg)

    def section(self, parent, title: str, desc: str = "") -> ttk.Frame:
        lf = ttk.LabelFrame(parent, text=f"  {title}  ", padding=(12, 8))
        lf.pack(fill="x", padx=12, pady=8)
        if desc:
            ttk.Label(lf, text=desc, style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(0, 6))
        return lf

    # ------------------------------------------------------------ toolbar
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(10, 8))
        bar.pack(fill="x")
        ttk.Label(bar, text="secret-scrub", style="Title.TLabel").pack(side="left", padx=(0, 16))
        left = [("Redact  ▶", self.do_redact, "Accent.TButton"), ("◀  Restore", self.do_restore, "Accent.TButton"),
                ("Auto", self.do_auto, "TButton"), ("Scan", self.do_scan, "TButton")]
        right = [("Clear", self.clear), ("⇄", self.swap), ("Save…", self.save_output), ("Copy", self.copy_output),
                 ("Paste", self.paste_input), ("Open…", self.open_file)]
        for label, cmd, style in left:
            ttk.Button(bar, text=label, command=cmd, style=style).pack(side="left", padx=3)
        for label, cmd in right:
            ttk.Button(bar, text=label, command=cmd, style="Small.TButton").pack(side="right", padx=2)

    def _bind_keys(self):
        self.bind_all("<Control-Return>", lambda e: self.do_auto())
        self.bind_all("<Control-r>", lambda e: self.do_redact())
        self.bind_all("<Control-R>", lambda e: self.do_restore())
        self.bind_all("<Control-o>", lambda e: self.open_file())
        self.bind_all("<Control-s>", lambda e: self.save_output())
        self.bind_all("<Control-Shift-C>", lambda e: self.copy_output())
        self.bind_all("<F5>", lambda e: self.do_scan())

    # ------------------------------------------------------------ work tab
    def _build_work_tab(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Work  ")

        quick = ttk.Frame(tab)
        quick.pack(fill="x", pady=(0, 6))
        ttk.Label(quick, text="Quick:", style="Muted.TLabel").pack(side="left", padx=(0, 6))

        def group_var(keys):
            def get():
                return all(self.cfg.detectors.get(k, True) for k in keys)

            def set_(val):
                for k in keys:
                    self.cfg.detectors[k] = val
                self.sync_detection_vars()
            return self.bvar(get, set_)

        secret_keys = [k for k, _ in GROUPS["Credentials"] if k != "entropy"] + \
                      [f"provider:{k}" for k, _ in PROVIDER_PATTERNS]
        self.quick_vars = {
            "secrets": (group_var(secret_keys), "Secrets"),
            "entropy": (group_var(["entropy"]), "Random strings"),
            "pii": (group_var([k for k, _ in GROUPS["Personal data"]]), "Personal data"),
            "queries": (group_var([k for k, _ in GROUPS["Queries"]]), "Queries"),
            "names": (self.bvar(lambda: self.cfg.rename_identifiers,
                                lambda v: (setattr(self.cfg, "rename_identifiers", v), self.sync_detection_vars())),
                      "Rename identifiers"),
        }
        for v, label in self.quick_vars.values():
            ttk.Checkbutton(quick, text=label, variable=v).pack(side="left", padx=6)
        ttk.Checkbutton(quick, text="Show real values in table", variable=self.show_values,
                        command=self.fill_table).pack(side="right", padx=6)

        vpan = ttk.PanedWindow(tab, orient="vertical")
        vpan.pack(fill="both", expand=True)
        hpan = ttk.PanedWindow(vpan, orient="horizontal")
        self.inp = Editor(hpan, "Input  —  original code, or the AI's answer", self)
        self.out = Editor(hpan, "Output", self)
        hpan.add(self.inp, weight=1)
        hpan.add(self.out, weight=1)
        vpan.add(hpan, weight=4)

        tbl = ttk.Frame(vpan)
        vpan.add(tbl, weight=1)
        head = ttk.Frame(tbl)
        head.pack(fill="x", pady=(6, 4))
        ttk.Label(head, text="Findings", style="Head.TLabel").pack(side="left")
        ttk.Label(head, text="  right-click a row for options", style="Muted.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.fill_table())
        ttk.Entry(head, textvariable=self.filter_var, width=28).pack(side="right")
        ttk.Label(head, text="Filter:", style="Muted.TLabel").pack(side="right", padx=4)
        self.cat_var = tk.StringVar(value="All")
        cb = ttk.Combobox(head, textvariable=self.cat_var, state="readonly", width=12,
                          values=["All", "Secret", "Personal", "Query", "Identifier"])
        cb.pack(side="right", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self.fill_table())

        cols = ("placeholder", "category", "kind", "value")
        frame = ttk.Frame(tbl, style="Border.TFrame", padding=1)
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=7)
        for c, w in zip(cols, (260, 100, 140, 600)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, stretch=(c == "value"))
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<Button-3>", self._tree_menu)
        self.tree.bind("<Double-1>", lambda e: self._jump_to_selected())

    # ------------------------------------------------------------ actions
    def do_redact(self):
        src = self.inp.get()
        if not src.strip():
            self.set_status("Input is empty.", error=True)
            return
        try:
            v = self.vault()
            safe, report = redact(src, v, self.cfg)
            v.save()
        except Exception as e:  # show, don't crash the GUI
            messagebox.showerror("Redact failed", str(e))
            return
        self.out.set(safe)
        self.last_report = report
        self.fill_table()
        self.highlight_output(v)
        self.highlight_input_findings(src, report)
        counts = {}
        for f, _, _ in report:
            counts[category(f.kind)] = counts.get(category(f.kind), 0) + 1
        msg = "Redacted: " + (", ".join(f"{n} {c.lower()}" for c, n in counts.items()) or "nothing found")
        if self.cfg.auto_copy:
            self.copy_text(safe)
            msg += "  ·  output copied to clipboard"
        self.set_status(msg)

    def do_restore(self):
        src = self.inp.get()
        if not src.strip():
            self.set_status("Input is empty.", error=True)
            return
        v = self.vault()
        out, restored, unknown = restore(src, v)
        self.out.set(out)
        self.last_report = []
        self.fill_table()
        for t in ("ph_data", "ph_ident", "ph_query", "found", "ph_unknown"):
            self.out.text.tag_remove(t, "1.0", "end")
        self.highlight_placeholders(self.inp.text, v)
        msg = f"Restored {len(restored)} placeholder(s)."
        if unknown:
            msg += f"  ⚠ {len(set(unknown))} unknown: " + ", ".join(sorted(set(unknown))[:6])
        if self.cfg.auto_copy:
            self.copy_text(out)
            msg += "  ·  output copied to clipboard"
        self.set_status(msg, error=bool(unknown))

    def do_auto(self):
        v = self.vault()
        rx = v.restore_regex()
        if rx is not None and rx.search(self.inp.get()):
            self.do_restore()
        else:
            self.do_redact()

    def do_scan(self):
        src = self.inp.get()
        v = self.vault()  # in-memory only, never saved
        _, report = redact(src, v, self.cfg)
        self.last_report = report
        self.fill_table()
        self.highlight_input_findings(src, report)
        self.set_status(f"Scan: {len(report)} item(s) would be hidden/renamed (nothing changed, vault untouched).")

    def open_file(self):
        p = filedialog.askopenfilename(title="Open file")
        if p:
            try:
                self.inp.set(Path(p).read_text(encoding="utf-8"))
                self.set_status(f"Loaded {p}")
            except (OSError, UnicodeDecodeError) as e:
                messagebox.showerror("Open failed", str(e))

    def save_output(self):
        p = filedialog.asksaveasfilename(title="Save output")
        if p:
            Path(p).write_text(self.out.get(), encoding="utf-8")
            self.set_status(f"Saved {p}")

    def paste_input(self):
        txt = self.read_clip()
        if txt is not None:
            self.inp.set(txt)
            self.set_status("Pasted clipboard into input.")

    def copy_output(self):
        self.copy_text(self.out.get())
        self.set_status("Output copied to clipboard.")

    def swap(self):
        a, b = self.inp.get(), self.out.get()
        self.inp.set(b)
        self.out.set(a)

    def clear(self):
        self.inp.set("")
        self.out.set("")
        self.last_report = []
        self.fill_table()

    def copy_text(self, s: str):
        self.clipboard_clear()
        self.clipboard_append(s)
        try:  # persist after the app closes too, if a system tool exists
            sysclip.write(s)
        except BaseException:
            pass

    def read_clip(self):
        try:
            return self.clipboard_get()
        except tk.TclError:
            try:
                return sysclip.read()
            except BaseException:
                self.set_status("Clipboard is empty or unavailable.", error=True)
                return None

    # ------------------------------------------------------------ table + highlight
    def fill_table(self):
        self.tree.delete(*self.tree.get_children())
        flt = self.filter_var.get().lower()
        cat = self.cat_var.get()
        show = self.show_values.get()
        seen = set()
        for f, value, ph in self.last_report:
            if ph in seen:
                continue
            seen.add(ph)
            c = category(f.kind)
            shown = value if (show or c == "Identifier") else mask(value)
            shown = shown.replace("\n", "⏎")
            if cat != "All" and c != cat:
                continue
            if flt and flt not in f"{ph} {c} {f.kind} {shown}".lower():
                continue
            self.tree.insert("", "end", iid=ph, values=(ph, c, f.kind, shown[:300]))

    def _report_entry(self, ph):
        for f, value, p in self.last_report:
            if p == ph:
                return f, value
        return None, None

    def _tree_menu(self, e):
        row = self.tree.identify_row(e.y)
        if not row:
            return
        self.tree.selection_set(row)
        f, value = self._report_entry(row)
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Copy placeholder", command=lambda: self.copy_text(row))
        m.add_command(label="Copy real value", command=lambda: self.copy_text(value or ""))
        m.add_command(label="Find in output", command=self._jump_to_selected)
        m.add_separator()
        m.add_command(label="Never hide this value (allowlist) and re-run",
                      command=lambda: (self.add_to_list("never_hide", value), self.do_redact()))
        if f is not None and f.kind not in IDENT_KINDS:
            m.add_command(label=f"Disable detector for kind {f.kind}…", command=lambda: self._disable_kind(f.kind))
        m.tk_popup(e.x_root, e.y_root)

    def _disable_kind(self, kind):
        key = f"provider:{kind}"
        if key in self.cfg.detectors:
            self.cfg.detectors[key] = False
        else:
            mapping = {"EMAIL": "email", "IP": "ipv4", "MAC": "mac", "PHONE": "phone", "CARD": "card",
                       "IBAN": "iban", "SSN": "ssn", "USERNAME": "home_user", "QUERY": "sql_string",
                       "HIGH_ENTROPY": "entropy", "URL_PASSWORD": "url_cred", "AUTH_TOKEN": "auth_header"}
            k = mapping.get(kind, "key_assign")
            if not messagebox.askyesno("Disable detector", f"Disable detector '{k}'?"):
                return
            self.cfg.detectors[k] = False
        self.sync_detection_vars()
        self.schedule_save()
        self.do_redact()

    def _jump_to_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        t = self.out.text
        idx = t.search(sel[0], "1.0", "end")
        if idx:
            end = f"{idx}+{len(sel[0])}c"
            t.tag_remove("sel", "1.0", "end")
            t.tag_add("sel", idx, end)
            t.see(idx)
            t.focus_set()

    def highlight_placeholders(self, widget: tk.Text, v: Vault):
        for t in ("ph_data", "ph_ident", "ph_query", "ph_unknown"):
            widget.tag_remove(t, "1.0", "end")
        if not self.cfg.highlight:
            return
        text = widget.get("1.0", "end-1c")
        for m in v.unknown_regex().finditer(text):
            ph = m.group()
            if ph not in v.by_placeholder:
                tag = "ph_unknown"
            else:
                c = category(v.kind_of(ph))
                tag = {"Identifier": "ph_ident", "Query": "ph_query"}.get(c, "ph_data")
            widget.tag_add(tag, f"1.0+{m.start()}c", f"1.0+{m.end()}c")

    def highlight_output(self, v: Vault):
        self.highlight_placeholders(self.out.text, v)

    def highlight_input_findings(self, src: str, report):
        t = self.inp.text
        t.tag_remove("found", "1.0", "end")
        t.tag_remove("found_ident", "1.0", "end")
        if not self.cfg.highlight:
            return
        idents = []
        for f, value, _ in report:
            if f.start >= 0:
                t.tag_add("found", f"1.0+{f.start}c", f"1.0+{f.end}c")
            else:
                idents.append(value)
        if idents:
            rx = re.compile(r"(?<![\w$])(?:" + "|".join(map(re.escape, idents)) + r")(?!\w)")
            for m in rx.finditer(src):
                t.tag_add("found_ident", f"1.0+{m.start()}c", f"1.0+{m.end()}c")

    # ------------------------------------------------------------ detection tab
    def _build_detection_tab(self):
        sf = ScrollFrame(self.nb)
        self.nb.add(sf, text="  Detection  ")
        root = sf.inner
        self.det_vars: dict[str, tk.BooleanVar] = {}

        def det_check(parent, key, label, row=None, col=0):
            v = self.bvar(lambda: self.cfg.detectors.get(key, True),
                          lambda val, k=key: self.cfg.detectors.__setitem__(k, val))
            self.det_vars[key] = v
            cb = ttk.Checkbutton(parent, text=label, variable=v)
            if row is None:
                cb.pack(anchor="w", pady=1)
            else:
                cb.grid(row=row, column=col, sticky="w", padx=(0, 18), pady=1)
            return cb

        def all_none(parent, keys):
            f = ttk.Frame(parent)
            f.pack(anchor="w", pady=(0, 4))
            ttk.Button(f, text="All", width=6, command=lambda: self._set_many(keys, True)).pack(side="left")
            ttk.Button(f, text="None", width=6, command=lambda: self._set_many(keys, False)).pack(side="left", padx=4)

        # credentials
        sec = self.section(root, "Credentials", "Generic secret detection that works in any language or config format.")
        all_none(sec, [k for k, _ in GROUPS["Credentials"]])
        for k, label in GROUPS["Credentials"]:
            det_check(sec, k, label)
        g = ttk.Frame(sec)
        g.pack(anchor="w", pady=(8, 0))
        ttk.Label(g, text="Entropy threshold (higher = fewer, more random strings):").grid(row=0, column=0, sticky="w")
        ev = self.nvar(lambda: self.cfg.entropy_threshold, lambda x: setattr(self.cfg, "entropy_threshold", round(float(x), 2)), tk.DoubleVar)
        ttk.Scale(g, from_=2.5, to=6.0, variable=ev, length=220).grid(row=0, column=1, padx=8)
        ev_lbl = ttk.Label(g, text=f"{self.cfg.entropy_threshold:.2f}", width=5)
        ev_lbl.grid(row=0, column=2)
        ev.trace_add("write", lambda *_: ev_lbl.configure(text=f"{ev.get():.2f}"))
        ttk.Label(g, text="Min random-string length:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Spinbox(g, from_=8, to=200, width=6, textvariable=self.nvar(
            lambda: self.cfg.entropy_min_len, lambda x: setattr(self.cfg, "entropy_min_len", int(x)))).grid(row=1, column=1, sticky="w", padx=8)
        ttk.Label(g, text="Min length of any hidden value:").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(g, from_=1, to=50, width=6, textvariable=self.nvar(
            lambda: self.cfg.min_secret_len, lambda x: setattr(self.cfg, "min_secret_len", int(x)))).grid(row=2, column=1, sticky="w", padx=8)
        ttk.Checkbutton(sec, text="Also hide every value already stored in the vault (once hidden, always hidden)",
                        variable=self.bvar(lambda: self.cfg.reuse_vault_values,
                                           lambda x: setattr(self.cfg, "reuse_vault_values", x))).pack(anchor="w", pady=(8, 0))

        # providers
        prov = self.section(root, "Provider token formats", "Exact token formats of known services.")
        kinds = list(dict.fromkeys(k for k, _ in PROVIDER_PATTERNS))
        all_none(prov, [f"provider:{k}" for k in kinds])
        grid = ttk.Frame(prov)
        grid.pack(anchor="w")
        for i, k in enumerate(kinds):
            det_check(grid, f"provider:{k}", k.replace("_", " ").title(), row=i // 4, col=i % 4)

        # personal
        pii = self.section(root, "Personal & infrastructure data")
        all_none(pii, [k for k, _ in GROUPS["Personal data"]])
        for k, label in GROUPS["Personal data"]:
            det_check(pii, k, label)
        f = ttk.Frame(pii)
        f.pack(anchor="w", fill="x", pady=(6, 0))
        ttk.Label(f, text="IPs never hidden (comma separated):").pack(side="left")
        ttk.Entry(f, width=60, textvariable=self.svar(
            lambda: ", ".join(self.cfg.trivial_ips),
            lambda s: setattr(self.cfg, "trivial_ips", [x.strip() for x in s.split(",") if x.strip()]))).pack(side="left", padx=8)

        # queries
        q = self.section(root, "Queries", "Whole query becomes REDACTED_QUERY_0001. Turn off when the bug is inside the query.")
        for k, label in GROUPS["Queries"]:
            det_check(q, k, label)

        # identifiers
        idf = self.section(root, "Identifier renaming",
                           "Names declared in the code are renamed consistently. Keywords, builtins and imported library names stay readable.")
        self.ident_master = self.bvar(lambda: self.cfg.rename_identifiers,
                                      lambda x: setattr(self.cfg, "rename_identifiers", x))
        ttk.Checkbutton(idf, text="Rename identifiers", variable=self.ident_master).pack(anchor="w")
        kf = ttk.Frame(idf)
        kf.pack(anchor="w", padx=20, pady=4)
        labels = {"VAR": "Variables", "FUNC": "Functions / methods", "CLASS": "Classes / types",
                  "PARAM": "Parameters", "ATTR": "Attributes (self.x / this.x / @x)"}
        self.ident_vars = {}
        for i, k in enumerate(IDENT_KINDS):
            v = self.bvar(lambda k=k: self.cfg.ident_kinds.get(k, True),
                          lambda val, k=k: self.cfg.ident_kinds.__setitem__(k, val))
            self.ident_vars[k] = v
            ttk.Checkbutton(kf, text=labels[k], variable=v).grid(row=i // 3, column=i % 3, sticky="w", padx=(0, 18))
        ttk.Checkbutton(idf, text="Rename inside comments", variable=self.bvar(
            lambda: self.cfg.rename_in_comments, lambda x: setattr(self.cfg, "rename_in_comments", x))).pack(anchor="w")
        ttk.Checkbutton(idf, text="Rename inside string interpolation  f\"{x}\"  `${x}`  \"#{x}\"  \"$x\"", variable=self.bvar(
            lambda: self.cfg.rename_in_strings, lambda x: setattr(self.cfg, "rename_in_strings", x))).pack(anchor="w")
        mf = ttk.Frame(idf)
        mf.pack(anchor="w", pady=4)
        ttk.Label(mf, text="Minimum name length:").pack(side="left")
        ttk.Spinbox(mf, from_=1, to=20, width=5, textvariable=self.nvar(
            lambda: self.cfg.ident_min_len, lambda x: setattr(self.cfg, "ident_min_len", int(x)))).pack(side="left", padx=8)

        # placeholders
        ph = self.section(root, "Placeholders & vault")
        pf = ttk.Frame(ph)
        pf.pack(anchor="w")
        self.ph_preview = ttk.Label(pf, style="Mono.TLabel")

        def upd_preview(*_):
            mid = "_PASSWORD" if self.cfg.kind_in_placeholder else ""
            p = re.sub(r"\W", "_", self.cfg.placeholder_prefix) or "REDACTED"
            self.ph_preview.configure(text=f"Preview:  {p}{mid}_{7:0{max(2, min(int(self.cfg.placeholder_digits), 8))}d}")
        ttk.Label(pf, text="Prefix:").grid(row=0, column=0, sticky="w")
        pv = self.svar(lambda: self.cfg.placeholder_prefix, lambda s: setattr(self.cfg, "placeholder_prefix", s))
        pv.trace_add("write", upd_preview)
        ttk.Entry(pf, textvariable=pv, width=18).grid(row=0, column=1, padx=8, sticky="w")
        ttk.Label(pf, text="Digits:").grid(row=0, column=2, sticky="w")
        dv = self.nvar(lambda: self.cfg.placeholder_digits, lambda x: setattr(self.cfg, "placeholder_digits", int(x)))
        dv.trace_add("write", upd_preview)
        ttk.Spinbox(pf, from_=2, to=8, width=4, textvariable=dv).grid(row=0, column=3, padx=8)
        kv = self.bvar(lambda: self.cfg.kind_in_placeholder, lambda x: setattr(self.cfg, "kind_in_placeholder", x))
        kv.trace_add("write", upd_preview)
        ttk.Checkbutton(pf, text="Include kind in name (helps the AI understand)", variable=kv).grid(row=0, column=4, padx=8)
        self.ph_preview.grid(row=1, column=0, columnspan=5, sticky="w", pady=6)
        upd_preview()
        vf = ttk.Frame(ph)
        vf.pack(anchor="w", fill="x")
        ttk.Label(vf, text="Vault file:").pack(side="left")
        self.vault_path_var = self.svar(lambda: self.cfg.vault_path, lambda s: setattr(self.cfg, "vault_path", s))
        ttk.Entry(vf, textvariable=self.vault_path_var, width=60).pack(side="left", padx=8)
        ttk.Button(vf, text="Browse…", command=self._browse_vault).pack(side="left")

        bottom = ttk.Frame(root)
        bottom.pack(fill="x", padx=12, pady=12)
        ttk.Button(bottom, text="Reset all settings to defaults", command=self.reset_defaults).pack(side="left")
        ttk.Label(bottom, text="Settings save automatically.", style="Muted.TLabel").pack(side="left", padx=12)

    def _set_many(self, keys, val):
        for k in keys:
            self.cfg.detectors[k] = val
        self.sync_detection_vars()
        self.schedule_save()

    def sync_detection_vars(self):
        """Reflect cfg in all checkbox variables (after bulk changes)."""
        for k, v in getattr(self, "det_vars", {}).items():
            want = self.cfg.detectors.get(k, True)
            if v.get() != want:
                v.set(want)
        if hasattr(self, "ident_master") and self.ident_master.get() != self.cfg.rename_identifiers:
            self.ident_master.set(self.cfg.rename_identifiers)
        if hasattr(self, "quick_vars"):
            q = self.quick_vars
            vals = {
                "secrets": all(self.cfg.detectors.get(k, True) for k in
                               [k for k, _ in GROUPS["Credentials"] if k != "entropy"] + [f"provider:{k}" for k, _ in PROVIDER_PATTERNS]),
                "entropy": self.cfg.detectors.get("entropy", True),
                "pii": all(self.cfg.detectors.get(k, True) for k, _ in GROUPS["Personal data"]),
                "queries": all(self.cfg.detectors.get(k, True) for k, _ in GROUPS["Queries"]),
                "names": self.cfg.rename_identifiers,
            }
            for name, (var, _) in q.items():
                if var.get() != vals[name]:
                    # set without re-triggering bulk setters
                    info = var.trace_info()
                    for mode, cb in info:
                        var.trace_remove(mode, cb)
                    var.set(vals[name])
                    for mode, cb in info:
                        var.trace_add(mode, cb)

    def _browse_vault(self):
        p = filedialog.asksaveasfilename(title="Vault file", defaultextension=".json",
                                         initialfile=Path(self.cfg.vault_path).name,
                                         initialdir=str(Path(self.cfg.vault_path).expanduser().parent),
                                         confirmoverwrite=False)
        if p:
            self.vault_path_var.set(p)

    def reset_defaults(self):
        if not messagebox.askyesno("Reset", "Reset every setting (including custom rules and lists) to defaults?\n"
                                            "The vault is NOT touched."):
            return
        vault_path = self.cfg.vault_path
        self.cfg = Settings()
        self.cfg.vault_path = vault_path
        self.cfg.save()
        messagebox.showinfo("Reset", "Defaults restored. The window will reload.")
        self.destroy()
        main()

    # ------------------------------------------------------------ custom tab
    def _build_custom_tab(self):
        sf = ScrollFrame(self.nb)
        self.nb.add(sf, text="  Custom rules  ")
        root = sf.inner
        self.list_widgets: dict[str, tk.Text] = {}

        lists = [
            ("always_hide", "Always hide",
             "One per line. Exact text hidden everywhere: real names, company, internal domains, hostnames, project codenames…"),
            ("never_hide", "Never hide (allowlist)",
             "One per line. Values and identifier names that must stay visible, even if a detector flags them."),
            ("extra_keywords", "Extra sensitive key names",
             "One per line (regex allowed). Values assigned to keys containing these words are hidden, e.g. pin, iban, ssn, otp."),
        ]
        row = ttk.Frame(root)
        row.pack(fill="x", padx=6)
        for i, (attr, title, desc) in enumerate(lists):
            lf = ttk.LabelFrame(row, text=f"  {title}  ", padding=8)
            lf.grid(row=0, column=i, sticky="nsew", padx=6, pady=8)
            row.columnconfigure(i, weight=1)
            ttk.Label(lf, text=desc, style="Muted.TLabel", wraplength=330, justify="left").pack(anchor="w", pady=(0, 6))
            t = tk.Text(lf, height=12, width=36, undo=True, borderwidth=1, padx=6, pady=4)
            t.pack(fill="both", expand=True)
            t.insert("1.0", "\n".join(getattr(self.cfg, attr)))
            t.bind("<KeyRelease>", lambda e, a=attr, w=t: self._list_changed(a, w))
            t.bind("<<Paste>>", lambda e, a=attr, w=t: self.after(10, self._list_changed, a, w))
            self.list_widgets[attr] = t

        cp = self.section(root, "Custom regex patterns",
                          "Your own detectors. Use a named group (?P<val>...) to hide only part of the match; "
                          "otherwise the whole match is hidden. Kind becomes part of the placeholder.")
        frame = ttk.Frame(cp, style="Border.TFrame", padding=1)
        frame.pack(fill="x")
        cols = ("on", "name", "kind", "regex")
        self.pat_tree = ttk.Treeview(frame, columns=cols, show="headings", height=6)
        for c, w in zip(cols, (50, 180, 140, 600)):
            self.pat_tree.heading(c, text=c.capitalize())
            self.pat_tree.column(c, width=w, stretch=(c == "regex"))
        self.pat_tree.pack(fill="x")
        self.pat_tree.bind("<Double-1>", lambda e: self._edit_pattern())
        bf = ttk.Frame(cp)
        bf.pack(anchor="w", pady=6)
        ttk.Button(bf, text="Add…", command=lambda: self._edit_pattern(new=True)).pack(side="left")
        ttk.Button(bf, text="Edit…", command=self._edit_pattern).pack(side="left", padx=4)
        ttk.Button(bf, text="Enable / disable", command=self._toggle_pattern).pack(side="left")
        ttk.Button(bf, text="Delete", command=self._delete_pattern).pack(side="left", padx=4)
        self._fill_patterns()

    def add_to_list(self, attr: str, value: str):
        lst = getattr(self.cfg, attr)
        if value and value not in lst:
            lst.append(value)
            w = self.list_widgets.get(attr)
            if w is not None:
                w.delete("1.0", "end")
                w.insert("1.0", "\n".join(lst))
            self.schedule_save()
            self.set_status(f"Added to {attr.replace('_', ' ')}: {mask(value) if attr == 'always_hide' else value}")

    def _list_changed(self, attr, widget):
        lines = [l.strip() for l in widget.get("1.0", "end-1c").splitlines() if l.strip()]
        setattr(self.cfg, attr, lines)
        self.schedule_save()

    def _fill_patterns(self):
        self.pat_tree.delete(*self.pat_tree.get_children())
        for i, p in enumerate(self.cfg.custom_patterns):
            self.pat_tree.insert("", "end", iid=str(i), values=("✔" if p.get("enabled", True) else "✘",
                                                                 p.get("name", ""), p.get("kind", ""), p.get("regex", "")))

    def _selected_pattern(self):
        sel = self.pat_tree.selection()
        return int(sel[0]) if sel else None

    def _toggle_pattern(self):
        i = self._selected_pattern()
        if i is not None:
            p = self.cfg.custom_patterns[i]
            p["enabled"] = not p.get("enabled", True)
            self._fill_patterns()
            self.schedule_save()

    def _delete_pattern(self):
        i = self._selected_pattern()
        if i is not None and messagebox.askyesno("Delete", "Delete this pattern?"):
            del self.cfg.custom_patterns[i]
            self._fill_patterns()
            self.schedule_save()

    def _edit_pattern(self, new=False):
        i = None if new else self._selected_pattern()
        if not new and i is None:
            return
        p = dict(self.cfg.custom_patterns[i]) if i is not None else {"name": "", "kind": "CUSTOM", "regex": "", "enabled": True}
        d = tk.Toplevel(self)
        d.title("Custom pattern")
        d.transient(self)
        d.configure(bg=THEMES[self.cfg.theme]["bg"])
        fr = ttk.Frame(d, padding=14)
        fr.pack(fill="both", expand=True)
        name, kind, regex = tk.StringVar(value=p["name"]), tk.StringVar(value=p["kind"]), tk.StringVar(value=p["regex"])
        for r, (lbl, var, w) in enumerate((("Name", name, 30), ("Kind", kind, 20), ("Regex", regex, 70))):
            ttk.Label(fr, text=lbl).grid(row=r, column=0, sticky="w", pady=3)
            ttk.Entry(fr, textvariable=var, width=w, font=self.mono).grid(row=r, column=1, sticky="w", padx=8)
        ttk.Label(fr, text="Test text:").grid(row=3, column=0, sticky="nw", pady=(10, 0))
        test = tk.Text(fr, height=8, width=80, font=self.mono)
        test.grid(row=3, column=1, pady=(10, 0), padx=8)
        test.insert("1.0", self.inp.get()[:4000])
        self._style_text(test)
        result = ttk.Label(fr, text="", style="Muted.TLabel")
        result.grid(row=4, column=1, sticky="w", padx=8, pady=4)

        def run_test(*_):
            test.tag_remove("found", "1.0", "end")
            try:
                rx = re.compile(regex.get(), re.M)
            except re.error as e:
                result.configure(text=f"Invalid regex: {e}")
                return
            if not regex.get():
                result.configure(text="")
                return
            src = test.get("1.0", "end-1c")
            n = 0
            for m in rx.finditer(src):
                g = "val" if "val" in rx.groupindex else 0
                if m.end(g) > m.start(g):
                    test.tag_add("found", f"1.0+{m.start(g)}c", f"1.0+{m.end(g)}c")
                    n += 1
            result.configure(text=f"{n} match(es) highlighted")
        regex.trace_add("write", run_test)
        test.bind("<KeyRelease>", run_test)
        run_test()

        def ok():
            try:
                re.compile(regex.get())
            except re.error as e:
                messagebox.showerror("Invalid regex", str(e), parent=d)
                return
            if not regex.get().strip():
                return
            item = {"name": name.get() or kind.get(), "kind": kind.get() or "CUSTOM", "regex": regex.get(),
                    "enabled": p.get("enabled", True)}
            if i is None:
                self.cfg.custom_patterns.append(item)
            else:
                self.cfg.custom_patterns[i] = item
            self._fill_patterns()
            self.schedule_save()
            d.destroy()
        bf = ttk.Frame(fr)
        bf.grid(row=5, column=1, sticky="e", pady=(8, 0))
        ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="right", padx=4)
        ttk.Button(bf, text="Save", style="Accent.TButton", command=ok).pack(side="right")

    # ------------------------------------------------------------ vault tab
    def _build_vault_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Vault  ")
        warn = ttk.Label(tab, style="Warn.TLabel", wraplength=1100, justify="left",
                         text="The vault stores the real values in plaintext (file mode 600). It never leaves this "
                              "computer and is required to restore. Don't share it or paste it anywhere.")
        warn.pack(anchor="w", pady=(0, 8))
        top = ttk.Frame(tab)
        top.pack(fill="x")
        self.vault_label = ttk.Label(tab, text="", style="Muted.TLabel")
        self.vault_label.pack(anchor="w", before=top, pady=(0, 6))
        self.vault_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Show real values", variable=self.vault_show, command=self.refresh_vault).pack(side="right")
        self.vault_filter = tk.StringVar()
        self.vault_filter.trace_add("write", lambda *_: self.refresh_vault())
        ttk.Entry(top, textvariable=self.vault_filter, width=28).pack(side="right", padx=8)
        ttk.Label(top, text="Search:", style="Muted.TLabel").pack(side="right")
        self.vault_cat = tk.StringVar(value="All")
        cb = ttk.Combobox(top, textvariable=self.vault_cat, state="readonly", width=12,
                          values=["All", "Secret", "Personal", "Query", "Identifier"])
        cb.pack(side="right", padx=8)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_vault())

        frame = ttk.Frame(tab, style="Border.TFrame", padding=1)
        frame.pack(fill="both", expand=True, pady=8)
        cols = ("placeholder", "category", "kind", "value")
        self.vtree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (260, 100, 140, 700)):
            self.vtree.heading(c, text=c.capitalize())
            self.vtree.column(c, width=w, stretch=(c == "value"))
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.vtree.yview)
        self.vtree.configure(yscrollcommand=ys.set)
        self.vtree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")

        bf = ttk.Frame(tab)
        bf.pack(fill="x")
        for label, cmd in (("Refresh", self.refresh_vault), ("Copy placeholder", self._vault_copy_ph),
                           ("Copy value", self._vault_copy_val), ("Delete selected", self._vault_delete),
                           ("Export…", self._vault_export), ("Import / merge…", self._vault_import),
                           ("Open folder", self._vault_open_folder)):
            ttk.Button(bf, text=label, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Button(bf, text="Clear entire vault…", style="Danger.TButton", command=self._vault_clear).pack(side="right")

    def refresh_vault(self):
        v = self.vault()
        self.vtree.delete(*self.vtree.get_children())
        flt = self.vault_filter.get().lower()
        cat = self.vault_cat.get()
        show = self.vault_show.get()
        n = 0
        for ph, val in v.by_placeholder.items():
            k = v.kind_of(ph)
            c = category(k)
            shown = (val if show or c == "Identifier" else mask(val)).replace("\n", "⏎")
            if cat != "All" and c != cat:
                continue
            if flt and flt not in f"{ph} {c} {k} {shown}".lower():
                continue
            self.vtree.insert("", "end", iid=ph, values=(ph, c, k, shown[:400]))
            n += 1
        self.vault_label.configure(text=f"{v.path}   ·   {len(v.by_placeholder)} entries ({n} shown)")

    def _vault_copy_ph(self):
        sel = self.vtree.selection()
        if sel:
            self.copy_text("\n".join(sel))

    def _vault_copy_val(self):
        sel = self.vtree.selection()
        if sel:
            v = self.vault()
            self.copy_text("\n".join(v.by_placeholder.get(s, "") for s in sel))
            self.set_status("Real value(s) copied to clipboard.")

    def _vault_delete(self):
        sel = self.vtree.selection()
        if not sel:
            return
        if not messagebox.askyesno("Delete", f"Delete {len(sel)} entr{'y' if len(sel) == 1 else 'ies'}?\n"
                                             "Text containing these placeholders can no longer be restored."):
            return
        v = self.vault()
        for s in sel:
            v.remove(s)
        v.save()
        self.refresh_vault()

    def _vault_clear(self):
        v = self.vault()
        if messagebox.askyesno("Clear vault", f"Permanently delete all {len(v.by_placeholder)} stored values in\n{v.path}?\n\n"
                                              "Any redacted text you still have can NOT be restored afterwards.",
                               icon="warning"):
            v.path.unlink(missing_ok=True)
            self.refresh_vault()
            self.set_status("Vault cleared.")

    def _vault_export(self):
        if not messagebox.askyesno("Export", "The exported file contains the real values in plaintext. Continue?"):
            return
        p = filedialog.asksaveasfilename(title="Export vault", defaultextension=".json")
        if p:
            v = self.vault()
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"counter": v.counter, "secrets": v.by_placeholder, "kinds": v.kinds}, f, indent=2)
            self.set_status(f"Vault exported to {p}")

    def _vault_import(self):
        p = filedialog.askopenfilename(title="Import vault", filetypes=[("JSON", "*.json"), ("All", "*")])
        if not p:
            return
        try:
            other = Vault(Path(p))
        except (OSError, ValueError) as e:
            messagebox.showerror("Import failed", str(e))
            return
        v = self.vault()
        added = conflicts = 0
        for ph, val in other.by_placeholder.items():
            if ph in v.by_placeholder:
                conflicts += v.by_placeholder[ph] != val
                continue
            v.by_placeholder[ph] = val
            v.kinds[ph] = other.kind_of(ph)
            v.by_value.setdefault(val, ph)
            added += 1
        v.counter = max(v.counter, other.counter)
        v.save()
        self.refresh_vault()
        messagebox.showinfo("Import", f"Added {added} entries. Skipped {conflicts} conflicting placeholder(s).")

    def _vault_open_folder(self):
        folder = str(Path(self.cfg.vault_path).expanduser().parent)
        opener = "open" if sys.platform == "darwin" else ("explorer" if os.name == "nt" else "xdg-open")
        try:
            subprocess.Popen([opener, folder])
        except OSError:
            self.set_status(folder)

    # ------------------------------------------------------------ appearance
    def _build_appearance_tab(self):
        sf = ScrollFrame(self.nb)
        self.nb.add(sf, text="  Appearance  ")
        root = sf.inner
        s = self.section(root, "Theme & font")
        f = ttk.Frame(s)
        f.pack(anchor="w")
        ttk.Label(f, text="Theme:").grid(row=0, column=0, sticky="w", pady=4)
        tv = self.svar(lambda: self.cfg.theme, lambda x: setattr(self.cfg, "theme", x))
        tv.trace_add("write", lambda *_: self.apply_theme())
        for i, t in enumerate(THEMES):
            ttk.Radiobutton(f, text=t.title(), value=t, variable=tv).grid(row=0, column=1 + i, sticky="w", padx=6)
        families = set(tkfont.families(self))
        options = [m for m in MONO_CANDIDATES if m in families or m in ("Monospace", "TkFixedFont")]
        if self.cfg.font_family not in options:
            options.insert(0, self.cfg.font_family)
        ttk.Label(f, text="Editor font:").grid(row=1, column=0, sticky="w", pady=4)
        fv = self.svar(lambda: self.cfg.font_family, lambda x: setattr(self.cfg, "font_family", x))
        fv.trace_add("write", lambda *_: self.apply_font())
        ttk.Combobox(f, textvariable=fv, values=options, width=24).grid(row=1, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Label(f, text="Font size:").grid(row=2, column=0, sticky="w", pady=4)
        sv = self.nvar(lambda: self.cfg.font_size, lambda x: setattr(self.cfg, "font_size", int(x)))
        sv.trace_add("write", lambda *_: self.apply_font())
        ttk.Spinbox(f, from_=7, to=32, width=5, textvariable=sv).grid(row=2, column=1, sticky="w", padx=6)

        b = self.section(root, "Behaviour")
        wv = self.bvar(lambda: self.cfg.wrap, lambda x: setattr(self.cfg, "wrap", x))
        wv.trace_add("write", lambda *_: self.apply_font())
        ttk.Checkbutton(b, text="Wrap long lines in editors", variable=wv).pack(anchor="w")
        ttk.Checkbutton(b, text="Highlight hidden values and placeholders", variable=self.bvar(
            lambda: self.cfg.highlight, lambda x: setattr(self.cfg, "highlight", x))).pack(anchor="w")
        ttk.Checkbutton(b, text="Copy output to clipboard automatically after Redact / Restore", variable=self.bvar(
            lambda: self.cfg.auto_copy, lambda x: setattr(self.cfg, "auto_copy", x))).pack(anchor="w")
        lg = self.section(root, "Highlight legend")
        self.legend = []
        for tag, text in (("data", "Secret / personal data placeholder"), ("ident", "Renamed identifier"),
                          ("query", "Hidden query"), ("unknown", "Placeholder not found in vault"),
                          ("found", "Detected in input (Scan / Redact)")):
            l = tk.Label(lg, text=f"  {text}  ", anchor="w")
            l.pack(anchor="w", pady=2)
            self.legend.append((tag, l))

    def apply_font(self):
        try:
            self.mono = tkfont.Font(family=self.cfg.font_family, size=max(6, int(self.cfg.font_size)))
        except (tk.TclError, ValueError):
            return
        for ed in (self.inp, self.out):
            ed.text.configure(font=self.mono, wrap="word" if self.cfg.wrap else "none")
        for w in getattr(self, "list_widgets", {}).values():
            w.configure(font=self.mono)
        self.style.configure("Mono.TLabel", font=self.mono)
        rh = self.mono.metrics("linespace") + 8
        self.style.configure("Treeview", rowheight=max(22, rh))

    def _style_text(self, t: tk.Text):
        c = THEMES.get(self.cfg.theme, THEMES["dark"])
        t.configure(bg=c["field"], fg=c["fg"], insertbackground=c["cursor"], selectbackground=c["select"],
                    selectforeground=c["fg"], highlightthickness=0, relief="flat")
        t.tag_configure("ph_data", foreground=c["data"], font=(self.cfg.font_family, self.cfg.font_size, "bold"))
        t.tag_configure("ph_ident", foreground=c["ident"])
        t.tag_configure("ph_query", foreground=c["query"], font=(self.cfg.font_family, self.cfg.font_size, "bold"))
        t.tag_configure("ph_unknown", background=c["data"], foreground=c["bg"])
        t.tag_configure("found", background=c["found"])
        t.tag_configure("found_ident", underline=True, foreground=c["ident"])
        t.tag_raise("sel")

    def apply_theme(self):
        c = THEMES.get(self.cfg.theme, THEMES["dark"])
        st = self.style
        self.configure(bg=c["bg"])
        st.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field"],
                     bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                     troughcolor=c["panel"], focuscolor=c["accent"], selectbackground=c["select"],
                     selectforeground=c["fg"], insertcolor=c["fg"])
        st.configure("TFrame", background=c["bg"])
        st.configure("Border.TFrame", background=c["border"])
        st.configure("TLabel", background=c["bg"], foreground=c["fg"])
        st.configure("Muted.TLabel", foreground=c["muted"])
        st.configure("Head.TLabel", font=("TkDefaultFont", 10, "bold"))
        st.configure("Title.TLabel", font=("TkDefaultFont", 14, "bold"), foreground=c["accent"])
        st.configure("Warn.TLabel", foreground=c["data"])
        st.configure("Status.TLabel", background=c["panel"], foreground=c["muted"])
        st.configure("StatusErr.TLabel", background=c["panel"], foreground=c["data"])
        st.configure("TLabelframe", background=c["bg"], bordercolor=c["border"])
        st.configure("TLabelframe.Label", background=c["bg"], foreground=c["accent"], font=("TkDefaultFont", 10, "bold"))
        st.configure("TButton", background=c["panel"], foreground=c["fg"], padding=(10, 5), bordercolor=c["border"])
        st.map("TButton", background=[("active", c["select"]), ("pressed", c["select"])])
        st.configure("Small.TButton", padding=(8, 5), width=-4)
        st.configure("TButton", width=-6)
        st.configure("Accent.TButton", background=c["accent"], foreground=c["accent_fg"], bordercolor=c["accent"])
        st.map("Accent.TButton", background=[("active", c["ident"]), ("pressed", c["ident"])])
        st.configure("Danger.TButton", background=c["panel"], foreground=c["data"])
        st.configure("TCheckbutton", background=c["bg"], foreground=c["fg"], indicatorbackground=c["field"],
                     indicatorforeground=c["accent"])
        st.map("TCheckbutton", background=[("active", c["bg"])], indicatorbackground=[("selected", c["accent"])],
               indicatorforeground=[("selected", c["accent_fg"])])
        st.configure("TRadiobutton", background=c["bg"], foreground=c["fg"], indicatorbackground=c["field"])
        st.map("TRadiobutton", background=[("active", c["bg"])], indicatorbackground=[("selected", c["accent"])])
        st.configure("TNotebook", background=c["bg"], bordercolor=c["border"], tabmargins=(0, 4, 0, 0))
        st.configure("TNotebook.Tab", background=c["panel"], foreground=c["muted"], padding=(14, 6), bordercolor=c["border"])
        st.map("TNotebook.Tab", background=[("selected", c["bg"])], foreground=[("selected", c["fg"])])
        st.configure("Treeview", background=c["field"], fieldbackground=c["field"], foreground=c["fg"], bordercolor=c["border"])
        st.map("Treeview", background=[("selected", c["select"])], foreground=[("selected", c["fg"])])
        st.configure("Treeview.Heading", background=c["panel"], foreground=c["fg"], bordercolor=c["border"])
        st.map("Treeview.Heading", background=[("active", c["select"])])
        st.configure("TEntry", fieldbackground=c["field"], foreground=c["fg"], insertcolor=c["fg"])
        st.configure("TSpinbox", fieldbackground=c["field"], foreground=c["fg"], arrowcolor=c["fg"], background=c["panel"])
        st.configure("TCombobox", fieldbackground=c["field"], foreground=c["fg"], arrowcolor=c["fg"], background=c["panel"])
        st.map("TCombobox", fieldbackground=[("readonly", c["field"])], foreground=[("readonly", c["fg"])])
        self.option_add("*TCombobox*Listbox.background", c["field"])
        self.option_add("*TCombobox*Listbox.foreground", c["fg"])
        self.option_add("*Menu.background", c["panel"])
        self.option_add("*Menu.foreground", c["fg"])
        st.configure("TScrollbar", background=c["panel"], troughcolor=c["bg"], arrowcolor=c["muted"], bordercolor=c["bg"])
        st.configure("TPanedwindow", background=c["bg"])
        st.configure("TScale", background=c["bg"], troughcolor=c["panel"])
        st.configure("Mono.TLabel", foreground=c["ident"])
        self.apply_font()
        for ed in (self.inp, self.out):
            self._style_text(ed.text)
        for w in list(getattr(self, "list_widgets", {}).values()) + ([self.help_text] if hasattr(self, "help_text") else []):
            self._style_text(w)
        for frame in self.nb.winfo_children():
            if isinstance(frame, ScrollFrame):
                frame.canvas.configure(bg=c["bg"])
        for tag, lbl in getattr(self, "legend", []):
            if tag == "found":
                lbl.configure(bg=c["found"], fg=c["fg"])
            elif tag == "unknown":
                lbl.configure(bg=c["data"], fg=c["bg"])
            else:
                lbl.configure(bg=c["bg"], fg=c[tag], font=("TkDefaultFont", 10, "bold"))

    # ------------------------------------------------------------ help
    def _build_help_tab(self):
        tab = ttk.Frame(self.nb, padding=16)
        self.nb.add(tab, text="  Help  ")
        txt = (
            "WORKFLOW\n"
            "  1. Paste or open your code in Input  →  Redact (Ctrl+R).  Output is copied automatically.\n"
            "  2. Paste the safe output into Claude / any AI. Ask it to keep REDACTED_* placeholders unchanged.\n"
            "  3. Paste the AI's answer into Input  →  Restore (Ctrl+Shift+R).  Real values come back.\n"
            "  Auto (Ctrl+Enter) picks Redact or Restore depending on whether Input contains known placeholders.\n\n"
            "SHORTCUTS\n"
            "  Ctrl+Enter auto · Ctrl+R redact · Ctrl+Shift+R restore · F5 scan · Ctrl+O open · Ctrl+S save output\n"
            "  Ctrl+Shift+C copy output · right-click text: always/never hide selection · right-click finding: options\n\n"
            "TIPS\n"
            "  • Scan shows what would be hidden without touching the vault.\n"
            "  • Same value → same placeholder, across files and sessions, so multi-file context stays consistent.\n"
            "  • A secret under an ordinary name (x = \"hunter2\") is not detectable: add it to Always hide.\n"
            "  • Turn off Queries when the bug is inside the SQL itself.\n"
            "  • New names the AI invents are left untouched on restore.\n"
            "  • Settings are shared with the command-line tool (secret_scrub.py).\n"
        )
        t = tk.Text(tab, wrap="word", borderwidth=0, padx=8, pady=8)
        t.insert("1.0", txt)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True)
        self.help_text = t
        self.after(10, lambda: self._style_text(t))


def main():
    app = App()
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        app.inp.set(Path(sys.argv[1]).read_text(encoding="utf-8"))
    app.mainloop()


if __name__ == "__main__":
    main()
