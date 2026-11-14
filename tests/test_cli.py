"""End-to-end CLI tests (subprocess). Each test gets its own SECRET_SCRUB_HOME."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

SCRIPT = str(ROOT / "secret_scrub.py")
SECRETS = ["Vx7!kq2LmZ9w", "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "jane.doe@example.com", "10.20.30.40",
           "pgPa55word"]
SRC = f'''import requests
password = "{SECRETS[0]}"
GITHUB = "{SECRETS[1]}"
OWNER = "{SECRETS[2]}"  # contact
SERVER = "{SECRETS[3]}"
DB = "postgres://app:{SECRETS[4]}@db/prod"

def fetch_orders(customer_id, page_size=50):
    return requests.get(f"http://{{SERVER}}/orders/{{customer_id}}", params={{"n": page_size}})
'''


class CLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.env = dict(os.environ, SECRET_SCRUB_HOME=str(self.dir / "home"))
        (self.dir / "app.py").write_text(SRC)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, stdin=None, ok=(0,)):
        p = subprocess.run([sys.executable, SCRIPT, *args], input=stdin, capture_output=True, text=True,
                           env=self.env, cwd=self.dir, timeout=60)
        self.assertIn(p.returncode, ok, p.stderr)
        return p

    def test_redact_restore_file(self):
        p = self.run_cli("redact", "app.py", "-o", "safe.py")
        safe = (self.dir / "safe.py").read_text()
        for s in SECRETS + ["fetch_orders", "customer_id"]:
            self.assertNotIn(s, safe)
            self.assertNotIn(s, p.stdout)
            if s in SECRETS:
                self.assertNotIn(s, p.stderr, "report must mask values")
        self.run_cli("restore", "safe.py", "-o", "back.py")
        self.assertEqual((self.dir / "back.py").read_text(), SRC)
        vault = self.dir / "home" / "vault.json"
        self.assertEqual(oct(vault.stat().st_mode & 0o777), "0o600")

    def test_stdin_stdout(self):
        safe = self.run_cli("redact", "-", stdin=SRC).stdout
        for s in SECRETS:
            self.assertNotIn(s, safe)
        back = self.run_cli("restore", stdin=safe).stdout
        self.assertEqual(back, SRC)

    def test_restore_after_ai_edit(self):
        safe = self.run_cli("redact", "app.py").stdout
        lines = safe.splitlines(keepends=True)
        edited = "# AI: refactored\n" + "".join(reversed(lines[1:6])) + "".join(lines[6:]) + "\n"
        back = self.run_cli("restore", stdin=edited).stdout
        orig = SRC.splitlines(keepends=True)
        expected = "# AI: refactored\n" + "".join(reversed(orig[1:6])) + "".join(orig[6:]) + "\n"
        self.assertEqual(back, expected)

    def test_unknown_placeholder_warning(self):
        self.run_cli("redact", "app.py")
        p = self.run_cli("restore", stdin="x = REDACTED_VAR_9999\n")
        self.assertIn("WARNING", p.stderr)
        self.assertIn("REDACTED_VAR_9999", p.stderr)

    def test_scan_exit_codes_and_no_vault_write(self):
        self.run_cli("scan", "app.py", ok=(1,))
        self.assertFalse((self.dir / "home" / "vault.json").exists())
        (self.dir / "clean.txt").write_text("hello world\n")
        self.run_cli("scan", "clean.txt", "--keep-names", ok=(0,))

    def test_flags(self):
        out = self.run_cli("redact", "app.py", "--keep-names").stdout
        self.assertIn("fetch_orders", out)
        out = self.run_cli("redact", "app.py", "--no-pii", "--keep-names", "--vault", "fresh.json").stdout
        self.assertIn(SECRETS[2], out)
        self.assertNotIn(SECRETS[0], out)
        out = self.run_cli("redact", "-", "--hide", "requests", stdin="import requests\n").stdout
        self.assertNotIn("requests", out)
        out = self.run_cli("redact", "-", "--no-entropy", "--keep-names", stdin='x("aZ3kLm9QwErTy7UiOp2As")\n').stdout
        self.assertIn("aZ3kLm9QwErTy7UiOp2As", out)
        out = self.run_cli("redact", "-", "--keep-queries", "--keep-names",
                           stdin='q("SELECT a FROM b WHERE c")\n').stdout
        self.assertIn("SELECT a FROM b", out)

    def test_custom_vault_path(self):
        self.run_cli("redact", "app.py", "-o", "s.py", "--vault", "other.json")
        self.assertTrue((self.dir / "other.json").exists())
        p = self.run_cli("restore", "s.py", "--vault", "other.json")
        self.assertEqual(p.stdout, SRC)
        # default vault does not know these placeholders
        p = self.run_cli("restore", "s.py")
        self.assertIn("WARNING", p.stderr)

    def test_vault_list_masks_values(self):
        self.run_cli("redact", "app.py")
        p = self.run_cli("vault", "list")
        for s in SECRETS:
            self.assertNotIn(s, p.stdout)
        p = self.run_cli("vault", "list", "--show")
        self.assertIn(SECRETS[0], p.stdout)

    def test_vault_clear(self):
        self.run_cli("redact", "app.py")
        vault = self.dir / "home" / "vault.json"
        self.run_cli("vault", "clear", stdin="no\n")
        self.assertTrue(vault.exists())
        self.run_cli("vault", "clear", stdin="yes\n")
        self.assertFalse(vault.exists())

    def test_settings_file_respected(self):
        home = self.dir / "home"
        home.mkdir()
        (home / "settings.json").write_text(json.dumps({"placeholder_prefix": "HIDDEN", "rename_identifiers": False}))
        out = self.run_cli("redact", "app.py").stdout
        self.assertIn("HIDDEN_PASSWORD_", out)
        self.assertIn("fetch_orders", out)

    def test_legacy_always_hide_txt(self):
        home = self.dir / "home"
        home.mkdir()
        (home / "always_hide.txt").write_text("# comment\nProjectFalcon\n")
        out = self.run_cli("redact", "-", stdin="codename ProjectFalcon\n").stdout
        self.assertNotIn("ProjectFalcon", out)

    def test_many_runs_consistent(self):
        outs = {self.run_cli("redact", "app.py").stdout for _ in range(5)}
        self.assertEqual(len(outs), 1)

    def test_help(self):
        p = self.run_cli("--help")
        self.assertIn("redact", p.stdout)
        p = self.run_cli("redact", "--help")
        self.assertIn("--keep-names", p.stdout)


class GUISmokeTest(unittest.TestCase):
    """Builds the real Tk window (if a display exists) and drives redact/restore/scan without
    touching the clipboard or the user's settings."""

    @classmethod
    def setUpClass(cls):
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            raise unittest.SkipTest("no display")
        try:
            import tkinter
            tkinter.Tk().destroy()
        except Exception as e:  # noqa: BLE001
            raise unittest.SkipTest(f"tk unavailable: {e}")

    def test_gui_roundtrip(self):
        import gui
        from helpers import Settings
        with tempfile.TemporaryDirectory() as d:
            orig_load = Settings.load
            orig_save = Settings.save

            def fake_load(*a, **k):
                s = Settings()
                s.vault_path = str(Path(d) / "vault.json")
                s.auto_copy = False
                s.detectors["machine_ids"] = False
                return s
            Settings.load = classmethod(lambda cls, *a, **k: fake_load())
            Settings.save = lambda self, *a, **k: None
            try:
                app = gui.App()
                app.withdraw()
                app.inp.set(SRC)
                app.do_scan()
                self.assertFalse((Path(d) / "vault.json").exists(), "scan must not write the vault")
                self.assertTrue(app.last_report)
                app.do_redact()
                safe = app.out.get()
                for s in SECRETS:
                    self.assertNotIn(s, safe)
                app.inp.set(safe)
                app.do_auto()  # detects placeholders -> restore
                self.assertEqual(app.out.get().rstrip("\n"), SRC.rstrip("\n"))
                app.refresh_vault()
                for theme in ("light", "dark"):
                    app.cfg.theme = theme
                    app.apply_theme()
                app.update()
                app.destroy()
            finally:
                Settings.load = orig_load
                Settings.save = orig_save

    def test_helpers(self):
        import gui
        self.assertEqual(gui.category("VAR"), "Identifier")
        self.assertEqual(gui.category("QUERY"), "Query")
        self.assertEqual(gui.category("EMAIL"), "Personal")
        self.assertEqual(gui.category("AWS_KEY"), "Secret")
        self.assertNotIn("supersecretvalue", gui.mask("supersecretvalue"))


if __name__ == "__main__":
    unittest.main()
