"""Vault persistence/permissions, settings load/save, and every option's effect."""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path

from helpers import Settings, Vault, make_cfg, make_vault, redact, restore
from scrubber.detectors import PROVIDER_PATTERNS, detect

SRC = '''import os
password = "Vx7!kq2LmZ9w"
def send_report(report_id):
    # mail admin@corp.example about report_id
    return report_id
'''


class TestVault(unittest.TestCase):
    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(Path(d) / "sub")
            redact(SRC, v, make_cfg())
            v.save()
            self.assertEqual(stat.S_IMODE(os.stat(v.path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(v.path.parent).st_mode), 0o700)
            self.assertFalse(v.path.with_suffix(".tmp").exists())

    def test_same_value_same_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            a = v.placeholder_for("abc123", "SECRET")
            b = v.placeholder_for("abc123", "PASSWORD")
            c = v.placeholder_for("zzz999", "SECRET")
            self.assertEqual(a, b)
            self.assertNotEqual(a, c)

    def test_counter_survives_reload(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            for i in range(25):
                v.placeholder_for(f"value-{i}", "SECRET")
            v.save()
            v2 = make_vault(d)
            ph = v2.placeholder_for("brand-new", "SECRET")
            self.assertNotIn(ph, list(v.by_placeholder))
            self.assertEqual(len(set(v2.by_placeholder)), 26)

    def test_remove_and_known_values(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            p1 = v.placeholder_for("s3cret-val", "PASSWORD")
            v.placeholder_for("my_function", "FUNC")
            v.placeholder_for("SELECT 1 FROM x", "QUERY")
            self.assertEqual(v.known_values(), ["s3cret-val"])
            v.remove(p1)
            self.assertNotIn(p1, v.by_placeholder)
            self.assertNotEqual(v.placeholder_for("s3cret-val", "PASSWORD"), p1)

    def test_legacy_vault_without_kinds(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "vault.json"
            p.write_text(json.dumps({"counter": 2, "secrets": {"REDACTED_PASSWORD_0001": "pw1", "REDACTED_0002": "x"}}))
            v = Vault(p)
            self.assertEqual(v.kind_of("REDACTED_PASSWORD_0001"), "PASSWORD")
            self.assertEqual(restore("a=REDACTED_PASSWORD_0001;b=REDACTED_0002", v)[0], "a=pw1;b=x")

    def test_digit_width_overflow(self):
        """Counter past 10^digits still yields restorable placeholders."""
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            v.digits = 2
            vals = [f"secret-number-{i}" for i in range(250)]
            phs = [v.placeholder_for(x, "SECRET") for x in vals]
            text = " ".join(phs)
            self.assertEqual(restore(text, v)[0], " ".join(vals))

    def test_prefix_sanitised(self):
        with tempfile.TemporaryDirectory() as d:
            v = Vault(Path(d) / "v.json", prefix="my-prefix!", digits=99)
            self.assertEqual(v.prefix, "my_prefix_")
            self.assertEqual(v.digits, 8)

    def test_prefix_change_keeps_old_placeholders_restorable(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg()
            v = make_vault(d, cfg)
            safe1, _ = redact(SRC, v, cfg)
            v.save()
            cfg2 = make_cfg(placeholder_prefix="HIDE")
            v2 = make_vault(d, cfg2)
            safe2, _ = redact('token = "Nn4!pq8ZzLx2"\n', v2, cfg2)
            v2.save()
            v3 = make_vault(d, cfg2)
            self.assertEqual(restore(safe1, v3)[0], SRC)
            self.assertEqual(restore(safe2, v3)[0], 'token = "Nn4!pq8ZzLx2"\n')

    def test_unknown_with_custom_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(placeholder_prefix="HIDE")
            v = make_vault(d, cfg)
            redact(SRC, v, cfg)
            _, _, unknown = restore("x = HIDE_VAR_7777", v)
            self.assertEqual(unknown, ["HIDE_VAR_7777"])

    def test_scan_does_not_persist(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            redact(SRC, v, make_cfg())   # no save()
            self.assertFalse(v.path.exists())


class TestSettings(unittest.TestCase):
    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            s = Settings()
            s.entropy_threshold = 3.3
            s.always_hide = ["Foo Corp"]
            s.detectors["email"] = False
            s.custom_patterns = [{"name": "t", "kind": "TICKET", "regex": r"TCK-\d+", "enabled": True}]
            s.save(p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            s2 = Settings.load(p)
            self.assertEqual(s2.entropy_threshold, 3.3)
            self.assertEqual(s2.always_hide, ["Foo Corp"])
            self.assertFalse(s2.detectors["email"])
            self.assertTrue(s2.detectors["ipv4"])
            self.assertEqual(s2.custom_patterns[0]["kind"], "TICKET")

    def test_corrupt_settings_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            p.write_text("{not json")
            self.assertEqual(Settings.load(p).entropy_threshold, Settings().entropy_threshold)

    def test_unknown_keys_ignored_and_new_detectors_default_on(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            p.write_text(json.dumps({"bogus": 1, "detectors": {"email": False}}))
            s = Settings.load(p)
            self.assertFalse(hasattr(s, "bogus"))
            self.assertTrue(all(s.detectors[f"provider:{k}"] for k, _ in PROVIDER_PATTERNS))


KIND_OF = {"email": "EMAIL", "ipv4": "IP", "ipv6": "IP", "mac": "MAC", "phone": "PHONE", "card": "CARD",
           "iban": "IBAN", "ssn": "SSN", "home_user": "USERNAME", "url_cred": "URL_PASSWORD",
           "auth_header": "AUTH_TOKEN", "conn_str": "PASSWORD", "key_assign": "PASSWORD",
           "entropy": "HIGH_ENTROPY", "sql_string": "QUERY", "graphql": "QUERY", "raw_sql": "QUERY"}


class TestOptions(unittest.TestCase):
    def run_cfg(self, src, **over):
        d = tempfile.mkdtemp()
        cfg = make_cfg(**over)
        v = make_vault(d, cfg)
        safe, report = redact(src, v, cfg)
        self.assertEqual(restore(safe, v)[0], src)
        return safe, report

    def test_each_detector_toggle(self):
        cases = {
            "email": "x jane@example.com y\n", "ipv4": "x 10.2.3.4 y\n", "ipv6": "h 2001:db8::7 y\n",
            "mac": "m 00:1A:2B:3C:4D:5E\n", "phone": "+1 415 555 0132\n", "card": "4111 1111 1111 1111\n",
            "iban": "DE89370400440532013000\n", "ssn": "123-45-6789\n", "home_user": "/home/janedoe/x\n",
            "url_cred": "postgres://u:Pw9xq2@h/db\n", "auth_header": "Authorization: Bearer abcdefghijklmnop123\n",
            "conn_str": "Server=x;Password=Qw3rty99;\n", "key_assign": 'password = "hunter22"\n',
            "entropy": 'x("aZ3kLm9QwErTy7UiOp2As")\n', "sql_string": 'q("SELECT a FROM b WHERE c")\n',
            "graphql": 'q("query { user { name } }")\n', "raw_sql": "SELECT a FROM bbb;\n",
        }
        for det, src in cases.items():
            with self.subTest(det=det):
                on, rep_on = self.run_cfg(src, rename_identifiers=False)
                self.assertNotEqual(on, src, f"{det} found nothing when enabled")
                cfg_off = make_cfg(rename_identifiers=False)
                cfg_off.detectors[det] = False
                v = make_vault(tempfile.mkdtemp(), cfg_off)
                off, rep_off = redact(src, v, cfg_off)
                self.assertEqual(restore(off, v)[0], src)
                self.assertNotIn(KIND_OF[det], [f.kind for f, _, _ in rep_off], f"{det} still active when off")

    def test_provider_toggle(self):
        src = "AKIAABCDEFGHIJKLMNOP\n"
        cfg = make_cfg()
        cfg.detectors["provider:AWS_KEY"] = False
        cfg.detectors["entropy"] = False
        v = make_vault(tempfile.mkdtemp(), cfg)
        self.assertNotIn("AWS_KEY", redact(src, v, cfg)[0])

    def test_never_hide_value_and_identifier(self):
        src = 'password = "public-demo-pass1"\ndef keep_this_name(arg_one):\n    return arg_one\n'
        safe, _ = self.run_cfg(src, never_hide=["public-demo-pass1", "keep_this_name"])
        self.assertIn("public-demo-pass1", safe)
        self.assertIn("keep_this_name", safe)
        self.assertNotIn("arg_one", safe)

    def test_custom_pattern_with_and_without_group(self):
        src = "ticket TCK-12345 and order ORD:9981\n"
        safe, rep = self.run_cfg(src, custom_patterns=[
            {"name": "t", "kind": "ticket id", "regex": r"TCK-\d+", "enabled": True},
            {"name": "o", "kind": "ORDER", "regex": r"ORD:(?P<val>\d+)", "enabled": True},
            {"name": "bad", "kind": "X", "regex": r"([unclosed", "enabled": True},
            {"name": "off", "kind": "OFF", "regex": r"ticket", "enabled": False},
        ], rename_identifiers=False)
        self.assertNotIn("TCK-12345", safe)
        self.assertIn("REDACTED_TICKET_ID_", safe)
        self.assertIn("ORD:REDACTED_ORDER_", safe)
        self.assertIn("ticket", safe)

    def test_custom_pattern_followed_by_digit(self):
        """Regression: a placeholder directly followed by a digit used to be unrestorable."""
        src = "codeABC7 codeABC77 xABC1\n"
        safe, _ = self.run_cfg(src, custom_patterns=[{"name": "a", "kind": "A", "regex": r"ABC", "enabled": True}],
                               rename_identifiers=False)
        self.assertNotIn("ABC", safe)

    def test_custom_pattern_empty_match_ignored(self):
        safe, _ = self.run_cfg("abc\n", custom_patterns=[{"name": "e", "kind": "E", "regex": r"x*", "enabled": True}])
        self.assertEqual(safe, "abc\n")

    def test_entropy_threshold(self):
        src = 'x = Thing("abcdefghijABCDEFGHIJ12")\n'
        low, _ = self.run_cfg(src, entropy_threshold=1.0, rename_identifiers=False)
        high, _ = self.run_cfg(src, entropy_threshold=7.9, rename_identifiers=False)
        self.assertNotIn("abcdefghijABCDEFGHIJ12", low)
        self.assertIn("abcdefghijABCDEFGHIJ12", high)

    def test_min_secret_len(self):
        src = 'password = "abc"\n'
        safe, _ = self.run_cfg(src, min_secret_len=10, rename_identifiers=False)
        self.assertIn('"abc"', safe)

    def test_ident_kinds_subset(self):
        src = "class Widget:\n    def spin_it(self, speed_val):\n        total_x = speed_val\n        return total_x\n"
        safe, _ = self.run_cfg(src, ident_kinds={"VAR": False, "FUNC": True, "CLASS": False, "PARAM": False, "ATTR": False})
        self.assertIn("Widget", safe)
        self.assertNotIn("spin_it", safe)
        self.assertIn("speed_val", safe)
        self.assertIn("total_x", safe)

    def test_rename_in_comments_off(self):
        src = "def compute_tax(amount):\n    # compute_tax uses amount\n    return amount\n"
        safe, _ = self.run_cfg(src, rename_in_comments=False)
        self.assertIn("# compute_tax uses amount", safe)
        safe, _ = self.run_cfg(src)
        self.assertNotIn("compute_tax", safe)

    def test_trivial_ips_kept(self):
        safe, _ = self.run_cfg("bind 127.0.0.1 and 0.0.0.0 dns 8.8.8.8\n")
        self.assertIn("127.0.0.1", safe)
        self.assertIn("8.8.8.8", safe)

    def test_reuse_vault_values_off(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(reuse_vault_values=False, rename_identifiers=False)
            v = make_vault(d, cfg)
            redact('password = "Tr0ub4dor&3x"\n', v, cfg)
            safe, _ = redact("print('Tr0ub4dor&3x')\n", v, cfg)
            self.assertIn("Tr0ub4dor&3x", safe)

    def test_machine_ids(self):
        import getpass
        import socket
        cfg = make_cfg()
        cfg.detectors["machine_ids"] = True
        user, host = getpass.getuser(), socket.gethostname()
        src = f"owner={user} host={host}\n"
        v = make_vault(tempfile.mkdtemp(), cfg)
        safe, _ = redact(src, v, cfg)
        for x in (user, host):
            if len(x) >= 4 and x.lower() not in {"root", "localhost", "user"}:
                self.assertNotIn(x, safe)
        self.assertEqual(restore(safe, v)[0], src)


class TestRegressions(unittest.TestCase):
    def test_typed_assignments(self):
        for src in ('const sessionSecret: string = "b7Gq9Lw2Zr4T";\n', 'private apiKey: string | null = "b7Gq9Lw2Zr4T";\n',
                    'var apiKey string = "b7Gq9Lw2Zr4T"\n', 'val authToken: String = "b7Gq9Lw2Zr4T"\n',
                    'let password: &str = "b7Gq9Lw2Zr4T";\n', "let api_key: &'static str = \"b7Gq9Lw2Zr4T\";\n"):
            with self.subTest(src=src):
                d = tempfile.mkdtemp()
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                self.assertNotIn("b7Gq9Lw2Zr4T", safe)
                self.assertEqual(restore(safe, v)[0], src)

    def test_url_empty_user(self):
        src = "REDIS_URL=redis://:r3disPw@cache.local:6379/0\n"
        v = make_vault(tempfile.mkdtemp())
        safe, _ = redact(src, v, make_cfg())
        self.assertNotIn("r3disPw", safe)
        self.assertEqual(restore(safe, v)[0], src)

    def test_adjacent_findings(self):
        src = "SELECT * FROM t WHERE x = 1;jane@example.com\n10.1.2.3jane@example.com"
        v = make_vault(tempfile.mkdtemp())
        safe, _ = redact(src, v, make_cfg())
        self.assertEqual(restore(safe, v)[0], src)

    def test_double_redaction_restores_fully(self):
        src = 'path = "/home/janedoe/x"\n{"client_secret": "8fJ2kLq9ZxW4mN7p",\n "contacts": []}\n'
        v = make_vault(tempfile.mkdtemp())
        once, _ = redact(src, v, make_cfg())
        twice, _ = redact(once, v, make_cfg())
        self.assertEqual(once, twice)
        self.assertEqual(restore(twice, v)[0], src)

    def test_nested_placeholder_value_restores(self):
        v = make_vault(tempfile.mkdtemp())
        inner = v.placeholder_for("realpw", "PASSWORD")
        outer = v.placeholder_for(f"SELECT {inner} FROM t", "QUERY")
        self.assertEqual(restore(outer, v)[0], "SELECT realpw FROM t")

    def test_tokens_ending_in_dash_or_underscore(self):
        toks = ["123456789:AA" + "b" * 32 + "-", "sk-ant-api03-" + "Xy9" * 8 + "-", "glpat-" + "aB3" * 7 + "_",
                "sk-proj-" + "Zq8" * 8 + "-", "eyJhbGciOiJI.eyJzdWIiOiIx.abcdefghij-"]
        for tok in toks:
            for ctx in ("# {}\n", "{}", "x = {} + 1\n"):
                src = ctx.format(tok)
                with self.subTest(src=src):
                    v = make_vault(tempfile.mkdtemp())
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(tok, safe)
                    self.assertEqual(restore(safe, v)[0], src)


if __name__ == "__main__":
    unittest.main()
