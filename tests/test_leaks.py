"""No-leak tests: every planted secret / PII value must be absent from the redacted text,
and restore() must give back the original byte-for-byte."""
from __future__ import annotations

import os
import random
import string
import tempfile
import unittest

from helpers import luhn_number, make_cfg, make_vault, rand_str, redact, restore, strong_secret

RNG = random.Random(1337)
HEX = "0123456789abcdef"
UP_DIG = string.ascii_uppercase + string.digits
B64U = string.ascii_letters + string.digits + "_-"


def provider_tokens(rng: random.Random) -> list[tuple[str, str]]:
    a = string.ascii_letters + string.digits
    return [
        ("AWS_KEY", "AKIA" + rand_str(rng, 16, UP_DIG)),
        ("AWS_KEY", "ASIA" + rand_str(rng, 16, UP_DIG)),
        ("GITHUB_TOKEN", "ghp_" + rand_str(rng, 36, a)),
        ("GITHUB_TOKEN", "gho_" + rand_str(rng, 36, a)),
        ("GITHUB_TOKEN", "github_pat_" + rand_str(rng, 40, a + "_")),
        ("GITLAB_TOKEN", "glpat-" + rand_str(rng, 20, B64U)),
        ("SLACK_TOKEN", "xoxb-" + rand_str(rng, 12, string.digits) + "-" + rand_str(rng, 24, a)),
        ("SLACK_WEBHOOK", "https://hooks.slack.com/services/T" + rand_str(rng, 8, UP_DIG) + "/B" + rand_str(rng, 8, UP_DIG) + "/" + rand_str(rng, 24, a)),
        ("DISCORD_WEBHOOK", "https://discord.com/api/webhooks/" + rand_str(rng, 18, string.digits) + "/" + rand_str(rng, 60, B64U)),
        ("STRIPE_KEY", "sk_live_" + rand_str(rng, 24, a)),
        ("STRIPE_KEY", "pk_test_" + rand_str(rng, 24, a)),
        ("GOOGLE_API_KEY", "AIza" + rand_str(rng, 35, B64U)),
        ("GOOGLE_OAUTH", "GOCSPX-" + rand_str(rng, 28, B64U)),
        ("GOOGLE_OAUTH", "ya29." + rand_str(rng, 40, B64U)),
        ("ANTHROPIC_KEY", "sk-ant-api03-" + rand_str(rng, 40, B64U)),
        ("OPENAI_KEY", "sk-proj-" + rand_str(rng, 40, a)),
        ("OPENAI_KEY", "sk-" + rand_str(rng, 48, a)),
        ("HUGGINGFACE_TOKEN", "hf_" + rand_str(rng, 34, a)),
        ("NPM_TOKEN", "npm_" + rand_str(rng, 36, a)),
        ("PYPI_TOKEN", "pypi-" + rand_str(rng, 60, B64U)),
        ("SENDGRID_KEY", "SG." + rand_str(rng, 22, a) + "." + rand_str(rng, 43, a)),
        ("TWILIO_KEY", "SK" + rand_str(rng, 32, HEX)),
        ("MAILGUN_KEY", "key-" + rand_str(rng, 32, a)),
        ("TELEGRAM_TOKEN", rand_str(rng, 9, string.digits) + ":AA" + rand_str(rng, 33, B64U)),
        ("SHOPIFY_TOKEN", "shpat_" + rand_str(rng, 32, HEX)),
        ("DIGITALOCEAN_TOKEN", "dop_v1_" + rand_str(rng, 64, HEX)),
        ("JWT", "eyJ" + rand_str(rng, 20, a) + ".eyJ" + rand_str(rng, 30, a) + "." + rand_str(rng, 43, B64U)),
    ]


# contexts where a provider token may appear; {t} = token
TOKEN_CONTEXTS = [
    "{t}",
    "x = \"{t}\"\n",
    "client({t})\n",
    "# leaked in a comment: {t}\n",
    "curl -H 'X: {t}' https://api.example.com\n",
    "<value>{t}</value>\n",
    "  - {t}\n",
]


class TestProviderTokens(unittest.TestCase):
    def test_every_provider_in_every_context(self):
        n = 0
        for rep in range(3):
            for kind, tok in provider_tokens(RNG):
                for ctx in TOKEN_CONTEXTS:
                    n += 1
                    src = ctx.format(t=tok)
                    with self.subTest(kind=kind, ctx=ctx, rep=rep), tempfile.TemporaryDirectory() as d:
                        v = make_vault(d)
                        safe, _ = redact(src, v, make_cfg())
                        self.assertNotIn(tok, safe, f"{kind} leaked")
                        self.assertEqual(restore(safe, v)[0], src)
        self.assertGreater(n, 500)

    def test_private_key_block(self):
        body = "\n".join(rand_str(RNG, 64, string.ascii_letters + string.digits + "+/") for _ in range(8))
        for label in ("RSA ", "EC ", "OPENSSH ", "", "ENCRYPTED "):
            pem = f"-----BEGIN {label}PRIVATE KEY-----\n{body}\n-----END {label}PRIVATE KEY-----"
            src = f'KEY = """{pem}"""\nprint(1)\n'
            with self.subTest(label=label), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                for line in body.splitlines():
                    self.assertNotIn(line, safe)
                self.assertEqual(restore(safe, v)[0], src)


# key-name assignment in many languages / formats
KEYS = ["password", "db_password", "DB_PASSWORD", "api_key", "apiKey", "API_KEY", "secret", "client_secret",
        "auth_token", "access_token", "private_key", "passphrase", "signing_key", "SECRET_KEY", "dsn", "bot_token"]
TEMPLATES = [
    ('py', '{k} = "{v}"\n'),
    ('py_single', "{k} = '{v}'\n"),
    ('py_dict', 'cfg = {{"{k}": "{v}", "debug": True}}\n'),
    ('js', 'const {k} = "{v}";\n'),
    ('js_obj', 'const conf = {{ {k}: "{v}", port: 80 }};\n'),
    ('ts_backtick', 'let {k} = `{v}`;\n'),
    ('json', '{{\n  "{k}": "{v}",\n  "name": "app"\n}}\n'),
    ('yaml', 'app:\n  {k}: {v}\n  name: demo\n'),
    ('yaml_quoted', 'app:\n  {k}: "{v}"\n'),
    ('env', '{K}={v}\n'),
    ('env_export', 'export {K}={v}\n'),
    ('ini', '[db]\n{k} = {v}\n'),
    ('toml', '[server]\n{k} = "{v}"\n'),
    ('xml', '<config><{k}>{v}</{k}></config>\n'),
    ('php', '<?php\n${k} = "{v}";\n'),
    ('php_arr', "<?php\n$c = ['{k}' => '{v}'];\n"),
    ('go', 'package main\nfunc main() {{\n\t{k} := "{v}"\n}}\n'),
    ('ruby', "{k} = '{v}'\n"),
    ('java', 'class A {{ String {k} = "{v}"; }}\n'),
    ('csharp', 'var {k} = "{v}";\n'),
    ('rust', 'let {k} = "{v}";\n'),
    ('kotlin', 'val {k} = "{v}"\n'),
    ('shell', '{K}="{v}"\n'),
    ('properties', 'app.{k}={v}\n'),
    ('pair_call', 'headers.put("{k}", "{v}");\n'),
    ('dict_index', 'os.environ["{K}"] = "{v}"\n'),
]


class TestKeyAssignments(unittest.TestCase):
    def test_matrix(self):
        rng = random.Random(42)
        count = 0
        for name, tpl in TEMPLATES:
            for k in KEYS:
                val = strong_secret(rng, rng.randint(12, 32))
                src = tpl.format(k=k, K=k.upper(), v=val)
                count += 1
                with self.subTest(fmt=name, key=k), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(val, safe, f"{name}/{k} leaked:\n{safe}")
                    self.assertEqual(restore(safe, v)[0], src)
        self.assertGreater(count, 400)

    def test_low_entropy_passwords_with_key(self):
        # human passwords: not random, rely purely on key detection
        for pw in ["hunter22", "Summer2024!", "letmein99", "correct-horse-battery", "P@ssw0rd", "qwerty123"]:
            for tpl in ('password = "{v}"\n', "DB_PASSWORD={v}\n", '"password": "{v}"\n', "password: {v}\n"):
                src = tpl.format(v=pw)
                with self.subTest(pw=pw, tpl=tpl), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(pw, safe)
                    self.assertEqual(restore(safe, v)[0], src)

    def test_extra_keywords(self):
        src = 'pin_code = "8812-ZZ-abc"\n'
        with tempfile.TemporaryDirectory() as d:
            safe, _ = redact(src, make_vault(d), make_cfg(rename_identifiers=False))
            self.assertIn("8812-ZZ-abc", safe)  # not a known key
            v = make_vault(d)
            safe, _ = redact(src, v, make_cfg(extra_keywords=["pin_code"]))
            self.assertNotIn("8812-ZZ-abc", safe)
            self.assertEqual(restore(safe, v)[0], src)


class TestStructuredCredentials(unittest.TestCase):
    def test_url_credentials(self):
        rng = random.Random(7)
        for scheme in ("postgres", "postgresql", "mysql", "mongodb+srv", "redis", "amqp", "https", "ftp", "smtp"):
            for _ in range(4):
                pw = strong_secret(rng, rng.randint(8, 20)).replace("@", "x")
                url = f"{scheme}://appuser:{pw}@db.internal.example:5432/prod"
                for src in (f'DATABASE_URL = "{url}"\n', f"{url}\n", f"conn = connect('{url}')\n"):
                    with self.subTest(src=src), tempfile.TemporaryDirectory() as d:
                        v = make_vault(d)
                        safe, _ = redact(src, v, make_cfg())
                        self.assertNotIn(pw, safe)
                        self.assertEqual(restore(safe, v)[0], src)

    def test_conn_strings(self):
        rng = random.Random(8)
        for key in ("Password", "pwd", "AccountKey", "SharedAccessKey"):
            for _ in range(5):
                pw = strong_secret(rng, 18)
                src = f'var cs = "Server=tcp:db.example;Database=prod;User Id=sa;{key}={pw};Encrypt=True";\n'
                with self.subTest(key=key), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(pw, safe)
                    self.assertEqual(restore(safe, v)[0], src)

    def test_auth_headers(self):
        rng = random.Random(9)
        for scheme in ("Bearer", "Basic", "Token", "bearer"):
            for _ in range(5):
                tok = rand_str(rng, 32, string.ascii_letters + string.digits + "._-")
                for src in (f'headers = {{"Authorization": "{scheme} {tok}"}}\n',
                            f"curl -H 'Authorization: {scheme} {tok}' https://x.example\n",
                            f"Authorization: {scheme} {tok}\n"):
                    with self.subTest(src=src), tempfile.TemporaryDirectory() as d:
                        v = make_vault(d)
                        safe, _ = redact(src, v, make_cfg())
                        self.assertNotIn(tok, safe)
                        self.assertEqual(restore(safe, v)[0], src)

    def test_high_entropy_unknown_format(self):
        rng = random.Random(10)
        for _ in range(40):
            tok = rand_str(rng, rng.randint(24, 64), string.ascii_letters + string.digits)
            src = f'client = Client("{tok}")\n'
            with self.subTest(tok=tok), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                self.assertNotIn(tok, safe)
                self.assertEqual(restore(safe, v)[0], src)


class TestPersonalData(unittest.TestCase):
    def _check(self, values, templates, cfg=None):
        for val in values:
            for tpl in templates:
                src = tpl.format(x=val)
                with self.subTest(val=val, tpl=tpl), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, cfg or make_cfg())
                    self.assertNotIn(val, safe, f"leaked: {safe!r}")
                    self.assertEqual(restore(safe, v)[0], src)

    CTX = ["{x}\n", 'contact = "{x}"\n', "# owner: {x}\n", "send({x!s})\n", "<td>{x}</td>\n"]

    def test_emails(self):
        self._check(["jane.doe@example.com", "j+tag@mail.example.org", "first_last@sub.domain.co.uk",
                     "ADMIN@CORP.EXAMPLE.NET", "a.b-c@x-y.io"], self.CTX)

    def test_ipv4(self):
        self._check(["10.0.12.34", "192.168.1.254", "172.16.0.9", "203.0.113.77", "51.15.8.200"], self.CTX)

    def test_ipv6(self):
        self._check(["2001:db8:85a3:0:0:8a2e:370:7334", "fe80::1ff:fe23:4567:890a", "2001:db8::42"],
                    ["{x}\n", 'host = "{x}"\n', "# {x}\n"])

    def test_mac(self):
        self._check(["00:1A:2B:3C:4D:5E", "a4-5e-60-c2-11-9f"], self.CTX)

    def test_phone(self):
        self._check(["+1 415 555 0132", "+44 20 7946 0958", "(415) 555-0199", "415-555-0123", "+39 333 123 4567"],
                    ["{x}\n", 'phone = "{x}"\n', "# call {x}\n"])

    def test_cards(self):
        rng = random.Random(11)
        cards = [luhn_number(rng, 16, "4") for _ in range(6)] + [luhn_number(rng, 16, "51") for _ in range(4)]
        self._check(cards, ["{x}\n", 'card = "{x}"\n', "# {x}\n"])

    def test_card_with_spaces(self):
        rng = random.Random(12)
        for _ in range(5):
            c = luhn_number(rng, 16, "4")
            spaced = " ".join(c[i:i + 4] for i in range(0, 16, 4))
            self._check([spaced], ["pay {x} now\n"])

    def test_iban_ssn(self):
        self._check(["DE89370400440532013000", "GB82 WEST 1234 5698 7654 32", "123-45-6789", "078-05-1120"],
                    ["{x}\n", 'v = "{x}"\n'])

    def test_home_paths(self):
        for p, name in (("/home/janedoe/projects/app", "janedoe"), ("/Users/jsmith/code", "jsmith"),
                        ("C:\\Users\\mrossi\\AppData", "mrossi"), ("C:\\\\Users\\\\mrossi\\\\x", "mrossi")):
            for tpl in ("{x}\n", 'path = "{x}"\n', "cd {x} && make\n"):
                src = tpl.format(x=p)
                with self.subTest(p=p, tpl=tpl), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(name, safe)
                    self.assertEqual(restore(safe, v)[0], src)

    def test_once_hidden_always_hidden(self):
        # a value hidden once (via key context) must be hidden later even without context
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            redact('password = "Tr0ub4dor&3x"\n', v, make_cfg())
            v.save()
            v2 = make_vault(d)
            safe, _ = redact("print('Tr0ub4dor&3x')\n", v2, make_cfg())
            self.assertNotIn("Tr0ub4dor&3x", safe)

    def test_always_hide_and_hide_literals(self):
        src = "Project Bluebird owned by AcmeCorp, codename bluebird-x\n"
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact(src, v, make_cfg(always_hide=["AcmeCorp", "Bluebird"]), extra_literals=["bluebird-x"])
            for w in ("AcmeCorp", "Bluebird", "bluebird-x"):
                self.assertNotIn(w, safe)
            self.assertEqual(restore(safe, v)[0], src)


class TestQueries(unittest.TestCase):
    QUERIES = [
        "SELECT id, email FROM customers WHERE plan = 'gold'",
        "select * from orders o join users u on u.id = o.user_id",
        "INSERT INTO audit_log (actor, action) VALUES (%s, %s)",
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        "DELETE FROM sessions WHERE expires_at < NOW()",
        "CREATE TABLE payroll (id INT, salary DECIMAL)",
        "WITH recent AS (SELECT * FROM t) SELECT * FROM recent",
        "query GetUser($id: ID!) { user(id: $id) { name email } }",
        "mutation { deleteAccount(id: 5) { ok } }",
    ]

    def test_queries_in_strings(self):
        for q in self.QUERIES:
            for tpl in ('cur.execute("{q}")\n', "db.query(`{q}`);\n", 'sql = """{q}"""\n', "$q = '{q}';\n"):
                if "'" in q and tpl.startswith("$q"):
                    continue
                src = tpl.format(q=q)
                with self.subTest(q=q, tpl=tpl), tempfile.TemporaryDirectory() as d:
                    v = make_vault(d)
                    safe, _ = redact(src, v, make_cfg())
                    self.assertNotIn(q, safe)
                    self.assertIn("QUERY", safe)
                    self.assertEqual(restore(safe, v)[0], src)

    def test_raw_sql_file(self):
        src = ("-- schema\nCREATE TABLE secrets_table (id INT PRIMARY KEY, val TEXT);\n"
               "INSERT INTO secrets_table VALUES (1, 'x');\nSELECT val FROM secrets_table WHERE id = 1;\n")
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact(src, v, make_cfg())
            self.assertNotIn("secrets_table", safe)
            self.assertEqual(restore(safe, v)[0], src)

    def test_keep_queries(self):
        src = 'cur.execute("SELECT id FROM customers")\n'
        cfg = make_cfg(rename_identifiers=False)
        for k in ("sql_string", "graphql", "raw_sql"):
            cfg.detectors[k] = False
        with tempfile.TemporaryDirectory() as d:
            safe, _ = redact(src, make_vault(d), cfg)
            self.assertEqual(safe, src)


class TestRandomLeakHunt(unittest.TestCase):
    """Random documents mixing code noise with planted secrets in random formats."""

    def test_random_mixed_documents(self):
        rng = random.Random(int(os.environ.get("SCRUB_SEED", 777)))
        noise = ["def handler(evt):", "    return evt", "for i in range(10): pass", "// TODO", "x = 1",
                 "if (a && b) { run(); }", "# config", "<div class='x'>hi</div>", "}", "SELECT_ALL = False",
                 "print('ok')", "items: [1, 2, 3]", "  - name: web", "fn main() {}", ""]
        for i in range(300):
            planted, lines = [], []
            for _ in range(rng.randint(3, 20)):
                if rng.random() < 0.35:
                    kind = rng.randrange(6)
                    if kind == 0:
                        val = strong_secret(rng, rng.randint(10, 30))
                        tpl = rng.choice([t for _, t in TEMPLATES if "{{" not in t and "\n" not in t.rstrip("\n")])
                        lines.append(tpl.format(k=rng.choice(KEYS), K=rng.choice(KEYS).upper(), v=val).rstrip("\n"))
                    elif kind == 1:
                        _, val = rng.choice(provider_tokens(rng))
                        lines.append(rng.choice(["t = '{}'", "# {}", "use({})", "{}"]).format(val))
                    elif kind == 2:
                        val = rand_str(rng, 7).lower() + "@example.net"
                        lines.append(f"# owner {val}")
                    elif kind == 3:
                        val = f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                        lines.append(f'host = "{val}"')
                    elif kind == 4:
                        val = strong_secret(rng, 14).replace("@", "x")
                        lines.append(f"url = 'mysql://svc:{val}@db.local/app'")
                    else:
                        val = luhn_number(rng, 16, "4")
                        lines.append(f"card = {val}")
                    planted.append(val)
                else:
                    lines.append(rng.choice(noise))
            src = "\n".join(lines) + "\n"
            with self.subTest(i=i, src=src), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                for val in planted:
                    self.assertNotIn(val, safe)
                self.assertEqual(restore(safe, v)[0], src)


if __name__ == "__main__":
    unittest.main()
