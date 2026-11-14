# secret-scrub

Hide credentials and personal data before pasting code into Claude (or any AI / website), then put the real values back into the answer.

Pure Python 3 stdlib. Works on any language / config format (Python, JS/TS, Java, C#, Go, PHP, Ruby, Rust, shell, .env, YAML, JSON, TOML, INI, XML, SQL...).

## GUI

```bash
./gui.py            # or: ./secret_scrub.py   (no args)   or app menu: "secret-scrub"
```

- **Work**: input/output editors, Redact / Restore / Auto (Ctrl+Enter) / Scan (F5), highlighted placeholders, findings table (filter, right-click: allowlist, disable detector, copy value)
- **Detection**: toggle every detector and provider format, entropy threshold, min lengths, identifier kinds, comment/string renaming, placeholder prefix/digits, vault path
- **Custom rules**: always-hide list, never-hide allowlist, extra sensitive key names, custom regex patterns with live tester
- **Vault**: search, show/hide values, delete, export, import/merge, clear
- **Appearance**: dark/light theme, editor font + size, wrap, highlight, auto-copy

Settings auto-save to `~/.secret_scrub/settings.json` and are shared with the CLI.

## CLI

```bash
./secret_scrub.py redact --clip     # copy code -> run -> paste safe version into Claude
./secret_scrub.py restore --clip    # copy Claude's answer -> run -> paste real code in editor
./secret_scrub.py                   # interactive menu
./secret_scrub.py redact app.py -o app.safe.py
./secret_scrub.py restore fixed.py -o app.py
./secret_scrub.py scan app.py       # report only, exit 1 if anything found
./secret_scrub.py vault list        # masked list of stored values
```

Placeholders look like `REDACTED_PASSWORD_0001`. Tell the AI to keep them unchanged.
New names the AI invents are left as-is on restore.
Same value always gets the same placeholder, across files and runs.

## What gets hidden

- Provider tokens: AWS, GitHub, GitLab, Slack, Discord, Stripe, Google, OpenAI, Anthropic, HuggingFace, npm, PyPI, SendGrid, Twilio, Mailgun, Telegram, Shopify, DigitalOcean, JWTs, private key blocks, webhooks
- Any value assigned to a key named like password/secret/token/api_key/credential/salt/dsn/...
- Passwords in URLs (`user:PASS@host`), connection strings (`Password=...;`), `Bearer`/`Basic` headers
- High-entropy random-looking strings (`--no-entropy` to disable)
- PII (`--no-pii` to disable): emails, IPv4/IPv6, MAC, phone numbers, credit cards (Luhn), IBAN, US SSN, usernames in `/home/<x>` / `C:\Users\<x>` paths
- Your local username + hostname, and every line of `~/.secret_scrub/always_hide.txt`
- **Queries**: SQL (SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/DROP/WITH/GRANT/EXEC...) and GraphQL, inside strings or raw `.sql` -> `REDACTED_QUERY_0001` (`--keep-queries` to disable)
- **Identifiers**: variables, functions, classes, params, attributes declared in the code -> `REDACTED_VAR_0001`, `REDACTED_FUNC_0002`, `REDACTED_CLASS_0003`... renamed consistently in code, comments and string interpolation (`f"{x}"`, `${x}`, `#{x}`, `"$x"`). Keywords, builtins and imported library names stay readable. (`--keep-names` to disable)
- Anything already in the vault (once hidden, always hidden)
- `--hide "text"` for one-off extras

## Vault

`~/.secret_scrub/vault.json` (mode 600) holds the real values in **plaintext**. Never share it; it is required for `restore`.

## Tests

```bash
python3 -m unittest discover -s tests          # ~90 test methods, ~2,900 sub-cases, stdlib only
SCRUB_SEED=7 python3 -m unittest discover -s tests   # re-run the randomized tests with another seed
```

Covers: no-leak checks for every provider format / key-assignment style / PII type in many languages,
exact `restore(redact(x)) == x` round-trips (incl. random fuzz and CRLF/unicode), restoring after
AI-style edits (moved / deleted / duplicated / new lines), vault persistence + permissions, every
setting and detector toggle, the CLI end to end, and a GUI smoke test (skipped without a display).
Tests use a temporary `SECRET_SCRUB_HOME`, so your real vault and settings are never touched.
