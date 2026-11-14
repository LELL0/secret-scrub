"""Round-trip tests: restore(redact(x)) == x for many languages, random fuzz input, and
AI-style edits of the redacted code (the edited answer must restore to the same edits
applied to the real code)."""
from __future__ import annotations

import os
import random
import re
import string
import tempfile
import time
import unittest

from helpers import make_cfg, make_vault, rand_str, redact, restore, strong_secret

# fake tokens are assembled at runtime so the source file itself never contains a
# token-shaped literal (keeps secret scanners / GitHub push protection quiet)
FAKE = {
    "@@STRIPE1@@": "sk_" + "live_51HxQzT2eZvKYlo2C8nB4mQ1",
    "@@STRIPE2@@": "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc",
    "@@GITLAB1@@": "gl" + "pat-AbCdEfGhIjKlMnOpQrSt",
    "@@GOOGLE1@@": "AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
}
SAMPLES = {
    "python": '''import os
from dataclasses import dataclass

DB_PASSWORD = "Xk29!fpL0qmZ"

@dataclass
class InvoiceService:
    tax_rate: float = 0.22

    def compute_invoice_total(self, line_items, discount=0):
        subtotal = sum(i.price * i.qty for i in line_items)
        self.last_total = subtotal * (1 + self.tax_rate) - discount
        print(f"total for {len(line_items)} items: {self.last_total}")
        return self.last_total

def load_customer(customer_id: int) -> dict:
    # fetch customer_id from the db
    with open(os.path.join("/srv/data", str(customer_id))) as fh:
        return {"id": customer_id, "raw": fh.read()}
''',
    "javascript": '''const express = require("express");
const { readFileSync } = require("fs");
const apiKey = "@@STRIPE1@@";

function calculateShipping(orderWeight, destinationZone) {
  const baseRate = 4.5;
  return baseRate * orderWeight + destinationZone.extra;
}

const formatReceipt = (receiptLines) => receiptLines.map(line => `${line.name}: ${line.amount}`).join("\\n");

class CartManager {
  constructor(storeName) {
    this.storeName = storeName;
    this.cartItems = [];
  }
  addItem(cartItem) { this.cartItems.push(cartItem); }
}
module.exports = { calculateShipping, formatReceipt, CartManager };
''',
    "typescript": '''import { Injectable } from "@angular/core";

export interface UserProfile { userName: string; joinedAt: Date }

export type ProfileMap = Record<string, UserProfile>;

export class ProfileStore {
  private profileCache: ProfileMap = {};
  getProfile(profileKey: string): UserProfile | undefined {
    return this.profileCache[profileKey];
  }
}
const sessionSecret: string = "b7Gq9Lw2Zr4Tx8Np";
''',
    "go": '''package main

import (
	"fmt"
	"net/http"
)

type PaymentGateway struct {
	merchantID string
}

func (g *PaymentGateway) ChargeCard(amountCents int, cardToken string) error {
	requestBody := fmt.Sprintf("amount=%d&token=%s", amountCents, cardToken)
	resp, err := http.Post("https://pay.example.com/charge", "text/plain", nil)
	_ = requestBody
	_ = resp
	return err
}
''',
    "java": '''package com.example.billing;

import java.util.List;

public class LedgerReconciler {
    private final String auditPassword = "Qz8!mPw3LxV9";
    private int mismatchCount;

    public int reconcileEntries(List<String> ledgerEntries, int toleranceCents) {
        int runningDelta = 0;
        for (String entry : ledgerEntries) {
            runningDelta += entry.length();
        }
        mismatchCount = runningDelta > toleranceCents ? 1 : 0;
        return mismatchCount;
    }
}
''',
    "csharp": '''using System;

namespace Acme.Payroll {
    public class SalaryCalculator {
        private string connStr = "Server=db;Database=hr;User Id=sa;Password=H7#kq2Lp9Wz;";
        public decimal NetSalary(decimal grossSalary, decimal taxBracket) {
            var deductions = grossSalary * taxBracket;
            return grossSalary - deductions;
        }
    }
}
''',
    "rust": '''use std::collections::HashMap;

struct TokenBucket {
    capacity: u32,
    refill_rate: u32,
}

fn consume_tokens(bucket: &mut TokenBucket, requested: u32) -> bool {
    let remaining = bucket.capacity - requested;
    let api_token = "@@GITLAB1@@";
    remaining > 0
}
''',
    "php": '''<?php
require_once "vendor/autoload.php";

$dbPassword = "Rt5!xQ2wLm8Z";

function sendNewsletter($subscriberList, $templateName) {
    foreach ($subscriberList as $subscriber) {
        echo "Sending $templateName to {$subscriber}";
    }
}
''',
    "ruby": '''require "json"

class OrderExporter
  def initialize(export_path)
    @export_path = export_path
  end

  def export_orders(order_rows)
    order_rows.each do |row|
      puts "#{row} -> #{@export_path}"
    end
  end
end
secret_token = "a8Zk2Lq9Xw4Rt7Pm"
''',
    "shell": '''#!/bin/bash
BACKUP_DIR="/home/opsadmin/backups"
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
backup_database() {
  local target_name="$1"
  pg_dump "postgres://backup:Pg5ecret9x@10.1.2.3/prod" > "$BACKUP_DIR/$target_name.sql"
}
backup_database nightly
''',
    "yaml": '''services:
  api:
    image: acme/api:1.2
    environment:
      DATABASE_URL: postgres://svc:Yt7pLq2xZ@db.internal:5432/main
      STRIPE_KEY: @@STRIPE2@@
      admin_email: owner@acme-example.com
''',
    "env": '''# local dev
APP_SECRET=Zx9!aQ2wE4rT6y
SMTP_PASSWORD=mailpass2025
REDIS_URL=redis://:r3disPw@cache.local:6379/0
OWNER_IP=192.168.10.44
''',
    "json": '''{
  "name": "billing",
  "client_secret": "8fJ2kLq9ZxW4mN7p",
  "contacts": ["ops@example.org"],
  "nested": {"apiKey": "@@GOOGLE1@@"}
}
''',
    "sql": '''-- migration 042
CREATE TABLE customer_secrets (id INT PRIMARY KEY, card TEXT);
INSERT INTO customer_secrets VALUES (1, '4111 1111 1111 1111');
SELECT card FROM customer_secrets WHERE id = 1;
''',
    "kotlin": '''package app

data class Shipment(val trackingCode: String, val weightKg: Double)

fun estimateArrival(shipment: Shipment, hubDelayDays: Int): Int {
    val baseDays = 3
    return baseDays + hubDelayDays
}
''',
    "c": '''#include <stdio.h>

static const char *license_key = "LK-9f8e7d6c5b4a";

int checksum_block(const unsigned char *block_data, int block_len) {
    int acc = 0;
    for (int idx = 0; idx < block_len; idx++) {
        acc += block_data[idx];
    }
    return acc;
}
''',
}

for _lang, _src in SAMPLES.items():
    for _k, _v in FAKE.items():
        _src = _src.replace(_k, _v)
    SAMPLES[_lang] = _src

# names that must be renamed in each sample (proves identifier hiding works)
MUST_RENAME = {
    "python": ["InvoiceService", "compute_invoice_total", "line_items", "load_customer", "customer_id", "subtotal"],
    "javascript": ["calculateShipping", "orderWeight", "formatReceipt", "CartManager", "cartItems"],
    "typescript": ["ProfileStore", "profileCache", "getProfile", "profileKey"],
    "go": ["PaymentGateway", "ChargeCard", "amountCents", "requestBody"],
    "java": ["LedgerReconciler", "reconcileEntries", "ledgerEntries", "runningDelta"],
    "csharp": ["SalaryCalculator", "NetSalary", "grossSalary", "deductions"],
    "rust": ["TokenBucket", "consume_tokens", "remaining"],
    "php": ["sendNewsletter", "subscriberList", "dbPassword"],
    "ruby": ["OrderExporter", "export_orders", "order_rows"],
    "kotlin": ["Shipment", "estimateArrival", "hubDelayDays"],
    "c": ["checksum_block", "block_data", "block_len"],
}
MUST_HIDE = {
    "python": ["Xk29!fpL0qmZ"],
    "javascript": [FAKE["@@STRIPE1@@"]],
    "typescript": ["b7Gq9Lw2Zr4Tx8Np"],
    "java": ["Qz8!mPw3LxV9"],
    "csharp": ["H7#kq2Lp9Wz"],
    "rust": [FAKE["@@GITLAB1@@"]],
    "php": ["Rt5!xQ2wLm8Z"],
    "ruby": ["a8Zk2Lq9Xw4Rt7Pm"],
    "shell": ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY", "opsadmin", "Pg5ecret9x", "10.1.2.3"],
    "yaml": ["Yt7pLq2xZ", FAKE["@@STRIPE2@@"], "owner@acme-example.com"],
    "env": ["Zx9!aQ2wE4rT6y", "mailpass2025", "r3disPw", "192.168.10.44"],
    "json": ["8fJ2kLq9ZxW4mN7p", "ops@example.org", FAKE["@@GOOGLE1@@"]],
    "sql": ["customer_secrets", "4111 1111 1111 1111"],
    "c": ["LK-9f8e7d6c5b4a"],
}

CONFIGS = {
    "default": {},
    "keep_names": {"rename_identifiers": False},
    "no_comments_strings": {"rename_in_comments": False, "rename_in_strings": False},
    "custom_prefix": {"placeholder_prefix": "HIDDEN", "placeholder_digits": 6},
    "no_kind": {"kind_in_placeholder": False},
    "min_len_5": {"ident_min_len": 5},
}


def apply_line_edits(lines: list[str], ops: list[tuple]) -> list[str]:
    out = list(lines)
    for op in ops:
        if op[0] == "del":
            del out[op[1]]
        elif op[0] == "swap":
            out[op[1]], out[op[2]] = out[op[2]], out[op[1]]
        elif op[0] == "dup":
            out.insert(op[1], out[op[1]])
        elif op[0] == "ins":
            out.insert(op[1], op[2])
        elif op[0] == "indent":
            out[op[1]] = "    " + out[op[1]]
    return out


class TestLanguageRoundtrip(unittest.TestCase):
    def test_all_samples_all_configs(self):
        for lang, src in SAMPLES.items():
            for cname, over in CONFIGS.items():
                with self.subTest(lang=lang, cfg=cname), tempfile.TemporaryDirectory() as d:
                    cfg = make_cfg(**over)
                    v = make_vault(d, cfg)
                    safe, _ = redact(src, v, cfg)
                    self.assertEqual(restore(safe, v)[0], src)
                    for s in MUST_HIDE.get(lang, []):
                        self.assertNotIn(s, safe, f"{lang}/{cname}: {s} leaked")
                    if over.get("rename_identifiers", True) and cname not in ("min_len_5", "no_comments_strings"):
                        for name in MUST_RENAME.get(lang, []):
                            self.assertIsNone(re.search(rf"\b{re.escape(name)}\b", safe),
                                              f"{lang}/{cname}: identifier {name} not renamed\n{safe}")

    def test_vault_persisted_restore(self):
        """Restore with a freshly loaded vault (as the CLI does in a separate run)."""
        for lang, src in SAMPLES.items():
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                v.save()
                self.assertEqual(restore(safe, make_vault(d))[0], src)

    def test_deterministic_across_runs(self):
        for lang, src in SAMPLES.items():
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                a, _ = redact(src, v, make_cfg())
                v.save()
                v2 = make_vault(d)
                b, _ = redact(src, v2, make_cfg())
                self.assertEqual(a, b)
                self.assertEqual(len(v2.by_placeholder), len(v.by_placeholder), "vault grew on re-run")

    def test_all_samples_in_one_vault(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            outs = []
            for src in SAMPLES.values():
                outs.append(redact(src, v, make_cfg())[0])
            v.save()
            v2 = make_vault(d)
            for src, safe in zip(SAMPLES.values(), outs):
                self.assertEqual(restore(safe, v2)[0], src)

    def test_redact_twice_is_stable(self):
        """Redacting already-redacted text must not wrap placeholders into new placeholders."""
        for lang, src in SAMPLES.items():
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                once, _ = redact(src, v, make_cfg())
                twice, _ = redact(once, v, make_cfg())
                self.assertEqual(twice, once)
                self.assertEqual(restore(twice, v)[0], src)


class TestAIEdits(unittest.TestCase):
    """Simulate an AI modifying the redacted code; the restored answer must equal the same
    modification applied to the real code."""

    def _single_line_sources(self):
        rng = random.Random(99)
        for lang, src in SAMPLES.items():
            yield lang, src
        for i in range(30):  # synthetic files
            lines = []
            for j in range(rng.randint(5, 15)):
                choice = rng.random()
                if choice < 0.3:
                    lines.append(f'api_key_{j} = "{strong_secret(rng)}"')
                elif choice < 0.5:
                    lines.append(f"def handler_{i}_{j}(arg_{j}, other_{j}):")
                elif choice < 0.65:
                    lines.append(f"    result_{j} = arg_{j} + 1  # uses arg_{j}")
                elif choice < 0.8:
                    lines.append(f"# mail {rand_str(rng, 6).lower()}@example.com at 10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}")
                else:
                    lines.append(f"print('plain text {j}')")
            yield f"synthetic{i}", "\n".join(lines) + "\n"

    def test_line_edits(self):
        rng = random.Random(int(os.environ.get("SCRUB_SEED", 2024)))
        n = 0
        for name, src in self._single_line_sources():
            with tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, report = redact(src, v, make_cfg())
                orig_lines = src.split("\n")
                safe_lines = safe.split("\n")
                if len(orig_lines) != len(safe_lines):
                    continue  # multi-line finding; line mapping not 1:1
                phs = sorted(set(re.findall(r"REDACTED_[A-Z_]+_\d{4}", safe)))
                for trial in range(8):
                    n += 1
                    ops = []
                    size = len(orig_lines)
                    for _ in range(rng.randint(1, 4)):
                        kind = rng.choice(["del", "swap", "dup", "ins", "indent"])
                        if kind == "del" and size > 2:
                            ops.append(("del", rng.randrange(size)))
                            size -= 1
                        elif kind == "swap" and size > 1:
                            ops.append(("swap", rng.randrange(size), rng.randrange(size)))
                        elif kind == "dup":
                            ops.append(("dup", rng.randrange(size)))
                            size += 1
                        elif kind == "ins" and phs:
                            ph = rng.choice(phs)
                            ops.append(("ins", rng.randrange(size + 1), f"new_helper_{trial} = check({ph})  # AI added, uses {ph}"))
                            size += 1
                        else:
                            ops.append(("indent", rng.randrange(size)))
                    edited_safe = "\n".join(apply_line_edits(safe_lines, ops))
                    # expected: same ops on original, inserted lines get the real values
                    exp_ops = [(o[0], o[1], re.sub(r"REDACTED_[A-Z_]+_\d{4}", lambda m: v.by_placeholder[m.group()], o[2]))
                               if o[0] == "ins" else o for o in ops]
                    expected = "\n".join(apply_line_edits(orig_lines, exp_ops))
                    with self.subTest(src=name, trial=trial, ops=ops):
                        out, _, unknown = restore(edited_safe, v)
                        self.assertEqual(out, expected)
                        self.assertEqual(unknown, [])
        self.assertGreater(n, 200)

    def test_ai_invented_placeholder_reported(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact(SAMPLES["python"], v, make_cfg())
            answer = safe + "\nREDACTED_VAR_9999 = REDACTED_FUNC_0002()\n"
            out, restored, unknown = restore(answer, v)
            self.assertIn("REDACTED_VAR_9999", unknown)
            self.assertIn("REDACTED_VAR_9999", out)

    def test_ai_changes_case_or_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact('password = "Mz8!pq2Lx9"\n', v, make_cfg())
            ph = re.search(r"REDACTED_PASSWORD_\d{4}", safe).group()
            # placeholder followed by a letter/underscore suffix still restores the prefix part?
            out, _, _ = restore(f"x = {ph}\ny = {ph}0\n", v)
            self.assertIn("Mz8!pq2Lx9", out.splitlines()[0])
            self.assertNotIn("Mz8!pq2Lx9", out.splitlines()[1])  # different number -> must not half-restore

    def test_placeholder_inside_new_strings_and_comments(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            src = 'def connect_db(db_host):\n    password = "Kq3!xW9zLp"\n    return db_host\n'
            safe, _ = redact(src, v, make_cfg())
            phs = re.findall(r"REDACTED_[A-Z_]+_\d{4}", safe)
            answer = safe + "".join(f"# note: {p} is important\nlog(f'{{{p}}}')\n" for p in phs)
            out, restored, unknown = restore(answer, v)
            self.assertFalse(re.search(r"REDACTED_[A-Z_]+_\d{4}", out))
            self.assertIn("connect_db", out)
            self.assertIn("Kq3!xW9zLp", out)
            self.assertEqual(unknown, [])


class TestFuzz(unittest.TestCase):
    PIECES = [
        lambda r: f'password = "{strong_secret(r)}"', lambda r: f"token: {strong_secret(r)}",
        lambda r: "ghp_" + rand_str(r, 36), lambda r: f"{rand_str(r, 5).lower()}@example.com",
        lambda r: f"10.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}",
        lambda r: f"def fn_{rand_str(r, 4)}(a1, b2):", lambda r: f"var_{rand_str(r, 3)} = {r.randint(0, 999)}",
        lambda r: "SELECT * FROM t WHERE x = 1;", lambda r: "/* block */", lambda r: "// line",
        lambda r: "# hash", lambda r: "'", lambda r: '"', lambda r: "`", lambda r: '"""', lambda r: "\\",
        lambda r: "{", lambda r: "}", lambda r: "${x}", lambda r: "\t", lambda r: "\r\n", lambda r: "\n",
        lambda r: "ünïcødé ✓ 日本語", lambda r: "REDACTED", lambda r: "REDACTED_VAR_", lambda r: "_0001",
        lambda r: rand_str(r, r.randint(1, 40), string.printable), lambda r: "<!-- c -->", lambda r: "-- sql c",
        lambda r: "postgres://u:" + strong_secret(r, 10).replace("@", "") + "@h/db",
        lambda r: "Bearer " + rand_str(r, 30), lambda r: "/home/" + rand_str(r, 6).lower() + "/x",
        lambda r: "AKIA" + rand_str(r, 16, string.ascii_uppercase + string.digits),
        lambda r: "class Klass_" + rand_str(r, 3) + ":", lambda r: "    ", lambda r: "f'{a1}'",
    ]

    def test_random_documents_roundtrip(self):
        rng = random.Random(int(os.environ.get("SCRUB_SEED", 31337)))
        for i in range(400):
            src = "".join(rng.choice(self.PIECES)(rng) + rng.choice(["", " ", "\n", "; "]) for _ in range(rng.randint(1, 40)))
            with self.subTest(i=i, src=src), tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, _ = redact(src, v, make_cfg())
                self.assertEqual(restore(safe, v)[0], src)
                v.save()
                self.assertEqual(restore(safe, make_vault(d))[0], src)

    def test_random_documents_shared_vault(self):
        """Many documents through ONE vault (real-world usage): all still restore."""
        rng = random.Random(int(os.environ.get("SCRUB_SEED", 4242)))
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            pairs = []
            for i in range(150):
                src = "".join(rng.choice(self.PIECES)(rng) + rng.choice(["", " ", "\n"]) for _ in range(rng.randint(1, 25)))
                pairs.append((src, redact(src, v, make_cfg())[0]))
            v.save()
            v2 = make_vault(d)
            for i, (src, safe) in enumerate(pairs):
                with self.subTest(i=i, src=src):
                    self.assertEqual(restore(safe, v2)[0], src)

    def test_restore_of_text_without_placeholders_is_identity(self):
        rng = random.Random(5)
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            redact(SAMPLES["python"], v, make_cfg())
            for i in range(100):
                txt = rand_str(rng, rng.randint(0, 200), string.printable)
                with self.subTest(i=i):
                    self.assertEqual(restore(txt, v)[0], txt)


class TestEdgeCases(unittest.TestCase):
    def test_empty_and_whitespace(self):
        for src in ("", " ", "\n", "\n\n\t  \r\n"):
            with tempfile.TemporaryDirectory() as d:
                v = make_vault(d)
                safe, report = redact(src, v, make_cfg())
                self.assertEqual(safe, src)
                self.assertEqual(report, [])

    def test_crlf_preserved(self):
        src = 'password = "Ab3!xyz9Q"\r\ndef run_job(job_id):\r\n    return job_id\r\n'
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact(src, v, make_cfg())
            self.assertEqual(safe.count("\r\n"), 3)
            self.assertEqual(restore(safe, v)[0], src)

    def test_unicode_secret(self):
        src = 'password = "pässwörd✓2024"\nnome_utente = "José"\n'
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, _ = redact(src, v, make_cfg())
            self.assertNotIn("pässwörd✓2024", safe)
            self.assertEqual(restore(safe, v)[0], src)
            v.save()
            self.assertEqual(restore(safe, make_vault(d))[0], src)

    def test_large_file_performance(self):
        src = "\n".join(SAMPLES.values()) * 20  # ~ 300 KB of mixed code
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            t = time.time()
            safe, _ = redact(src, v, make_cfg())
            self.assertEqual(restore(safe, v)[0], src)
            self.assertLess(time.time() - t, 60, "too slow")

    def test_report_matches_output(self):
        with tempfile.TemporaryDirectory() as d:
            v = make_vault(d)
            safe, report = redact(SAMPLES["yaml"], v, make_cfg())
            for f, value, ph in report:
                self.assertIn(ph, safe)
                self.assertEqual(v.by_placeholder[ph], value)


if __name__ == "__main__":
    unittest.main()
