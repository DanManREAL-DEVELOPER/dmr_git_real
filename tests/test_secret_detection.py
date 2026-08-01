#!/usr/bin/env python3
"""Regression test for the GIT_REAL secret-detector fix (2026-06-22).

Bug: `aws_secret_access_key = "..."` value lines slipped past detection
(AWS-secret regex gap too tight; generic rule's \\b couldn't cross snake_case
underscores). Survived a multi-person stress test; caught on first agent run.

Run:  python3 tests/test_secret_detection.py   (exit 0 = all pass)
"""
import importlib.util, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gitreal", os.path.join(HERE, "..", "gitreal.py"))
gr = importlib.util.module_from_spec(spec); spec.loader.exec_module(gr)

def detects(line: str) -> list:
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "f.txt"), "w") as fh:
            fh.write(line + "\n")
        return gr.scan_file_for_secrets(d, "f.txt")

# (label, line, must_detect)
CASES = [
    # Fixtures below carry deliberately non-functional example secrets so GIT_REAL's
    # own detector can be tested. `gitleaks:allow` keeps the repo's CI from flagging them.
    ("AWS secret - env style (THE BUG)",     'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', True),  # gitleaks:allow
    ("AWS secret - quoted assignment (THE BUG)", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', True),  # gitleaks:allow
    ("snake_case db_password",                'db_password = "S3cr3t-P@ssw0rd-9281xZ"', True),  # gitleaks:allow
    ("snake_case github_client_secret",       'GITHUB_CLIENT_SECRET = "ab12cd34ef56gh78ij90kl"', True),  # gitleaks:allow
    ("AWS access key id (regression)",        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', True),  # gitleaks:allow
    # --- must NOT flag (false-positive guards) ---
    ("tail-anchor: my_token_count",           'my_token_count = "abcdefgh"', False),
    ("low-entropy placeholder",               'password = "00000000"', False),
    ("too short",                             'password = "x"', False),
    ("ordinary code",                         'const handler = () => doStuff(items)', False),
]

fails = 0
for label, line, must in CASES:
    got = bool(detects(line))
    ok = (got == must)
    if not ok: fails += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] expect={'DETECT' if must else 'clean':6} got={'DETECT' if got else 'clean':6}  {label}")

print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}  ({len(CASES)} cases)")
sys.exit(1 if fails else 0)
