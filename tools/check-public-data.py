#!/usr/bin/env python3
"""Scan tracked files or reachable Git blobs. Report paths/categories, never secrets."""
import re
import subprocess
import sys


RULES = [
    ("private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("embedded certificate", re.compile(rb"-----BEGIN " + rb"CERTIFICATE-----")),
    ("GitHub credential", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("AWS access key", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("production identity", re.compile(
        rb"(?i)(?:120[.]26[.]230[.]117|172[.]17[.]36[.]43|logic769[.]xyz|"
        rb"tiancongyu769@outlook[.]com|C:[/\\]Users[/\\]tianc(?:[/\\]|$))")),
]


def violations(data):
    return [label for label, pattern in RULES if pattern.search(data)]


def git(*args):
    return subprocess.check_output(["git"] + list(args))


def main():
    failures = 0
    if "--history" in sys.argv:
        objects = git("rev-list", "--objects", "--all").splitlines()
        for entry in objects:
            fields = entry.split(b" ", 1)
            oid = fields[0].decode("ascii")
            kind = git("cat-file", "-t", oid).strip()
            if kind not in (b"blob", b"commit", b"tag"):
                continue
            labels = violations(git("cat-file", kind.decode("ascii"), oid))
            if labels:
                location = fields[1].decode("utf-8", "replace") if len(fields) > 1 else kind.decode()
                print("FAIL %s %s: %s" % (oid[:12], location, ", ".join(labels)))
                failures += 1
    else:
        for raw in git("ls-files", "-z").split(b"\0"):
            if not raw:
                continue
            name = raw.decode("utf-8")
            with open(name, "rb") as stream:
                labels = violations(stream.read())
            if labels:
                print("FAIL %s: %s" % (name, ", ".join(labels)))
                failures += 1
    print("Public data check: %s (%d affected objects/files)" %
          ("FAIL" if failures else "PASS", failures))
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
