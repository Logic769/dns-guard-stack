#!/usr/bin/env python3
"""Embed local TLS files into rendered AGH YAML; never print their contents."""
import io
import os
import re
import sys
import tempfile


def configure(cert_path, key_path, paths):
    with io.open(cert_path, encoding="utf-8") as stream:
        cert = stream.read().strip()
    with io.open(key_path, encoding="utf-8") as stream:
        key = stream.read().strip()
    if not cert or not key:
        raise ValueError("TLS certificate and key must be non-empty")
    updated = []
    for path in paths:
        with io.open(path, encoding="utf-8") as stream:
            text = stream.read()
        for field, value in (("certificate_chain", cert), ("private_key", key)):
            pattern = r"(?m)^  " + field + r":[^\n]*(?:\n(?:    [^\n]*|[ \t]*))*(?:\n|$)"
            replacement = "  " + field + ": |\n" + "".join(
                "    " + line + "\n" for line in value.splitlines())
            text, count = re.subn(pattern, lambda match: replacement, text)
            if count != 1:
                raise ValueError("Expected exactly one TLS field: " + field)
        updated.append((path, text))
    for path, text in updated:
        descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
        try:
            with io.open(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if __name__ == "__main__":
    try:
        if len(sys.argv) < 4:
            raise ValueError("Usage: configure-agh-tls.py CERT KEY CONFIG [CONFIG ...]")
        configure(sys.argv[1], sys.argv[2], sys.argv[3:])
    except Exception as error:
        # Errors may contain input paths, but never certificate/key bytes.
        print("AGH TLS configuration failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
