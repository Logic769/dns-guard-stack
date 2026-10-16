"""2026-10-15 审计 F5 —— **live** 验收：真实 verifier 必须拒绝"非本发布"的握手。

默认跳过（不联网、不碰生产）；在目标机上显式开启：

    DNS_LIVE_VERIFIER=/run/dnsguard/verifier.sock python3 tests/test_verifier_live_handshake.py

本方只发一个**错身份**的握手帧，verifier 会立刻拒服务 ⇒ 无查询、无副作用 ✓。
"""
import json
import os
import socket
import struct
import sys
import unittest

SOCK = os.environ.get("DNS_LIVE_VERIFIER", "")


def _recvn(c, n):
    d = b""
    while len(d) < n:
        x = c.recv(n - len(d))
        if not x:
            raise IOError("short")
        d += x
    return d


def _handshake(meta):
    msg = struct.pack("!HHHHHH", 0x1234, 0x100, 1, 0, 0, 0) + b"\x04zzz\x03com\x00" + struct.pack("!HH", 1, 1)
    payload = json.dumps(meta).encode()
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5.0)
    c.connect(SOCK)
    c.sendall(struct.pack("!HH", len(payload), len(msg)) + payload + msg)
    n = struct.unpack("!H", _recvn(c, 2))[0]
    raw = _recvn(c, n) if n else b""
    c.close()
    return raw


@unittest.skipUnless(SOCK and os.path.exists(SOCK), "set DNS_LIVE_VERIFIER to the live socket")
class LiveHandshake(unittest.TestCase):
    def test_wrong_sha_rejected_with_version_mismatch(self):
        raw = _handshake({"name": "example.com", "qtype": 1, "timeout": 1.0,
                          "prefer_addr": False, "op": "corrob", "targets": None,
                          "pool": "corrob", "rid": "live-test",
                          "rel": "not-this-release", "sha": "0" * 64, "proto": 2})
        self.assertTrue(raw, "verifier 无应答")
        self.assertEqual(raw[0:1], b"\x05",
                         "错身份握手应回 VERSION_MISMATCH(0x05)，实得 %r" % raw[0:1])

    def test_wrong_rel_same_sha_rejected(self):
        raw = _handshake({"name": "example.com", "qtype": 1, "timeout": 1.0,
                          "prefer_addr": False, "op": "corrob", "targets": None,
                          "pool": "corrob", "rid": "live-test",
                          "rel": "other-release", "sha": "1" * 64, "proto": 2})
        self.assertEqual(raw[0:1], b"\x05")


if __name__ == "__main__":
    unittest.main()
