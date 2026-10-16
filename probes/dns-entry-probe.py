#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""入口探针 v2（服务器侧运行）：确认 §3.1 限额补丁与 §3.3 收敛后，公网入口仍正常解析。

v2 修正：
  · DoT 是 **2 字节长度前缀** 封装（RFC 7858）—— v1 未剥离前缀导致解析整体位移 2 字节
    （表现为假的 "rcode=4/TC=1"）✓ 本版按前缀读满一帧；
  · 查询带 EDNS0 + DO（RFC 3225），否则 guard 不做 DNSSEC 验证、AD 必然为 0，
    会把"探针没要验证"误判成"验证失效"；
  · DoH 用手写 HTTP/1.0 + 显式 SNI（127.0.0.1 作为 SNI 会被 00.reject-unknown-sni.conf 拒绝）。

判据：rcode=0 且 an>=1；`cloudflare.com`（带 DO）额外要求 ad=1（DNSSEC 验证链仍然成立）。
"""
from __future__ import print_function

import base64
import socket
import ssl
import struct

SNI = "dns.example.com"


def build(name, qtype=1, qid=0x1234, do=True, bufsize=1232):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    ar = 1 if do else 0
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, ar) + qn + struct.pack("!HH", qtype, 1)
    if do:
        # OPT: root name(1) + type=A|41 + class=bufsize + ttl=DO(0x8000) + rdlen=0
        msg += b"\x00" + struct.pack("!HHIH", 41, bufsize, 0x8000, 0)
    return msg


def summary(d):
    _qid, flags, _qd, an, _ns, ar = struct.unpack("!HHHHHH", d[:12])
    return "len=%d rcode=%d an=%d ns=%d ar=%d ad=%d tc=%d" % (
        len(d), flags & 0xF, an, _ns, ar,
        1 if flags & 0x20 else 0, 1 if flags & 0x200 else 0)


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def dot(host, port, name):
    ctx = ssl.create_default_context()      # 严格：CERT_REQUIRED + check_hostname（F3）

    s = socket.create_connection((host, port), 6)
    ss = ctx.wrap_socket(s, server_hostname=SNI)
    q = build(name)
    ss.sendall(struct.pack("!H", len(q)) + q)
    head = _read_exact(ss, 2)                 # DoT 长度前缀
    if len(head) < 2:
        ss.close()
        raise RuntimeError("DoT 未收到长度前缀")
    n = struct.unpack("!H", head)[0]
    body = _read_exact(ss, n)
    ss.close()
    return body


def doh_http10(host, port, name, path="/dns-query"):
    ctx = ssl.create_default_context()      # 严格：CERT_REQUIRED + check_hostname（F3）

    s = socket.create_connection((host, port), 6)
    ss = ctx.wrap_socket(s, server_hostname=SNI)
    b = base64.urlsafe_b64encode(build(name)).decode().rstrip("=")
    req = ("GET %s?dns=%s HTTP/1.0\r\nHost: %s\r\nAccept: application/dns-message\r\n\r\n"
           % (path, b, SNI))
    ss.sendall(req.encode())
    data = b""
    while True:
        chunk = ss.recv(4096)
        if not chunk:
            break
        data += chunk
    ss.close()
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        raise RuntimeError("DoH 无 HTTP 头: %r" % data[:80])
    status = head.split(b"\r\n")[0]
    return status, body


ENDPOINTS = (
    ("dot853", lambda n: dot("127.0.0.1", 853, n)),
    ("doh444", lambda n: doh_http10("127.0.0.1", 444, n)[1]),
    ("doh443", lambda n: doh_http10("127.0.0.1", 443, n)[1]),
)


def main():
    bad = 0
    for name in ("cloudflare.com", "www.qq.com"):
        want_ad = name.startswith("cloudflare")
        for label, fn in ENDPOINTS:
            try:
                d = fn(name)
                flags = struct.unpack("!H", d[2:4])[0]
                rcode = flags & 0xF
                an = struct.unpack("!H", d[6:8])[0]
                ad = 1 if flags & 0x20 else 0
                ok = (rcode == 0 and an >= 1 and (not want_ad or ad == 1))
                print("%s %-7s %-15s %s" % ("OK  " if ok else "BAD ", label, name, summary(d)))
                if not ok:
                    bad += 1
            except Exception as exc:
                print("FAIL %-7s %-15s %s" % (label, name, exc))
                bad += 1
    print("RESULT: %s" % ("ALL OK" if bad == 0 else "%d failure(s)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
