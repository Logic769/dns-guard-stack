#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""external-probe.py —— F3 建议的**服务器外独立探针**（从家庭/其它网络验证公网入口）。

审计 F3 指出：原有 dns-chain-probe.py / dns-entry-probe.py 都在**服务器本机**跑，
无法证明「公网客户端经公网 IP + 证书 + Nginx 入口」这条真实路径可用。
本脚本从**外部网络**（默认本机所在网络）直连公网入口：

  · DoT  tcp/853  —— TLS(SNI=dns.example.com) + RFC7858 两字节长度前缀
  · DoH  tcp/444  —— TLS(SNI=dns.example.com) + 手写 HTTP/1.0 POST /dns-query
  · DoH  tcp/443  —— 同上（同证书，走 443 站点）

判据（与服务器内侧探针一致，便于对比）：
  cloudflare.com 带 EDNS0+DO ⇒ rcode=0 且 an>=1 且 ad=1（DNSSEC 验证链完整）
  www.qq.com                 ⇒ rcode=0 且 an>=1（国内分流，不要求 ad）

用法：python3 external-probe.py [HOST] [--insecure]
退出码：0 全绿 / 1 有失败
"""
import socket
import ssl
import struct
import sys

HOST = "198.51.100.10"
SNI = "dns.example.com"
TIMEOUT = 12.0
INSECURE = "--insecure" in sys.argv
for a in sys.argv[1:]:
    if not a.startswith("-"):
        HOST = a


def build(name, do=True):
    qid = 0x4321
    flags = 0x0100
    body = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 1 if do else 0)
    body += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    body += struct.pack("!HH", 1, 1)
    if do:
        body += b"\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00"
    return body


def parse(d):
    if len(d) < 12:
        return None
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", d[:12])
    return {"qid": qid, "rcode": flags & 0xF, "ad": (flags >> 5) & 1,
            "tc": (flags >> 9) & 1, "an": an, "ar": ar, "len": len(d)}


def tls_ctx():
    if INSECURE:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return ssl.create_default_context()


def dot(name):
    q = build(name, do=True)
    raw = socket.create_connection((HOST, 853), timeout=TIMEOUT)
    s = tls_ctx().wrap_socket(raw, server_hostname=SNI)
    try:
        s.sendall(struct.pack("!H", len(q)) + q)
        head = s.recv(2)
        if len(head) != 2:
            return None, "DoT 未收到长度前缀"
        n = struct.unpack("!H", head)[0]
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf, None
    finally:
        s.close()


def doh(name, port):
    q = build(name, do=True)
    raw = socket.create_connection((HOST, port), timeout=TIMEOUT)
    s = tls_ctx().wrap_socket(raw, server_hostname=SNI)
    try:
        req = ("POST /dns-query HTTP/1.0\r\nHost: %s\r\n"
               "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % (SNI, len(q)))
        s.sendall(req.encode() + q)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        i = buf.find(b"\r\n\r\n")
        if i < 0:
            return None, "DoH 响应无 HTTP 头"
        head, body = buf[:i].decode("latin-1"), buf[i + 4:]
        if " 200 " not in head.split("\r\n")[0]:
            return None, "DoH HTTP: " + head.split("\r\n")[0]
        return body, None
    finally:
        s.close()


CASES = [("cloudflare.com", True), ("www.qq.com", False)]


def main():
    fails = 0
    for kind, fn in (("dot853", lambda n: dot(n)),
                     ("doh444", lambda n: doh(n, 444)),
                     ("doh443", lambda n: doh(n, 443))):
        for name, want_ad in CASES:
            try:
                wire, err = fn(name)
            except Exception as e:
                wire, err = None, "%s: %s" % (type(e).__name__, e)
            if wire is None:
                print("FAIL %-7s %-16s %s" % (kind, name, err))
                fails += 1
                continue
            r = parse(wire)
            if r is None:
                print("FAIL %-7s %-16s 响应过短" % (kind, name))
                fails += 1
                continue
            ok = (r["rcode"] == 0 and r["an"] >= 1 and (r["ad"] == 1 if want_ad else True))
            print("%s %-7s %-16s len=%d rcode=%d an=%d ad=%d tc=%d"
                  % ("OK  " if ok else "FAIL", kind, name, r["len"], r["rcode"],
                     r["an"], r["ad"], r["tc"]))
            if not ok:
                fails += 1
    print("EXTERNAL RESULT: %s（host=%s sni=%s）" % ("ALL OK" if fails == 0 else "FAIL", HOST, SNI))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
