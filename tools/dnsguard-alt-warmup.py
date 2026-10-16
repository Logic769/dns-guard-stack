#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""预热 unbound-alt（Task 1）：让 root / 常用 TLD 的 DS·DNSKEY 与 bogus 样本常驻缓存。
目的：
  ① 故障切换（Task 4）时 alt 首查不再付"全链首建"代价（实测冷启动头 2 个查询 >10 s，
     预热后新区首查 ≈0.5–1.5 s、暖区 ≈0–1 ms）；
  ② 让容器健康检查的"bogus 2 秒内 SERVFAIL"断言稳定成立（否则容器重启后的头几个周期会 flapping）。
只读：只发 DNS 查询，不写任何状态。EDNS0 DO 位必须带，否则 AD 无意义。
"""
import random, socket, struct, sys, time

ADDR = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5357

# (name, qtype) —— 覆盖 root、常用 TLD 的 DS、签名域、bogus 样本、国内/境外代表
NAMES = [
    (".", 2), (".", 48),            # root NS / DNSKEY
    ("com", 43), ("org", 43), ("net", 43), ("cn", 43),   # TLD DS（取回 DS 也会拉起 DNSKEY）
    ("cloudflare.com", 1), ("example.com", 1), ("iana.org", 1),
    ("www.qq.com", 1), ("www.baidu.com", 1), ("www.google.com", 1),
    ("dnssec-failed.org", 1),       # bogus 样本：保持其"校验失败"状态常驻
]

def mk(name, qt):
    qid = random.randint(0, 65535)
    h = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    if name == ".":
        q = b"\x00"
    else:
        q = b"".join(struct.pack("B", len(l)) + l.encode() for l in name.split(".") if l) + b"\x00"
    return h + q + struct.pack("!HH", qt, 1) + b"\x00" + struct.pack("!HHIH", 41, 4096, 0x00008000, 0)

def go(name, qt, to=6.0):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(to)
    try:
        s.sendto(mk(name, qt), (ADDR, PORT))
        d, _ = s.recvfrom(4096)
        rc = struct.unpack("!HHHHHH", d[:12])[1] & 0xF
        return "rc%d" % rc, (time.time() - t0) * 1000
    except Exception as e:
        return "ERR:%s" % type(e).__name__, (time.time() - t0) * 1000
    finally:
        s.close()

ok = 0
slow = 0
for name, qt in NAMES:
    r, ms = go(name, qt)
    if r.startswith("rc"):
        ok += 1
    if ms > 2000:
        slow += 1
print("warmup: %d/%d 有应答, %d 个 >2s (%.1fs)" % (ok, len(NAMES), slow, time.time() % 1000))
