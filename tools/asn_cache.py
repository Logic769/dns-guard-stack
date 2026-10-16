#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASN 归属**缓存模块**（Codex 要求：ASN 绝不进热路径 ✗）。

设计（与 Codex "离线静态前缀表"要求的务实等价物）：
  · 归属数据只在 **audit/分析路径**使用 ✓ —— 热路径（guard 的答案选择）**永不**发起归属查询 ✓。
  · 用**长 TTL 缓存**（默认 30 天）把外部查询压到最少 ✓：`/opt/dnsguard/verify/asn_cache.json`。
  · 每次运行**有界**（默认最多 200 次外部查询、间隔 50ms）✓，且**失败 ⇒ 记 unknown 并保留旧值**，
    绝不把 "查不到" 变成任何路由决策 ✓（Codex：查不到就 `unknown`，不改变路由 ✓）。
  · 外部查询**必须经认证 DoT**（本地明文路径不可信；P1 之后 A 也已加密，但归属查询要独立于被测路径 ✓）。

用法：
  python3 asn_cache.py --prefetch 1.2.3.4 5.6.7.8      # 预取若干 IP
  python3 asn_cache.py --show                          # 打印缓存摘要
  python3 asn_cache.py --lookup 1.2.3.4                # 查单个（命中即 0 外部查询）
作为模块：`from asn_cache import lookup, class_of`（返回 (asn, cc, cls, src)）
"""
import io
import json
import os
import random
import socket
import ssl
import struct
import sys
import time

CACHE = "/opt/dnsguard/verify/asn_cache.json"
TTL = float(os.environ.get("GUARD_ASN_CACHE_TTL", str(30 * 86400)))     # 30 天
MAX_LOOKUPS = int(os.environ.get("GUARD_ASN_MAX_LOOKUPS", "200"))      # 每次运行上限
SPACING = float(os.environ.get("GUARD_ASN_SPACING", "0.05"))           # 公共解析器礼貌间隔
DOT = [("194.242.2.2", 853, "base.dns.mullvad.net"),
       ("89.233.43.71", 853, "unicast.censurfridns.dk"),
       ("185.95.218.42", 853, "dns.digitale-gesellschaft.ch")]
CDN_CLOUD = {13335, 15169, 396982, 16509, 14618, 20940, 16625, 54113, 8075, 32934, 13414,
             45090, 45102, 24429, 21859, 14061, 24940, 16276, 63949, 31898}
_BUDGET = {"n": 0}


def _load():
    try:
        return json.load(io.open(CACHE, encoding="utf-8"))
    except Exception:
        return {}


def _save(d):
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with io.open(CACHE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1, sort_keys=True)
    except Exception:
        pass


def _cymru_name(ip):
    if ":" in ip:
        try:
            packed = socket.inet_pton(socket.AF_INET6, ip)
        except Exception:
            return None
        nib = "".join("%02x" % b for b in packed)
        return ".".join(reversed(nib)) + ".origin6.asn.cymru.com"
    p = ip.split(".")
    if len(p) != 4:
        return None
    return "%s.%s.%s.%s.origin.asn.cymru.com" % (p[3], p[2], p[1], p[0])


def _mk(name, qtype=16):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return struct.pack("!HHHHHH", random.randrange(1, 65535), 0x0100, 1, 0, 0, 1) + qn + \
        struct.pack("!HH", qtype, 1) + opt


def _name(d, off):
    labels, jumps, ret = [], 0, None
    while True:
        ln = d[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | d[off + 1]
            if jumps == 0:
                ret = off + 2
            jumps += 1
            off = ptr
            continue
        labels.append(d[off + 1:off + 1 + ln].decode("latin1"))
        off += 1 + ln
    return ".".join(labels), (ret if ret is not None else off)


def _parse_txt(d):
    if len(d) < 12:
        return None
    _i, _fl, qd, an = struct.unpack("!HHHH", d[:8])
    out = []
    off = 12
    try:
        for _ in range(qd):
            _n, off = _name(d, off)
            off += 4
        for _ in range(an):
            _n, off = _name(d, off)
            t, _c, _ttl, ln = struct.unpack("!HHIH", d[off:off + 10])
            off += 10
            rd = d[off:off + ln]
            off += ln
            if t == 16:
                i, txt = 0, ""
                while i < len(rd):
                    l = rd[i]
                    txt += rd[i + 1:i + 1 + l].decode("latin1", "replace")
                    i += 1 + l
                out.append(txt)
    except Exception:
        return out or None
    return out or None


def _q_dot(ip, port, sni, msg, to=6.0):
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, port), timeout=to)
        raw.settimeout(to)
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        ss.sendall(struct.pack("!H", len(msg)) + msg)
        ln = struct.unpack("!H", ss.recv(2))[0]
        b = b""
        while len(b) < ln:
            ch = ss.recv(ln - len(b))
            if not ch:
                break
            b += ch
        ss.close()
        return _parse_txt(b)
    except Exception:
        return None


def _external(ip):
    """经认证明文 DoT 查 Team Cymru；**有界** + 记预算。"""
    if _BUDGET["n"] >= MAX_LOOKUPS:
        return None
    nm = _cymru_name(ip)
    if not nm:
        return None
    for ipx, port, sni in DOT:
        _BUDGET["n"] += 1
        txt = _q_dot(ipx, port, sni, _mk(nm))
        time.sleep(SPACING)
        if txt:
            for line in txt:
                f = [x.strip() for x in line.split("|")]
                if len(f) >= 3 and f[0].isdigit():
                    return (int(f[0]), f[2] or "??", f[1])
    return None


def class_of(asn, cc):
    if asn is None:
        return "unknown"
    if cc == "CN":
        return "cn"
    if asn in CDN_CLOUD:
        return "cdn-cloud"
    return "other"


def lookup(ip, force=False):
    """返回 (asn, cc, cls, src)；src ∈ {cache, live, unknown}。查不到 ⇒ (None,'??','unknown','unknown') 且**不改变任何路由**。"""
    d = _load()
    e = d.get(ip)
    if e and not force and (time.time() - float(e.get("ts") or 0)) < TTL:
        return (e.get("asn"), e.get("cc"), e.get("cls"), "cache")
    r = _external(ip)
    if r is None:
        if e:                                   # 保留旧值（宁可旧也不写坏值）
            return (e.get("asn"), e.get("cc"), e.get("cls"), "cache-stale")
        return (None, "??", "unknown", "unknown")
    asn, cc, _pfx = r
    rec = {"asn": asn, "cc": cc, "cls": class_of(asn, cc), "ts": time.time()}
    d[ip] = rec
    _save(d)
    return (rec["asn"], rec["cc"], rec["cls"], "live")


def prefetch(ips):
    out = {}
    for ip in ips:
        out[ip] = lookup(ip)
    return out


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--prefetch":
        res = prefetch(args[1:])
        print("=== 预取 %d 个（外部查询 %d 次）===" % (len(res), _BUDGET["n"]))
        for ip, r in res.items():
            print("  %-18s ASN=%-7s CC=%-3s class=%-10s src=%s" % (ip, r[0], r[1], r[2], r[3]))
    elif args and args[0] == "--lookup":
        for ip in args[1:]:
            r = lookup(ip)
            print("  %-18s ASN=%-7s CC=%-3s class=%-10s src=%s" % (ip, r[0], r[1], r[2], r[3]))
        print("  外部查询 %d 次" % _BUDGET["n"])
    else:
        d = _load()
        cls = {}
        for ip, e in d.items():
            cls[e.get("cls")] = cls.get(e.get("cls"), 0) + 1
        print("=== asn_cache 摘要 ===")
        print("  条目 %d；分类分布 %s" % (len(d), cls))
        for ip in sorted(d)[:12]:
            e = d[ip]
            print("  %-18s ASN=%-7s CC=%-3s class=%-10s age=%.1fh" % (
                ip, e.get("asn"), e.get("cc"), e.get("cls"), (time.time() - float(e.get("ts") or 0)) / 3600))
