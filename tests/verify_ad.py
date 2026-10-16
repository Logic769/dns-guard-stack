#!/usr/bin/env python3
# verify_ad.py —— 带 EDNS0+DO（并请求 AD）复测 DNSSEC 正样本，避免"未协商 DNSSEC"造成的假阴性
import socket, struct

GUARD = ("172.18.0.2", 53)
HDR = "!HHHHHH"


def skip_name(buf, i):
    while True:
        l = buf[i]
        if l == 0:
            return i + 1
        if l & 0xC0 == 0xC0:
            return i + 2
        i += 1 + l


def query(name, qtype=1, do=True, req_ad=True, timeout=8.0):
    w = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    flags = 0x0100 | (0x0020 if req_ad else 0)
    ar = 1 if do else 0
    msg = struct.pack(HDR, 0x2222, flags, 1, 0, 0, ar) + w + struct.pack("!HH", qtype, 1)
    if do:
        msg += b"\x00" + struct.pack("!HHIH", 41, 4096, 0x00008000, 0)  # OPT, DO=1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, GUARD)
    d, _ = s.recvfrom(4096)
    s.close()
    f = struct.unpack("!H", d[2:4])[0]
    an = struct.unpack("!H", d[6:8])[0]
    arn = struct.unpack("!H", d[10:12])[0]
    i = skip_name(d, 12) + 4
    ttls, types = [], []
    for _ in range(an):
        i = skip_name(d, i)
        if i + 10 > len(d):
            break
        t, cls, ttl, rdl = struct.unpack("!HHIH", d[i:i + 10])
        i += 10 + rdl
        ttls.append(ttl)
        types.append(t)
    has_opt = False
    for _ in range(arn):
        i = skip_name(d, i)
        if i + 10 > len(d):
            break
        t, cls, ttl, rdl = struct.unpack("!HHIH", d[i:i + 10])
        i += 10 + rdl
        if t == 41:
            has_opt = True
    return {"rcode": f & 0x0F, "ad": bool(f & 0x0020), "tc": bool(f & 0x0200), "an": an,
            "types": types, "ttl_min": (min(ttls) if ttls else None), "opt": has_opt, "bytes": len(d)}


print("== 带 DO=1 + AD 请求（EDNS0 4096）==")
for n in ("cloudflare.com", "ietf.org", "verisigninc.com", "dnssec-failed.org"):
    r = query(n)
    print("  %-20s rcode=%s ad=%-5s an=%s types=%s ttl_min=%s opt=%s  %s"
          % (n, r["rcode"], r["ad"], r["an"], r["types"], r["ttl_min"], r["opt"],
             "PASS" if (r["rcode"] == 0 and r["ad"]) or n == "dnssec-failed.org" and r["rcode"] == 2 else "CHECK"))

print("\n== 不带 DO 对照（应为 ad=False，用于确认上一步不是假阴性）==")
for n in ("cloudflare.com",):
    r = query(n, do=False, req_ad=False)
    print("  %-20s rcode=%s ad=%-5s an=%s ttl_min=%s" % (n, r["rcode"], r["ad"], r["an"], r["ttl_min"]))
