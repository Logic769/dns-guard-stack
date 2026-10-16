#!/usr/bin/env python3
# verify_effect.py —— 修复有效性快速验证（只读；反样本/正样本/分流/TTL 时效/计数）
import json, socket, struct, sys, time

GUARD = ("172.18.0.2", 53)
STATS = "/opt/dnsguard/stats.json"


def qwire(name, qtype=1, rid=0x1234):
    w = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", rid, 0x0100, 1, 0, 0, 0) + w + struct.pack("!HH", qtype, 1)


def skip_name(buf, i):
    while True:
        l = buf[i]
        if l == 0:
            return i + 1
        if l & 0xC0 == 0xC0:
            return i + 2
        i += 1 + l


def query(name, qtype=1, timeout=6.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(qwire(name, qtype), GUARD)
    d, _ = s.recvfrom(4096)
    s.close()
    flags = struct.unpack("!H", d[2:4])[0]
    an = struct.unpack("!H", d[6:8])[0]
    i = skip_name(d, 12) + 4
    ttls = []
    for _ in range(an):
        i = skip_name(d, i)
        if i + 10 > len(d):
            break
        t, cls, ttl, rdl = struct.unpack("!HHIH", d[i:i + 10])
        i += 10 + rdl
        ttls.append(ttl)
    return {"rcode": flags & 0x0F, "ad": bool(flags & 0x0020), "an": an,
            "ttl_min": (min(ttls) if ttls else None), "bytes": len(d)}


def counts():
    try:
        s = json.load(open(STATS))
    except Exception as e:
        return {"_err": str(e)}
    keys = ("ttl_src_wire", "hot_skip_ttl", "hot_skip_stale", "dnssec_bogus", "fc_unbound_servfail",
            "udp_qid_mismatch", "neg_cache_hit", "neg_cache_skip_zero_ttl", "cn_local", "cn_foreign",
            "cn_dom_accepted", "cn_b_denied", "fin_ok_local-alt", "corrob_ok", "corrob_error",
            "verifier_release_mismatch", "ttl_zero_a", "ttl_zero_cn", "adm_cache_hit", "adm_cache_expired")
    return {k: s.get(k) for k in keys}


print("=== 0) 基线计数 ===")
c0 = counts()
print(" ", json.dumps(c0, ensure_ascii=False))

print("\n=== 1) F4 反样本：真 bogus 必须 SERVFAIL（rcode=2）===")
for n in ("dnssec-failed.org",):
    r = query(n)
    print("  %-22s rcode=%s an=%s ad=%s %s" % (n, r["rcode"], r["an"], r["ad"],
                                               "PASS" if r["rcode"] == 2 else "FAIL"))

print("\n=== 2) F4 正样本：正常 DNSSEC 不得被误伤（期望 NOERROR + AD=1）===")
for n in ("cloudflare.com", "ietf.org"):
    r = query(n)
    print("  %-22s rcode=%s an=%s ad=%s ttl_min=%s %s" % (n, r["rcode"], r["an"], r["ad"], r["ttl_min"],
                                                          "PASS" if r["rcode"] == 0 and r["ad"] else "CHECK"))

print("\n=== 3) F7 分流样本：国内仍国内、境外仍境外 ===")
for n in ("www.baidu.com", "www.qq.com", "google.com", "github.com"):
    r = query(n)
    print("  %-22s rcode=%s an=%s ttl_min=%s" % (n, r["rcode"], r["an"], r["ttl_min"]))

print("\n=== 4) F1 时效：同一域名连查 3 次，出口 TTL 不得回升 ===")
seq = []
for k in range(3):
    r = query("www.qq.com")
    seq.append(r["ttl_min"])
    print("  第%d次 ttl_min=%s" % (k + 1, r["ttl_min"]))
    if k < 2:
        time.sleep(2)
ok = all(a is not None and b is not None and b <= a for a, b in zip(seq, seq[1:]))
print("  单调不回升：%s ⇒ %s" % (seq, "PASS" if ok else "CHECK（同域多 RR 或每次都回源时会波动）"))

print("\n=== 5) 计数增量（对照第 0 步）===")
time.sleep(1)
c1 = counts()
for k in c1:
    if k in c0 and c1[k] != c0[k]:
        print("  %-28s %s → %s (+%s)" % (k, c0[k], c1[k],
                                         (c1[k] - c0[k]) if isinstance(c0[k], (int, float)) else "?"))
print("  未变化的键：", [k for k in c1 if k in c0 and c1[k] == c0[k]])
