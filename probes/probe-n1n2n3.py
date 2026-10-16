# -*- coding: utf-8 -*-
"""发布 10（N1/N2/N3）生效核查：路由类别、TXT 正答案、见证来源、指标。

用法（服务器上）：python3 probe-n1n2n3.py [随机后缀]
输出每行：查询名 | qtype | 各源 rcode/an/ad
"""
import json
import random
import socket
import struct
import sys
import time

TAGS = ("CN-SUFFIX", "CN-BRAND", "EXCEPTION", "NORMAL")


def nw(n):
    out = b""
    for lab in n.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def build(name, qtype=1, do=True):
    qid = random.randint(1, 65535)
    opt = struct.pack("!HHIH", 41, 1232, 0x8000 if do else 0, 0) if do else b""
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if opt else 0)
    return qid, hdr + nw(name) + struct.pack("!HH", qtype, 1) + opt


def parse(data):
    if not data or len(data) < 12:
        return ("empty",)
    rcode = data[3] & 0xF
    ad = bool(data[3] & 0x20)
    tc = bool(data[2] & 0x02)
    an = struct.unpack("!H", data[6:8])[0]
    return (rcode, an, ad, tc)


def udp(host, port, name, qtype=1, do=True, timeout=4.0):
    qid, q = build(name, qtype, do)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (host, port))
        t0 = time.time()
        while time.time() - t0 < timeout:
            d, _ = s.recvfrom(4096)
            if len(d) >= 2 and struct.unpack("!H", d[:2])[0] == qid:
                return parse(d)
        return ("timeout",)
    except socket.timeout:
        return ("timeout",)
    except Exception as e:
        return ("err:" + type(e).__name__,)
    finally:
        s.close()


def main():
    rnd = sys.argv[1] if len(sys.argv) > 1 else str(random.randint(10000, 99999))
    cases = [
        ("CN-SUFFIX", "zz-n1-%s.cn" % rnd, 1),
        ("CN-SUFFIX", "zz-n1-%s.com.cn" % rnd, 1),
        ("CN-BRAND", "zz-n1-%s.alibaba" % rnd, 1),
        ("EXCEPTION", "zz-n1-%s.tiktokcdn-us.com" % rnd, 1),
        ("NORMAL", "www.qq.com", 1),
        ("NORMAL", "cloudflare.com", 16),
        ("NORMAL", "tiktok.com", 16),
    ]
    print("随机标签：%s" % rnd)
    print("%-11s %-38s %-5s | %-22s | %-22s | %s" % ("类别", "查询名", "qtype", "guard 172.18.0.1:5355", "AGH 172.18.0.2:53", "B 127.0.0.1:5354"))
    for tag, name, qt in cases:
        g = udp("172.18.0.1", 5355, name, qt)
        a = udp("172.18.0.2", 53, name, qt)
        b = udp("127.0.0.1", 5354, name, qt)
        fmt = lambda r: ("rc=%s an=%s ad=%s" % (r[0], r[1] if len(r) > 1 else "-",
                                                r[2] if len(r) > 2 else "-")) + (" tc" if len(r) > 3 and r[3] else "")
        print("%-11s %-38s %-5s | %-22s | %-22s | %s" % (tag, name, qt, fmt(g), fmt(a), fmt(b)))
    print()
    print("判定要点：")
    print("  CN-SUFFIX/NORMAL(www.qq.com) ⇒ guard 应给 NOERROR（走国内路径，rc=0）；")
    print("  EXCEPTION ⇒ guard 不应把国内上游的污染答案下发（rc=2/3 或来自境外源）；")
    print("  cloudflare.com TXT / tiktok.com TXT ⇒ 正答案必须 rc=0 且 an>=1（N2 修复点）。")
    try:
        st = json.load(open("/opt/dnsguard/stats.json"))
        keys = ("cn_trust_class_suffix", "cn_trust_class_allow", "cn_trust_class_witness",
                "cn_trust_bypass", "cn_trust_witness", "cn_witness_secure_ad_declared",
                "denial_proof_answered", "cn_dom_witness_bypass", "cn_dom_exception",
                "cn_list_gen_change", "cn_list_gen_change_trust", "adm_cache_gen_mismatch",
                "cn_typed_active", "cn_typed_snapshot_used", "cn_typed_fallback_denied")
        print()
        print("stats.json 关键指标：")
        for k in keys:
            if k in st:
                print("  %-30s %s" % (k, st[k]))
    except Exception as e:
        print("stats.json 读取失败：%s" % e)


if __name__ == "__main__":
    main()
