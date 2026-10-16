# -*- coding: utf-8 -*-
"""N3 隔离验证：运营方「声明 AD」是否被当作「本地验证器已确认」。

不碰生产进程：只 import 发布目录里的 alt_adapter / answer_policy，在内存里构造报文。

构造三类输入（都带 DO 请求下的回答形态）：
  P1 正答案 + AD=1 + **无 RRSIG**：真实验证器不会这样置位；若被判 SECURE ⇒ 说明
     "运营方声明"与"本机独立验证"在代码里没有被区分（N3 要校准的点）。
  P2 正答案 + AD=0 + 无 RRSIG            ⇒ 应 ACCEPTED。
  P3 SERVFAIL + OPT EDE=15(DNSSEC Bogus)  ⇒ 应 BOGUS。
用法：python probe-ad-declared.py <发布目录>
"""
import io
import os
import struct
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import alt_adapter as A  # noqa: E402
import answer_policy as P  # noqa: E402


def nw(n):
    out = b""
    for lab in n.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def rr(owner, rtype, rdata, ttl=300):
    return nw(owner) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def resp(qname, qtype, answers=(), rcode=0, ad=False, opt_ede=None):
    flags = 0x8000 | (0x0020 if ad else 0) | (rcode & 0xF)
    ar = 0
    extra = b""
    if opt_ede is not None:
        ar = 1
        ede = struct.pack("!HH", 15, opt_ede)
        extra = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(ede)) + ede
    hdr = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, ar)
    return hdr + nw(qname) + struct.pack("!HH", qtype, 1) + b"".join(answers) + extra


def show(tag, wire, qtype=1, src="witness"):
    a = A.classify_response(wire, src)
    if a is None:
        print("%-46s classify=None" % tag)
        return
    print("%-46s verdict=%-9s source=%-8s ttl=%s valid_until=%s dnssec_bogus=%s"
          % (tag, a.verdict.value, a.source, getattr(a, "ttl", "-"),
             getattr(a, "valid_until", "-"), A.dnssec_bogus(wire)))


def main():
    print("=== N3 隔离验证（%s）===" % ROOT)
    pos = [rr("ad.example", 1, b"\x01\x02\x03\x04")]
    p1 = resp("ad.example", 1, pos, rcode=0, ad=True)          # 声明 AD、无 RRSIG
    p2 = resp("ad.example", 1, pos, rcode=0, ad=False)
    p3 = resp("bad.example", 1, [], rcode=2, ad=False, opt_ede=15)
    show("P1 正答案 AD=1 无 RRSIG（来源=witness）", p1)
    show("P1 正答案 AD=1 无 RRSIG（来源=local-a）", p1, src="local-a")
    show("P2 正答案 AD=0 无 RRSIG", p2)
    show("P3 SERVFAIL + EDE 15", p3)
    a1 = A.classify_response(p1, "witness")
    print()
    print("结论：声明 AD 的见证响应被判 %s（verdict=%s）——"
          % ("为可采纳的加密答案" if a1 and a1.verdict in (P.Verdict.SECURE, P.Verdict.ACCEPTED) else "未采纳",
             a1.verdict.value if a1 else None))
    print("      本路径下「运营方声明 AD」与「本机验证器独立确认」在 verdict 上不可区分；")
    print("      发布 10 的修正是**来源标签**（witness）与独立计数 cn_witness_secure_ad_declared，")
    print("      使这项差别在指标/审计里可分；是否把 witness 结论强制降级为 ACCEPTED 留给下一轮决策。")


if __name__ == "__main__":
    main()
