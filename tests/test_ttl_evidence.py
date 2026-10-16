# -*- coding: utf-8 -*-
"""test_ttl_evidence.py —— 方案 §2「缓存有效期 / TTL 重放 / 证据来源」的离线用例。

现场问题（本用例逐条钉住）：
  A. **硬编码 `ttl=300.0`**（5 处调用点）⇒ `valid_until` 与报文里真实的
     RRset TTL / RRSIG 失效时间**无关** ✗ —— 短 TTL 被超期复用 ✗、长 TTL 被迫重查 ✗。
  B. **B（见证）也拿到 300s 的 `valid_until`** ✗ —— 只靠 `classify_response` 里的
     `local-b` 特判才没被采纳；现在必须由"零有效期"**结构上**保证 ✓。
  C. **证据来源错标**：`_retry_authenticated()` 把**见证通道**的字节标成 `local-a` ✗。
  D. **否定有效期凭空 60s**：`_mt`（A/AAAA 的 TTL）对否定答案恒为 0 ⇒ 落 `else 60` ✗，
     且外加强制 30s 下限 ✗ —— 完全没读 SOA ✗。
  E. **"只有 CNAME、没有 DNSSEC 证明"被当成已证明 NODATA** ✗（方案明令不算 ✓）。

全部离线、不触网 ✓、不写生产目录 ✓。
运行：PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
"""
import ast
import atexit
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
from dns_test_wire import dnssec_failure

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_SRC = os.path.join(RELEASE_DIR, "guard.py")
ALT_SRC = os.path.join(RELEASE_DIR, "alt_adapter.py")
sys.path.insert(0, RELEASE_DIR)

_TMP = tempfile.mkdtemp(prefix="ttl-evidence-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)

import alt_adapter                                        # noqa: E402
import answer_policy                                      # noqa: E402
import guard                                              # noqa: E402
from answer_policy import ACCEPTED_MAX_TTL, ACCEPT_MAX_TTL, Verdict, is_fresh   # noqa: E402

NOW = 10 ** 9
QNAME_STR = "www.example.com"
QNAME = b"\x03www\x07example\x03com\x00"
QID = 0x4321


# ---------------------------------------------------------------- 报文构造
def _name_wire(name):
    return b"".join(bytes([len(p)]) + p.encode("ascii")
                    for p in name.split(".") if p) + b"\x00"


def mk(rrs, rcode=0, ad=False, qname=QNAME_STR, qtype=1, ns_rrs=(), ar_rrs=()):
    """构造应答：`rrs` / `ns_rrs` / `ar_rrs` 为 (name, type, ttl, rdata) 列表 ✓。"""
    flags = 0x8180 | (0x20 if ad else 0) | (rcode & 0xF)
    body = _name_wire(qname) + struct.pack("!HH", qtype, 1)

    def _enc(nm, rt, ttl, rd):
        return _name_wire(nm) + struct.pack("!HHIH", rt, 1, ttl, len(rd)) + rd

    for t in rrs:
        body += _enc(*t)
    for t in ns_rrs:
        body += _enc(*t)
    for t in ar_rrs:
        body += _enc(*t)
    return (struct.pack("!HHHHHH", QID, flags, 1, len(rrs), len(ns_rrs), len(ar_rrs))
            + body)


def a_rr(name=QNAME_STR, ttl=300):
    return (name, 1, ttl, b"\x01\x02\x03\x04")


def cname_rr(name, target, ttl=60):
    return (name, 5, ttl, _name_wire(target))


def soa_rdata(mname=QNAME_STR, rname="ns." + QNAME_STR, minimum=30):
    return _name_wire(mname) + _name_wire(rname) + struct.pack("!IIIII", 1, 3600, 600,
                                                              604800, minimum)


def soa_rr(name=QNAME_STR, ttl=100, minimum=30):
    return (name, 6, ttl, soa_rdata(minimum=minimum))


def rrsig_rdata(covered=6, exp=NOW + 3600):
    return struct.pack("!HBBIIIH", covered, 8, 0, 3600, int(exp), 0, 7) + b"k"


def rrsig_rr(name=QNAME_STR, covered=6, exp=NOW + 3600, ttl=300):
    return (name, 46, ttl, rrsig_rdata(covered=covered, exp=exp))


def nsec_rr(name=QNAME_STR, ttl=100):
    return (name, 47, ttl, _name_wire("a" + QNAME_STR) + b"\x00\x06\x00\x00\x00\x00\x00")


# ---------------------------------------------------------------- A/B：报文取有效期
class ForwardValidity(unittest.TestCase):
    """正向：`valid_until` 必须来自**报文自己**的 TTL（含 CNAME 链最小值）✓。"""

    def test_uses_rrset_ttl_not_300(self):
        """有效期 = `min(报文 TTL, 策略上限)` ✓ —— 上限按裁定分档（ACC/300，SEC/900）✓。

        关键断言是「**不再是常数 300**」：短于上限时严格等于报文 TTL ✓。
        """
        for ttl in (5, 30, 120, 600, 3600):
            with self.subTest(ttl=ttl):
                t, det = alt_adapter.rrset_validity(mk([a_rr(ttl=ttl)]), now=NOW)
                self.assertEqual(det["kind"], "forward")
                self.assertEqual(t, float(ttl), "报文有效期必须原样取出（不再恒 300）")
                a = alt_adapter.classify_response(mk([a_rr(ttl=ttl)]), "local-a",
                                                  ttl=t, now=NOW)
                self.assertEqual(a.verdict, Verdict.ACCEPTED)
                want = min(float(ttl), ACCEPTED_MAX_TTL)
                self.assertAlmostEqual(a.valid_until, NOW + want, places=3,
                                       msg="ACCEPTED 上限 300s 必须生效")

    def test_secure_cap_allows_up_to_900(self):
        """SECURE 的上限是 900s ✓ —— 800s 的 TTL 必须**原样保留**（旧代码会截到 300 ✗）。"""
        w = mk([a_rr(ttl=800)], ad=True)
        t, _det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 800.0)
        a = alt_adapter.classify_response(w, "local-a", ttl=t, now=NOW)
        self.assertEqual(a.verdict, Verdict.SECURE)
        self.assertAlmostEqual(a.valid_until, NOW + 800.0, places=3)
        # 超 900 才被截
        w2 = mk([a_rr(ttl=5000)], ad=True)
        t2, _d2 = alt_adapter.rrset_validity(w2, now=NOW)
        a2 = alt_adapter.classify_response(w2, "local-a", ttl=t2, now=NOW)
        self.assertAlmostEqual(a2.valid_until, NOW + ACCEPT_MAX_TTL, places=3)

    def test_validity_is_not_a_constant(self):
        """反例守卫：若有人把有效期写回常数，跨 TTL 的取值必须同时不同 ✗→✓。"""
        vals = set()
        for ttl in (7, 61, 277, 899):
            t, _ = alt_adapter.rrset_validity(mk([a_rr(ttl=ttl)]), now=NOW)
            vals.add(t)
        self.assertEqual(len(vals), 4, "有效期必须随报文 TTL 变化（不是常数）")

    def test_zero_ttl_stays_zero_never_extended(self):
        """零 TTL 绝不被补成固定值 ✓（P1-2 同一条铁律）。"""
        t, det = alt_adapter.rrset_validity(mk([a_rr(ttl=0)]), now=NOW)
        self.assertEqual(t, 0.0)
        a = alt_adapter.classify_response(mk([a_rr(ttl=0)]), "local-a", ttl=t, now=NOW)
        self.assertFalse(is_fresh(a, now=NOW), "零 TTL 的答案必须立即判为不新鲜")

    def test_cname_chain_takes_minimum(self):
        w = mk([cname_rr(QNAME_STR, "cdn.example.net", ttl=30),
                a_rr("cdn.example.net", ttl=900)])
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 30.0, "CNAME 链必须取最小值，不能只看最终 RRset")
        self.assertIn(QNAME_STR, det["chain"])
        self.assertIn("cdn.example.net", det["chain"])

    def test_rrsig_signature_expiry_lowers_validity(self):
        """方案：「对使用的 DNSSEC 证明检查签名失效时间」✓ ⇒ 取 min(TTL, 签名剩余) ✓。"""
        w = mk([a_rr(ttl=3600)], ad=True,
               ns_rrs=(), ar_rrs=())
        w = mk([a_rr(ttl=3600), rrsig_rr(covered=1, exp=int(NOW) + 120, ttl=3600)], ad=True)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(det["sig_rem"], 120.0)
        self.assertEqual(t, 120.0, "签名剩余 120s ⇒ 有效期必须被压到 120s")

    def test_signature_of_unused_type_is_ignored(self):
        """只算**被使用过**的那类签名 ✓ —— 无关类型的签名不参与取 min ✓。"""
        w = mk([a_rr(ttl=600), rrsig_rr(covered=28, exp=int(NOW) + 5)], ad=True)
        t, _det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 600.0, "覆盖 AAAA 的签名不该影响 A 查询的有效期")

    def test_incomplete_chain_is_not_reused(self):
        """有 CNAME 但走不到目标类型 ⇒ 不得给有效期 ✗（宁可不缓存 ✓）。"""
        w = mk([cname_rr(QNAME_STR, "void.example.net", ttl=300)], qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 0.0, "残缺链绝不能凭空获得有效期")
        self.assertEqual(det["kind"], "incomplete")
        self.assertNotEqual(det["kind"], "forward")


class _CompressedWire(object):
    """按**真实上游**写法构造报文：名字用**压缩指针**，指针值 = 整报文绝对偏移 ✓。

    现场事故（本节用例的来源）：真实 CDN 应答里 CNAME 的 RDATA 形如
        `c0 16`   （指针 → 报文中已有后缀）
    而当时的实现用 `_read_name(rr["rdata"], 0)` —— **在 rdata 切片上**跟随指针 ✗
    ⇒ 越界 ⇒ 目标名解析失败 ⇒ CNAME 链只走 1 跳 ⇒ `kind="incomplete"` ⇒ 有效期 0 ✗。
    受害实测：`www.baidu.com` / `www.taobao.com` / `www.bilibili.com` ✓
    （`www.qq.com` 因目标名**未压缩**而侥幸通过 ⇒ 掩盖了 bug ✗）。
    """

    def __init__(self, qname, qtype=1, flags=0x8180):
        self.qname = qname.lower()
        self.qtype = qtype
        self.buf = bytearray(struct.pack("!HHHHHH", QID, flags, 1, 0, 0, 0))
        self.suffix = {}
        self.counts = {"an": 0, "ns": 0, "ar": 0}
        self._reg(self.qname, 12)
        self.buf += _name_wire(qname) + struct.pack("!HH", qtype, 1)

    def _reg(self, name, off):
        """登记 `name` 及其各级后缀在报文中的**起始偏移** ✓。"""
        parts = [p for p in name.lower().split(".") if p]
        o = off
        for i in range(len(parts)):
            self.suffix.setdefault(".".join(parts[i:]), o)
            o += 1 + len(parts[i])

    def _enc(self, name, off):
        """编码名字：能压缩的部分一律用**指针**（最长后缀优先）✓ —— 与上游行为一致 ✓。"""
        parts = [p for p in name.lower().split(".") if p]
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix in self.suffix:
                o = off
                for j in range(i):          # 前导标签按字面写，并登记其自身的后缀 ✓
                    self.suffix.setdefault(".".join(parts[j:]), o)
                    o += 1 + len(parts[j])
                head = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts[:i])
                return head + struct.pack("!H", 0xC000 | self.suffix[suffix])
        self._reg(name, off)                # 全新名字 ⇒ 整体写字面并登记 ✓
        return _name_wire(name)

    def add(self, owner, rtype, ttl, rdata=None, sec="an"):
        """加一条 RR；`rdata` 为 callable 时传 `(builder, rdata_abs_off)` ⇒ 可写压缩指针 ✓。"""
        self.buf += self._enc(owner, len(self.buf))
        self.buf += struct.pack("!HHIH", rtype, 1, ttl, 0)
        rd_off = len(self.buf)
        rd = rdata(self, rd_off) if callable(rdata) else (rdata or b"")
        self.buf += rd
        struct.pack_into("!H", self.buf, rd_off - 2, len(rd))
        self.counts[sec] += 1
        return self

    def cname(self, owner, target, ttl, sec="an"):
        return self.add(owner, 5, ttl,
                        lambda b, off: b._enc(target, off), sec=sec)

    def out(self):
        struct.pack_into("!HHH", self.buf, 6, self.counts["an"], self.counts["ns"],
                         self.counts["ar"])
        return bytes(self.buf)


def soa_rdata_compressed(b, off, minimum=30):
    """SOA 的 MNAME/RNAME 也写成压缩指针 ✓ —— 与真实 Authority 段一致 ✓。"""
    return (b._enc("ns1." + b.qname, off) + b._enc("hostmaster." + b.qname, off)
            + struct.pack("!IIIII", 1, 3600, 600, 604800, minimum))


class CompressedNameRegression(unittest.TestCase):
    """压缩指针回归 —— 这三个用例失败即表示 §2-a 在国内域名上再次退化为零有效期 ✗。"""

    def _baidu_shaped(self):
        """`www.baidu.com` 的实测形态：两级 CNAME（目标名都被压缩）✓。

        实测原始 rdata（`rd_off=43`）：`03 77 77 77 01 61 06 73 68 69 66 65 6e c0 16`
        —— `c0 16`(=22) 指向**问题名里的 `com`** ⇒ 目标是 `www.a.shifen.com` ✓。
        """
        b = _CompressedWire("www.baidu.com", 1)
        b.cname("www.baidu.com", "www.a.shifen.com", 611)
        b.cname("www.a.shifen.com", "www.wshifen.com", 30)
        b.add("www.wshifen.com", 1, 199, b"\x67\xeb\x2e\x60")
        b.add("www.wshifen.com", 1, 199, b"\x67\xeb\x2f\xbc")
        return b.out()

    def test_compressed_cname_rdata_parses_target(self):
        """核心不变量：CNAME 目标名必须按**整报文绝对偏移**解析 ✓。"""
        w = self._baidu_shaped()
        h, _q, out = alt_adapter._parse_rrs(w)
        self.assertIsNotNone(h)
        cn = out["an"][0]
        self.assertEqual(cn["type"], 5)
        self.assertTrue(any((x & 0xC0) == 0xC0 for x in cn["rdata"]),
                        "本用例要求 rdata 里含压缩指针（否则测不到该 bug）")
        # 错法：在 rdata **切片**上解析 ⇒ 失败 ✗
        bad, _ = alt_adapter._read_name(cn["rdata"], 0)
        self.assertIsNone(bad, "切片解析应当失败 —— 这正是原缺陷的形态")
        # 对法：整报文 + 绝对偏移 ⇒ 成功 ✓
        self.assertEqual(alt_adapter._cname_target(w, cn), "www.a.shifen.com")

    def test_compressed_chain_yields_real_validity(self):
        """两级压缩 CNAME 链 ⇒ 必须得到真实有效期（= 链上最小 TTL 30）✓，不再 0 ✗。"""
        t, det = alt_adapter.rrset_validity(self._baidu_shaped(), now=NOW)
        self.assertEqual(det["kind"], "forward", "压缩链必须能走通（此前误判 incomplete）")
        self.assertEqual(t, 30.0, "有效期 = min(611, 30, 199) = 30")
        self.assertEqual(det["chain"],
                         ["www.baidu.com", "www.a.shifen.com", "www.wshifen.com"])
        self.assertIsNone(det.get("reason"))

    def test_compressed_three_hop_chain(self):
        """三级压缩链（`www.bilibili.com` 形态）✓。"""
        b = _CompressedWire("www.bilibili.com", 1)
        b.cname("www.bilibili.com", "a.w.bilicdn1.com", 52)
        b.cname("a.w.bilicdn1.com", "i.w.bilicdn1.com", 6)
        b.add("i.w.bilicdn1.com", 1, 39, b"\x94\x99\x23\x42")
        t, det = alt_adapter.rrset_validity(b.out(), now=NOW)
        self.assertEqual(det["kind"], "forward")
        self.assertEqual(t, 6.0, "三级链取最小值 ⇒ 6s ✓")
        self.assertEqual(len(det["chain"]), 3)

    def test_compressed_soa_minimum_is_read(self):
        """SOA 的 MNAME/RNAME 被压缩时，MINIMUM 仍必须读到 ✓（否定有效期不再凭空归零）✓。"""
        b = _CompressedWire("nope.example.com", 1)
        b.add("example.com", 6, 100, lambda bb, off: soa_rdata_compressed(bb, off, 45),
              sec="ns")
        w = b.out()
        _h, _q, out = alt_adapter._parse_rrs(w)
        soa = out["ns"][0]
        # 旧签名（只给 rdata 切片）读不到 —— 因为 MNAME 是指针 ✗
        self.assertIsNone(alt_adapter._soa_minimum(soa["rdata"]),
                          "切片法读到指针即失败 ⇒ 这正是原缺陷")
        # 新签名（整报文 + RR）读得到 ✓
        self.assertEqual(alt_adapter._soa_minimum(w, soa), 45)

    def test_compressed_negative_validity(self):
        """否定 + 压缩 SOA + NSEC ⇒ 有效期 = min(SOA.TTL, MINIMUM) ✓ 且 proven ✓。"""
        b = _CompressedWire("nope.example.com", 1)
        b.add("example.com", 6, 100, lambda bb, off: soa_rdata_compressed(bb, off, 45),
              sec="ns")
        b.add("example.com", 47, 100, b"\x03nop\xc0\x0c\x00\x06\x00\x00\x00\x00\x00",
              sec="ns")
        t, det = alt_adapter.rrset_validity(b.out(), now=NOW)
        self.assertEqual(det["kind"], "negative")
        self.assertTrue(det["proven"], "有 NSEC ⇒ 已证明 ✓")
        self.assertEqual(det["soa_min"], 45)
        self.assertEqual(t, 45.0, "min(SOA.TTL=100, MINIMUM=45) = 45 ✓")

    def test_no_pointer_still_works(self):
        """反向守卫：目标名**未压缩**（`www.qq.com` 形态）也必须照旧正确 ✓。"""
        w = mk([cname_rr(QNAME_STR, "cdn.example.net", 30),
                a_rr("cdn.example.net", 900)])
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(det["kind"], "forward")
        self.assertEqual(t, 30.0)


class NegativeValidity(unittest.TestCase):
    """否定：有效期取 `min(SOA.TTL, SOA.MINIMUM)`（RFC 2308）✓，且必须**有证明** ✓。"""

    def test_nxdomain_uses_soa_minimum(self):
        w = mk([], rcode=3, ns_rrs=[soa_rr(ttl=100, minimum=25)], qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(det["kind"], "negative")
        self.assertEqual(t, 25.0, "SOA MINIMUM 必须是下界依据")

    def test_nxdomain_soa_ttl_is_upper_bound(self):
        w = mk([], rcode=3, ns_rrs=[soa_rr(ttl=10, minimum=900)], qtype=1)
        t, _det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 10.0, "SOA 自身 TTL 更小时取更小的那个")

    def test_no_soa_means_no_validity(self):
        w = mk([], rcode=3, ns_rrs=[], qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 0.0)
        self.assertEqual(det["reason"], "no_soa")

    def test_cname_only_negative_is_unproven(self):
        """★ 方案硬要求：只有 CNAME、没有 DNSSEC 证明 ⇒ **proven 必须为假** ✗。

        ★ release-17（§8 最终验收现场缺陷）：**"未证明"≠"不可用"** ✓ ——
          有效期取 RFC 2308 的 `min(SOA.TTL, SOA.MINIMUM)`，并加 `_NEG_UNPROVEN_TTL_CAP` 上限 ✓；
          仍**不延长**、不冒充已证明 ✓。旧行为（ttl=0）会把合法 CNAME→NODATA 变成
          客户可见的 SERVFAIL ✗（实测隔离回放：release-9 rc=0，release-12/14/16 rc=2）。
        """
        w = mk([cname_rr(QNAME_STR, "cdn.example.net", ttl=60)], rcode=0,
               ns_rrs=[soa_rr(ttl=100, minimum=60)], qtype=1)
        self.assertIsNotNone(alt_adapter._parse_rrs(w))
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        # 该报文既无地址也无终态记录 ⇒ 进否定分支，但**没有** NSEC/NSEC3、也没有 SOA 签名
        self.assertEqual(det["proven"], False, "CNAME+NODATA 未被证明 ⇒ proven 必须为假")
        self.assertEqual(det["kind"], "negative_unproven")
        self.assertEqual(det["reason"], "cname_only_soa_ttl")
        self.assertEqual(t, 60.0, "未证明的否定用 min(SOA.TTL, SOA.MINIMUM) 求有效期（不延长、不放大）")
        self.assertEqual(det["capped"], False)

    def test_cname_only_unproven_ttl_is_capped(self):
        """★ release-17：未证明否定的有效期**硬上限 300s** ✓（不因大 SOA 而放大）。"""
        w = mk([cname_rr(QNAME_STR, "cdn.example.net", ttl=60)], rcode=0,
               ns_rrs=[soa_rr(ttl=3600, minimum=1800)], qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(det["proven"], False)
        self.assertEqual(det["reason"], "cname_only_soa_ttl")
        self.assertEqual(t, 300.0, "上限 = min(soa_ttl, _NEG_UNPROVEN_TTL_CAP)")
        self.assertTrue(det["capped"])

    def test_cname_only_without_soa_stays_zero(self):
        """残缺链路（CNAME 且**连 SOA 都没有**）⇒ 仍不给有效期 ✓（宁可不缓存）。"""
        w = mk([cname_rr(QNAME_STR, "cdn.example.net", ttl=60)], rcode=0, qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t, 0.0)
        self.assertEqual(det["kind"], "incomplete")
        self.assertEqual(det["reason"], "chain_no_target_no_soa")

    def test_nsec_proves_negative(self):
        w = mk([], rcode=3, ns_rrs=[soa_rr(ttl=100, minimum=60), nsec_rr(ttl=60)], qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertTrue(det["proven"], "有 NSEC 即算已证明")
        self.assertEqual(t, 60.0)

    def test_signed_soa_proves_negative(self):
        w = mk([], rcode=3, ns_rrs=[soa_rr(ttl=100, minimum=45),
                                    rrsig_rr(covered=6, exp=int(NOW) + 30, ttl=100)],
               qtype=1)
        t, det = alt_adapter.rrset_validity(w, now=NOW)
        self.assertTrue(det["proven"], "覆盖 SOA 的 RRSIG 即算已证明")
        self.assertEqual(t, 30.0, "签名剩余 30s 比 SOA 的 45s 更小 ⇒ 取 30s")

    def test_bogus_has_no_validity(self):
        t, det = alt_adapter.rrset_validity(dnssec_failure(mk([], rcode=2)), now=NOW)
        self.assertEqual(t, 0.0)
        self.assertEqual(det["kind"], "bogus")


# ---------------------------------------------------------------- B：B 恒无有效期
class WitnessNeverValid(unittest.TestCase):

    def test_b_always_unknown_with_zero_validity(self):
        """B 恒 UNKNOWN + **恒零有效期** ✓（与传入的 ttl 无关 ✓）。"""
        for rcode, ad, answers in ((0, False, 1), (0, True, 1), (3, False, 0)):
            with self.subTest(rcode=rcode, ad=ad, answers=answers):
                w = mk([a_rr(ttl=3600)] if answers else [], rcode=rcode, ad=ad)
                b = alt_adapter.classify_response(w, "local-b", ttl=0.0, now=NOW)
                self.assertEqual(b.verdict, Verdict.UNKNOWN)
                self.assertIsNone(b.wire)
                self.assertEqual(b.valid_until, 0.0,
                                 "B 的有效期必须是 0（不是 now+ttl）")
                self.assertFalse(is_fresh(b, now=NOW))

    def test_b_ttl_is_ignored_even_if_caller_passes_huge_ttl(self):
        """防御性：即使调用方误传大 TTL，B 也拿不到可采纳的有效期 ✓。"""
        b = alt_adapter.classify_response(mk([a_rr(ttl=9999)]), "local-b", ttl=9999.0, now=NOW)
        self.assertEqual(b.verdict, Verdict.UNKNOWN)
        self.assertIsNone(b.wire)


# ---------------------------------------------------------------- 策略上限分档
class PolicyCaps(unittest.TestCase):

    def test_secure_cap_is_900_and_accepted_cap_is_300(self):
        self.assertEqual(guard._adm_cap_for(Verdict.SECURE), ACCEPT_MAX_TTL)
        self.assertEqual(guard._adm_cap_for(Verdict.ACCEPTED), ACCEPTED_MAX_TTL)
        self.assertEqual(guard._adm_cap_for("secure"), 900.0)
        self.assertEqual(guard._adm_cap_for("accepted"), 300.0)
        self.assertGreater(ACCEPT_MAX_TTL, ACCEPTED_MAX_TTL)

    def test_admission_cache_ttl_respects_verdict_cap(self):
        """准入缓存：SECURE 可到 900s，ACCEPTED 截到 300s ✓（不再一律 300 ✗）。"""
        guard._ADM_CACHE.clear()
        sec = answer_policy.make_answer(b"x" * 40, "local-a", Verdict.SECURE, 5000.0, now=0.0)
        self.assertEqual(guard._adm_ttl_from(sec, guard._adm_cap_for(sec.verdict), now=0.0), 900.0)
        acc = answer_policy.make_answer(b"y" * 40, "local-alt", Verdict.ACCEPTED, 5000.0, now=0.0)
        self.assertEqual(guard._adm_ttl_from(acc, guard._adm_cap_for(acc.verdict), now=0.0), 300.0)

    def test_zero_ttl_is_never_cached(self):
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("zero.ttl.example", 1, b"z" * 40, "accepted", "local-alt",
                             0.0, now=time_now())
        self.assertEqual(len(guard._ADM_CACHE), 0, "零 TTL 不得入准入缓存（不得被延长）")


def time_now():
    import time as _t
    return _t.time()


_SRC_CACHE = {}


def _src_lines():
    """全部源码行（1-based 行号可直接索引 ✓）。"""
    if "lines" not in _SRC_CACHE:
        _SRC_CACHE["lines"] = open(GUARD_SRC, encoding="utf-8").read().split("\n")
    return _SRC_CACHE["lines"]


def _subtree_end(node):
    """节点**子树**的最大行号 —— 3.6 没有 `end_lineno` ⇒ 自己算 ✓。

    这一步是必需的：`_seg()` 若在 3.6 上退化到"单行"，`marker in _seg(fn)`
    就永远找不到函数体里的标记 ✗（本地 3.14 有 `end_lineno` 所以看不出问题 ✗）。
    """
    hi = getattr(node, "lineno", 1) or 1
    for n in ast.walk(node):
        ln = getattr(n, "lineno", None)
        if ln and ln > hi:
            hi = ln
    return hi


def _seg(node):
    """3.6 安全的「取节点源码文本」：用行号切行，**不用** `ast.get_source_segment` ✗。

    现场坑：`ast.get_source_segment` 与 `node.end_lineno` 都是 **3.8+** ✗，
    而发布环境是 **py3.6.8** ⇒ 原实现会在服务器上直接 `AttributeError` ✗。
    """
    lines = _src_lines()
    a = max(1, getattr(node, "lineno", 1) or 1)
    b = getattr(node, "end_lineno", None) or _subtree_end(node)
    return "\n".join(lines[a - 1:max(a, b)])


def _enclosing_function(tree, marker=None, line=None):
    """找到**最内层**（源码最短的）包含 `marker` 文本或 `line` 行号的函数定义 ✓。"""
    cands = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if marker is not None and marker not in _seg(node):
            continue
        if line is not None and not (node.lineno <= line <= _subtree_end(node)):
            continue
        cands.append(node)
    if not cands:
        return None
    return min(cands, key=lambda n: len(_seg(n)))


def _num_const(node):
    """取数字字面量（兼容 3.6 `ast.Num` 与 3.8+ `ast.Constant` ✓）。"""
    nc = getattr(ast, "Num", None)
    if nc is not None and isinstance(node, nc):
        return node.n
    c = getattr(ast, "Constant", None)
    if c is not None and isinstance(node, c) and isinstance(node.value, (int, float)) \
            and not isinstance(node.value, bool):
        return node.value
    return None


# ---------------------------------------------------------------- C：来源标签
class EvidenceSource(unittest.TestCase):

    def test_witness_bucket_is_whitelisted(self):
        self.assertIn("witness", guard._SRC_WHITELIST)
        self.assertEqual(guard._src_bucket("witness"), "witness")
        self.assertEqual(guard._src_bucket("local-a"), "local-a")
        self.assertEqual(guard._src_bucket("local-b"), "local-b")

    def test_retry_authenticated_labels_witness_truthfully(self):
        """★ 来源不得错标：见证通道的字节不能被当成 `local-a` ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_retry_authenticated":
                fn = node
        self.assertIsNotNone(fn, "必须仍存在 _retry_authenticated()")
        seg = _seg(fn)
        self.assertIn('_alt_classify(_rawretry, "witness")', seg,
                      "见证重试必须标为 witness，而不是 local-a")
        self.assertNotIn('_rawretry, "local-a"', seg)

    def test_no_hardcoded_ttl_300_call_remains(self):
        """A：`classify_response(..., ttl=300.0)` 的 5 处调用点必须全部消失 ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute) and f.attr == "classify_response":
                    for kw in node.keywords:
                        if kw.arg == "ttl" and _num_const(kw.value) == 300.0:
                            bad.append(node.lineno)
        self.assertEqual(bad, [], "仍有硬编码 ttl=300.0 的 classify_response 调用: %r" % bad)

    def test_alt_classify_is_the_route(self):
        src = open(GUARD_SRC, encoding="utf-8").read()
        self.assertIn("def _alt_classify(wire, source, now=None):", src)
        self.assertIn("rrset_validity", src)

    def test_query_alt_does_not_hardcode_ttl(self):
        """★ 方案 §2 第 42 行**点名**了 `alt_adapter.py::query_alt` ⇒ 它也不能写死 300 ✗。

        为什么单独测这一处：`query_alt()` 是 `_finalize_return()` 救援路径与
        `_retry_authenticated()` 的**唯一来源** ⇒ 它固定 300 就等于"所有走备用的答案
        寿命 300s" ✗（短 TTL 的 CDN 名被延长、长 TTL 的稳定名被迫重查 ✗）。
        注意本文件里的调用是**裸名** `classify_response(...)`（同模块内），
        不是 `X.classify_response(...)` ⇒ 上面的 Attribute 扫描抓不到它 ✗，必须单独断言 ✓。
        """
        alt_src = open(ALT_SRC, encoding="utf-8").read()
        tree = ast.parse(alt_src)
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if (isinstance(f, ast.Name) and f.id == "classify_response") or \
                   (isinstance(f, ast.Attribute) and f.attr == "classify_response"):
                    for kw in node.keywords:
                        if kw.arg == "ttl" and _num_const(kw.value) is not None:
                            bad.append((node.lineno, _num_const(kw.value)))
        self.assertEqual(bad, [], "alt_adapter 里仍有写死 ttl 常量的 classify_response 调用: %r" % bad)
        # 反向守卫：`query_alt()` 必须真的用 `rrset_validity` 取有效期 ✓
        # 注意：`_seg()` 固定读 `GUARD_SRC` ✗ ⇒ 对 alt_adapter 的节点必须自己切行 ✓。
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "query_alt":
                fn = node
        self.assertIsNotNone(fn, "必须仍存在 query_alt()")
        lines = alt_src.split("\n")
        seg = "\n".join(lines[fn.lineno - 1: _subtree_end(fn)])
        self.assertIn("rrset_validity", seg,
                      "query_alt() 必须从报文自身取有效期 ✗（方案 §2 第 42/49 行）")

    def test_negative_cache_no_forced_30s_floor(self):
        """D：**否定缓存所在函数**里 `max(30, ...)` 的强制下限必须消失 ✗。

        断言方式是 **AST 级**（只看可执行代码 ✓）：注释里提到旧写法是允许的 ✓。
        范围刻意**限定在含 `_neg_ttl` 的那个函数**，因为 guard 里另有若干**独立**缓存
        （R8T 类型化核对缓存 `_r8t_put`、CN 否决缓存、严格清单 TTL）也带各自的 30s 下限 ——
        它们是**别的逻辑项**（方案要求每步只改一项 ✓），故不在本条断言范围内，
        只在本文件末尾的 `test_no_answer_path_uses_forced_30s_floor` 里作为**观察项**记录 ✓。
        """
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        owner = _enclosing_function(tree, marker="_neg_ttl")
        self.assertIsNotNone(owner, "必须仍存在含 _neg_ttl 的否定缓存函数")
        seg_src = _seg(owner)
        bad = []
        for node in ast.walk(owner):
            if isinstance(node, ast.Assign):
                seg = _seg(node.value)
                if seg.startswith("max(30") or " max(30," in seg:
                    bad.append((node.lineno, seg[:70]))
        self.assertEqual(bad, [], "否定缓存不得再有 max(30, ...) 强制下限: %r" % bad)
        # 注意：计数键是**拼接**出来的（`"neg_cache_skip_" + _neg_reason`）✓
        # ⇒ 断言拼接前缀与两个 reason 字面量，而不是拼好的整串 ✗（否则永远匹配不到）。
        self.assertIn("neg_cache_skip_", seg_src)
        self.assertIn('"unproven"', seg_src)
        self.assertIn('"zero_ttl"', seg_src)
        self.assertIn("min(ttl, 900.0)", seg_src)
        self.assertIn("if expiry > 0:", seg_src)
        self.assertIn("neg_cache_store", seg_src)
        self.assertIn("_ALT.rrset_validity(uresp)", seg_src)

    def test_no_answer_path_uses_forced_30s_floor(self):
        """观察项（**不属 §2-a 的变更范围**）：把仍带 30s 强制下限的赋值点**列出来** ✓。

        这些是 R8T 核对 / CN 否决 / 严格清单各自的缓存，属后续步骤；
        本测试只做**清点**，不因它们存在而失败 —— 但一旦**答案路径**上出现新的
        `max(30, ...)`，就会出现在这份清单里并被复核 ✓。
        """
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        hits = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                seg = _seg(node.value)
                if seg.startswith("max(30") or " max(30," in seg:
                    fn = _enclosing_function(tree, line=node.lineno)
                    hits.append((node.lineno, (fn.name if fn else "?"), seg[:60]))
        # 已知的三处非答案缓存（R8T / CN 否决 / 严格清单）—— 记录其函数名，便于交叉复核 ✓
        names = sorted(set(h[1] for h in hits))
        self.assertIn("_r8t_put", names,
                      "R8T 核对缓存的 30s 下限应仍可被看见（观察项）: %r" % (hits,))
        self.assertNotIn("_adm_cache_put", names, "★答案准入缓存绝不许有 30s 强制下限 ✗")

    def test_negative_cache_uses_soa_and_proof(self):
        """否定有效期必须由 `rrset_validity()` 提供，且必须要求 `proven` ✓。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        self.assertIn("_neg_ttl", src)
        # 找到负缓存写入所在的函数，断言其中同时出现 proven 与 expiry>0 的守卫
        seg = src[src.index('_neg_ttl') - 200:]
        self.assertIn("_proven", src)
        self.assertTrue("if ttl > 0 and _proven" in src or ("_proven" in src and "ttl > 0" in src),
                        "必须同时要求 ttl>0 与 proven 才落否定缓存")
        self.assertIn("neg_cache_store", src)

    def test_guard_has_no_executable_ttl_300_default_in_adm_cache(self):
        """准入缓存的上限必须按裁定分档，不得处处写 300.0 ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name) and f.id == "_adm_ttl_from":
                    for a in list(node.args) + [k.value for k in node.keywords]:
                        if _num_const(a) == 300.0:
                            bad.append(node.lineno)
        self.assertEqual(bad, [], "仍有 _adm_ttl_from(..., 300.0) 硬编码上限: %r" % bad)


class PerRrTtlReplay(unittest.TestCase):
    """方案 §2 第 50 行：重放时**逐 RR 扣除经过秒数** ✓，且 OPT 不被损坏 ✗。

    离线必测（方案第 55 行）逐条对应：
      · "原 TTL=20，t=8 返回≤12" ⇒ 老化后每个 RR 的 TTL 必须 ≤ 剩余 ✓
      · "OPT 不被损坏" ⇒ OPT 的"TTL"字段（实为扩展 rcode/版本/flags）不得被扣减 ✗
      · "反复命中…不能延长原始期限" ⇒ 老化后重新分类得到的 `valid_until` 不得回升 ✓
    """

    def _wire_with_opt(self, ttl=20):
        """一个带 OPT 的应答 ✓（OPT 的 class=1232 payload、TTL 字段=0x00008000 DO 位）。"""
        return mk([a_rr(ttl=ttl)], ar_rrs=[("", 41, 0x8000, b"")])

    def test_age_wire_decrements_all_sections(self):
        """三段（AN/NS/AR）里除 OPT 外的 RR 全部按经过秒数扣减 ✓。"""
        w = mk([a_rr(ttl=20)], ns_rrs=[soa_rr(QNAME_STR, ttl=100, minimum=30)])
        aged = alt_adapter.age_wire(w, 8)
        _h, _q, out = alt_adapter._parse_rrs(aged)
        self.assertEqual(out["an"][0]["ttl"], 12, "TTL=20 经过 8 秒 ⇒ 剩 12 ✓")
        self.assertEqual(out["ns"][0]["ttl"], 92, "Authority 段同样要扣减 ✓")

    def test_age_wire_preserves_length_and_pointers(self):
        """★ 原地改写 ⇒ 报文长度不变 ✓ ⇒ 压缩指针仍逐字节有效 ✓。"""
        w = _CompressedWire("www.baidu.com", 1)
        w.cname("www.baidu.com", "www.a.shifen.com", 611)
        w.cname("www.a.shifen.com", "www.wshifen.com", 30)
        w.add("www.wshifen.com", 1, 199, b"\x67\xeb\x2e\x60")
        raw = w.out()
        aged = alt_adapter.age_wire(raw, 10)
        self.assertEqual(len(aged), len(raw), "原地改写不得改变报文长度")
        _h, _q, out = alt_adapter._parse_rrs(aged)
        # 压缩链必须仍然解析得出目标名 ✓（指针没被破坏）
        self.assertEqual(alt_adapter._cname_target(aged, out["an"][0]),
                         "www.a.shifen.com")
        self.assertEqual([r["ttl"] for r in out["an"]],
                         [601, 20, 189], "每条 RR 各自扣减 10 秒")

    def test_age_wire_does_not_touch_opt(self):
        """★ OPT 的字段不是寿命 ✗ —— 扣减它会破坏 EDNS0 语义 ✗。"""
        w = self._wire_with_opt(ttl=20)
        _h, _q, before = alt_adapter._parse_rrs(w)
        self.assertEqual(before["ar"][0]["type"], 41)
        _opt_ttl_before = before["ar"][0]["ttl"]
        aged = alt_adapter.age_wire(w, 8)
        _h2, _q2, after = alt_adapter._parse_rrs(aged)
        opt = [r for r in after["ar"] if r["type"] == 41][0]
        self.assertEqual(opt["ttl"], _opt_ttl_before,
                         "OPT 的 TTL 字段（扩展 rcode/版本/flags）绝不能被当寿命扣减 ✗")
        self.assertEqual(after["an"][0]["ttl"], 12, "普通 RR 仍要正常扣减 ✓")

    def test_age_wire_never_underflows(self):
        """扣到 ≤0 保留 0 ✓（绝不下溢成 4294967291 这种天文数字 ✗）。"""
        w = mk([a_rr(ttl=5)])
        aged = alt_adapter.age_wire(w, 999)
        _h, _q, out = alt_adapter._parse_rrs(aged)
        self.assertEqual(out["an"][0]["ttl"], 0, "过老 ⇒ 归 0，不得负数回绕 ✗")
        self.assertGreaterEqual(out["an"][0]["ttl"], 0)

    def test_age_wire_zero_elapsed_is_identity(self):
        """经过 <1 秒 ⇒ 原样返回 ✓（不做无意义改写）。"""
        w = mk([a_rr(ttl=20)])
        self.assertEqual(alt_adapter.age_wire(w, 0), w)

    def test_min_rr_ttl_ignores_opt(self):
        """`min_rr_ttl()` 必须忽略 OPT ✓ —— 否则 OPT 的 0x8000 会把最小值伪造成 32768 之类 ✗。"""
        w = mk([a_rr(ttl=45)], ar_rrs=[("", 41, 0x8000, b"")])
        self.assertEqual(alt_adapter.min_rr_ttl(w), 45)

    def test_replay_does_not_extend_original_deadline(self):
        """★ 核心不变量：反复命中**不得**把寿命从当下重新起算 ✗。

        复现用户现象：上层更新了地址，guard 在原始 TTL 到期后仍答旧值 ✓。
        老化修复后，t=8 命中得到的 `valid_until` 必须 ≈ NOW+12（原截止），
        而不是 NOW+20 或 NOW+300 ✗。
        """
        w = mk([a_rr(ttl=20)])
        t0, _d0 = alt_adapter.rrset_validity(w, now=NOW)
        self.assertEqual(t0, 20.0)
        aged = alt_adapter.age_wire(w, 8)
        t8, _d8 = alt_adapter.rrset_validity(aged, now=NOW)
        self.assertLessEqual(t8, 12.0, "t=8 时必须剩 ≤12 秒（方案第 55 行明列）")
        # 用老化后的报文重新分类 ⇒ 截止仍是 NOW+12（与"从当下再起算 20s"不同 ✓）
        ans = alt_adapter.classify_response(aged, "local-a", ttl=t8, now=NOW)
        self.assertLessEqual(ans.valid_until, NOW + 12.0001)
        # 再老 4 秒 ⇒ 必须严格更短，绝不回升 ✗
        aged2 = alt_adapter.age_wire(w, 12)
        t12, _d12 = alt_adapter.rrset_validity(aged2, now=NOW)
        self.assertLess(t12, t8, "时间只会让寿命更短 ⇒ 绝不允许回升 ✗")

    def test_ttl_zero_after_aging_is_not_fresh(self):
        """老化到 0 ⇒ 判不新鲜 ✓（配合"准入缓存不滑动续期"的结构保证 ✓）。"""
        w = mk([a_rr(ttl=20)])
        aged = alt_adapter.age_wire(w, 20)
        _h, _q, out = alt_adapter._parse_rrs(aged)
        self.assertEqual(out["an"][0]["ttl"], 0)
        t, _d = alt_adapter.rrset_validity(aged, now=NOW)
        self.assertEqual(t, 0.0)
        ans = alt_adapter.classify_response(aged, "local-a", ttl=t, now=NOW)
        self.assertFalse(is_fresh(ans, now=NOW))

    def test_adm_cache_records_stored_time_and_rr_ttls(self):
        """§2 第 48 行：缓存记录必须含"插入时间"与"原始各 RR TTL" ✓。"""
        w = mk([a_rr(ttl=120)], ar_rrs=[("", 41, 0x8000, b"")])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("cache-me.example", 1, w, "accepted", "local-a", 120.0,
                             now=NOW)
        rec = guard._ADM_CACHE[guard._adm_key("cache-me.example", 1)]
        for k in ("stored", "until", "valid_until", "wire", "verdict", "source",
                  "policy_version", "qtype", "ttl", "rr_ttls"):
            self.assertIn(k, rec, "缓存记录缺字段 %s ✗（方案 §2 第 48 行）" % k)
        # ★ 方案 §2 第 48 行：**插入单调时间** + 视图维度（qclass/DO/CD/ECS/view）✓
        for k in ("stored_mono", "qclass", "do", "cd", "ecs", "view"):
            self.assertIn(k, rec, "缓存记录缺视图/单调字段 %s ✗（方案 §2 第 48 行）" % k)
        self.assertEqual(rec["stored"], NOW)
        self.assertEqual(rec["valid_until"], NOW + 120.0)
        self.assertIsInstance(rec["stored_mono"], float, "插入单调时间必须是单调时钟读数 ✓")
        self.assertEqual(rec["qclass"], 1)
        self.assertIs(rec["do"], True)
        self.assertIs(rec["cd"], False)
        self.assertIsNone(rec["ecs"], "本链路无 ECS ⇒ 必须记 None（而不是静默省略 ✗）")
        # `rr_ttls` 记录原始 TTL 且不含 OPT ✓
        self.assertEqual(rec["rr_ttls"]["an"], [120])
        self.assertEqual(rec["rr_ttls"]["ar"], [], "OPT 不得计入原始 TTL 记录 ✗")

    def test_cross_view_record_is_not_shared(self):
        """★ 方案 §2 第 48 行："**无法证明同一视图时不共用缓存**" ✗。

        本链路 DO=1/CD=0/QCLASS=IN/无 ECS 是固定的 ⇒ 若某条记录被改成别的视图
        （有人给某路径开了 ECS 或 CD），命中必须**拒绝**而不是照样返回答案 ✗。
        """
        w = mk([a_rr(ttl=300)])
        guard._ADM_CACHE.clear()
        t0 = 3_000_000.0
        guard._adm_cache_put("view.example", 1, w, "accepted", "local-a", 300.0, now=t0)
        self.assertIsNotNone(guard._adm_cache_get("view.example", 1, now=t0 + 1))
        # 篡改成"CD=1"的视图 ⇒ 不得共用 ✓
        guard._ADM_CACHE[guard._adm_key("view.example", 1)]["cd"] = True
        self.assertIsNone(guard._adm_cache_get("view.example", 1, now=t0 + 2),
                          "视图不一致时必须拒绝共用缓存 ✗")
        guard._ADM_CACHE.clear()

    def test_monotonic_age_is_not_affected_by_wall_clock_jump(self):
        """★ 用**单调时钟**算经过秒数 ⇒ NTP 回拨/前跳都不会把剩余寿命算错 ✓。

        为什么必需：若只用墙上时钟，回拨会让"经过秒数"变负 ⇒ 被钳到 0 ⇒
        `age_wire(0)` 是恒等变换 ⇒ **等于原地续期回到满 TTL** ✗（正是要修的病 ✗）。
        判别方法：把 `stored` 篡改成"5000 秒前的墙上时刻"（模拟时钟前跳），
        但 `stored_mono` 保持当下 ⇒
          · 走单调差 ⇒ 经过 ≈0 ⇒ TTL 仍 ≈100 ✓（正确）；
          · 走墙上差 ⇒ 经过 5000s ⇒ TTL 被扣成 0 ✗（错误）。
        再反过来把 `stored_mono` 往回挪 40 秒 ⇒ 必须真的扣掉 40 ✓。
        """
        w = mk([a_rr(ttl=100)])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("mono.example", 1, w, "accepted", "local-a", 100.0)
        _rec = guard._ADM_CACHE[guard._adm_key("mono.example", 1)]
        # 模拟"墙上时钟前跳 5000 秒"：只动 stored，不动 stored_mono ✓
        _rec["stored"] = time.time() - 5000.0
        got = guard._adm_cache_get("mono.example", 1)
        self.assertIsNotNone(got)
        _h, _q, out = alt_adapter._parse_rrs(got)
        self.assertEqual(out["an"][0]["ttl"], 100,
                         "必须走单调差（经过≈0）而不是墙上差（会扣成 0）✗")
        # 真的过了 40 秒（单调口径）⇒ 必须扣掉 40 ✓
        _rec["stored_mono"] = time.monotonic() - 40.0
        got2 = guard._adm_cache_get("mono.example", 1)
        self.assertIsNotNone(got2)
        _h2, _q2, out2 = alt_adapter._parse_rrs(got2)
        self.assertEqual(out2["an"][0]["ttl"], 60, "单调差必须真的扣掉经过的 40 秒 ✓")
        guard._ADM_CACHE.clear()

    def test_adm_cache_hit_returns_aged_wire(self):
        """★ 命中返回的 wire 必须是**已老化**的 ✓ —— 否则下游重新分类会把寿命续期 ✗。"""
        w = mk([a_rr(ttl=120)])
        guard._ADM_CACHE.clear()
        put_at = 1_000_000.0
        guard._adm_cache_put("age-me.example", 1, w, "accepted", "local-a", 120.0,
                             now=put_at)
        # 命中时已过 30 秒
        got = guard._adm_cache_get("age-me.example", 1, now=put_at + 30)
        self.assertIsNotNone(got)
        _h, _q, out = alt_adapter._parse_rrs(got)
        self.assertEqual(out["an"][0]["ttl"], 90, "命中必须扣除已过的 30 秒 ✓")
        t, _d = alt_adapter.rrset_validity(got, now=put_at + 30)
        self.assertEqual(t, 90.0)
        # 由此得到的绝对截止仍是 put_at+120（原期限）✓，不是"从命中时刻再算 90s" ✗
        ans = alt_adapter.classify_response(got, "local-a", ttl=t, now=put_at + 30)
        self.assertAlmostEqual(ans.valid_until, put_at + 120.0, places=3)

    def test_repeated_hits_never_slide_deadline(self):
        """反复命中 5 次，截止时刻必须**单调不增** ✓（无界续期 bug 的回归守卫）。"""
        w = mk([a_rr(ttl=100)])
        guard._ADM_CACHE.clear()
        t0 = 2_000_000.0
        guard._adm_cache_put("repeat.example", 1, w, "accepted", "local-a", 100.0, now=t0)
        deadlines = []
        for dt in (0, 10, 20, 30, 40):
            got = guard._adm_cache_get("repeat.example", 1, now=t0 + dt)
            self.assertIsNotNone(got, "原始 TTL 未到 ⇒ 必须仍可命中")
            rem, _d = alt_adapter.rrset_validity(got, now=t0 + dt)
            ans = alt_adapter.classify_response(got, "local-a", ttl=rem, now=t0 + dt)
            deadlines.append(ans.valid_until)
        self.assertEqual(deadlines, sorted(deadlines), "截止时刻必须单调不增 ✗")
        self.assertAlmostEqual(deadlines[0], t0 + 100.0, places=3)
        self.assertAlmostEqual(deadlines[-1], t0 + 100.0, places=3,
                               msg="无论命中几次，绝对截止都必须等于原始期限 ✗")
        # 超过原始 TTL ⇒ 必须未命中 ✓
        self.assertIsNone(guard._adm_cache_get("repeat.example", 1, now=t0 + 101))
        guard._ADM_CACHE.clear()


class BogusInvalidation(unittest.TestCase):
    """方案 §2 第 51 行：**新观察到 bogus 或强否决时立即失效关联缓存** ✓。

    为什么必须有这组用例：缓存里存的是**已采纳**的答案；若上游在验证侧翻转为
    bogus 而缓存不清，命中就会把"已被推翻的结论"继续放给客户端 ✗ ——
    这正是用户观察到的"上游换了地址、guard 还答旧值" ✓。
    """

    def setUp(self):
        guard._ADM_CACHE.clear()

    def tearDown(self):
        guard._ADM_CACHE.clear()

    def test_invalidate_drops_all_qtypes_of_name(self):
        """bogus 是**名字级**结论 ⇒ 该名字所有 qtype 一起失效 ✓（宁可多失效 ✓）。"""
        w = mk([a_rr(ttl=300)])
        for qt in (1, 28, 15):
            guard._adm_cache_put("victim.example", qt, w, "accepted", "local-a", 300.0,
                                 now=1_000_000.0)
        guard._adm_cache_put("other.example", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        self.assertEqual(len(guard._ADM_CACHE), 4)
        n = guard._adm_invalidate("victim.example", why="bogus")
        self.assertEqual(n, 3, "victim 的三种 qtype 必须全部失效 ✓")
        self.assertIsNone(guard._adm_cache_get("victim.example", 1, now=1_000_001.0))
        self.assertIsNone(guard._adm_cache_get("victim.example", 28, now=1_000_001.0))
        self.assertIsNotNone(guard._adm_cache_get("other.example", 1, now=1_000_001.0),
                             "无关名字绝不能被误伤 ✗")

    def test_invalidate_single_qtype(self):
        """指定 qtype ⇒ 只失效那一个 ✓。"""
        w = mk([a_rr(ttl=300)])
        guard._adm_cache_put("partial.example", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        guard._adm_cache_put("partial.example", 28, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        self.assertEqual(guard._adm_invalidate("partial.example", qtype=28, why="x"), 1)
        self.assertIsNotNone(guard._adm_cache_get("partial.example", 1, now=1_000_001.0))
        self.assertIsNone(guard._adm_cache_get("partial.example", 28, now=1_000_001.0))

    def test_invalidate_is_case_and_dot_insensitive(self):
        """键归一化（小写、去尾点）必须一致 ✓ —— 否则会出现"清了但没清掉"的假失效 ✗。"""
        w = mk([a_rr(ttl=300)])
        guard._adm_cache_put("MiXeD.Example.COM.", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        self.assertEqual(guard._adm_invalidate("mixed.example.com", why="bogus"), 1)
        self.assertIsNone(guard._adm_cache_get("MiXeD.Example.COM.", 1, now=1_000_001.0))

    def test_invalidate_missing_name_is_noop(self):
        """名字不在缓存 ⇒ 返回 0 ✓（不得抛异常 / 不得误删别人 ✗）。"""
        w = mk([a_rr(ttl=300)])
        guard._adm_cache_put("keep.example", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        self.assertEqual(guard._adm_invalidate("nope.example", why="bogus"), 0)
        self.assertEqual(len(guard._ADM_CACHE), 1)

    def test_bogus_and_zone_pin_sites_call_invalidate(self):
        """源码守卫：bogus 与 zone pin 两处必须**真的**调用了失效 ✓（不是只有函数定义 ✗）。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        self.assertIn("def _adm_invalidate", src, "失效函数必须存在 ✓")
        # ★ 现在两处都用 `_drop_caches_for()`（准入缓存 + `_corrob` 钉住 + `_neg_cache` 三清 ✓）
        # —— 只清准入缓存是不够的：`_corrob` 的生产窗口是 `GUARD_CORROB_TTL=3600s` ✗。
        self.assertIn("def _drop_caches_for", src, "三清函数必须存在 ✓")
        # bogus 分支：`dnssec_bogus` 记账点附近必须有失效调用 ✓
        i = src.index('_stats["dnssec_bogus"] += 1')
        near = src[i:i + 1200]
        self.assertTrue("_drop_caches_for(" in near or "_adm_invalidate(" in near,
                        "观察到 bogus/SERVFAIL 时必须立即失效关联缓存 ✗（方案 §2 第 51 行）")
        # zone pin 分支：`cn_zone_deny_hit` 记账点附近必须有失效调用 ✓
        j = src.index('_stats["cn_zone_deny_hit"] = _stats.get("cn_zone_deny_hit", 0) + 1')
        near2 = src[j:j + 1200]
        self.assertTrue("_drop_caches_for(" in near2 or "_adm_invalidate(" in near2,
                        "强否决（zone pin）时必须立即失效关联缓存 ✗（方案 §2 第 51 行）")
        # 后台发现 bogus（`mark()` = `verify_one()` 的唯一落点）也必须阻止后续返回 ✓
        k = src.index("def mark(name, why, bad, good):")
        seg_mark = src[k:k + 6000]
        self.assertIn("_drop_caches_for(", seg_mark,
                      "后台核验判定后必须阻止旧答案继续返回 ✗（方案 §2 第 51 行后半句）")

    def test_drop_caches_for_clears_pin_and_negative_cache(self):
        """三清必须真的清掉 `_corrob` 与 `_neg_cache`，而不只是准入缓存 ✓。"""
        w = mk([a_rr(ttl=300)])
        guard._ADM_CACHE.clear()
        guard._corrob.clear()
        guard._neg_cache.clear()
        for nm in ("three.example", "keep.example"):
            guard._adm_cache_put(nm, 1, w, "accepted", "local-a", 300.0, now=1_000_000.0)
            guard._corrob[(nm, 1)] = (time.time() + 3600, w, ("1.2.3.4",))
            guard._neg_cache[(nm, 1)] = (time.time() + 300, w)
        self.assertEqual(len(guard._ADM_CACHE), 2)
        self.assertEqual(len(guard._corrob), 2)
        self.assertEqual(len(guard._neg_cache), 2)
        guard._drop_caches_for("three.example", why="bogus")
        self.assertNotIn(("three.example", 1), guard._corrob, "钉住窗口必须被清 ✗")
        self.assertNotIn(("three.example", 1), guard._neg_cache, "否定结论必须被清 ✗")
        self.assertIsNone(guard._adm_cache_get("three.example", 1, now=1_000_001.0))
        # ★ 方案 §2 第 51 行"安全准入证据和答案缓存**分开**" ⇒ 三类必须**分开记账** ✗→✓
        # 从前 `_corrob` 与 `_neg_cache` 共用一个 `pin_invalidated_*` 计数 ✗，
        # 看板上分不出"是钉住窗口没清掉"还是"否定结论还在用" ✗（两种完全不同的故障 ✗）。
        self.assertEqual(guard._stats.get("pin_invalidated_bogus"), 1,
                         "钉住窗口的失效必须单独记账 ✓")
        self.assertEqual(guard._stats.get("neg_invalidated_bogus"), 1,
                         "否定缓存的失效必须单独记账 ✓")
        # 无关名字不受影响 ✓
        self.assertIn(("keep.example", 1), guard._corrob)
        self.assertIn(("keep.example", 1), guard._neg_cache)
        self.assertIsNotNone(guard._adm_cache_get("keep.example", 1, now=1_000_001.0))
        guard._ADM_CACHE.clear()
        guard._corrob.clear()
        guard._neg_cache.clear()
        for _k in ("pin_invalidated_bogus", "neg_invalidated_bogus"):
            guard._stats[_k] = 0

    def test_reput_of_same_answer_does_not_slide_deadline(self):
        """★ 方案 §2 第 50 行："缓存命中**不重新插入、不滑动续期**" ✓。

        命中的字节会再走一遍出口闸门 ⇒ 若"同一答案又写一次"，`stored`/`stored_mono`
        被刷新 ⇒ 之后每次命中算出的"经过秒数"都从**这次**起算 ⇒ 等于每次命中都续期 ✗。
        """
        w = mk([a_rr(ttl=300)])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("reput.example", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        _k = guard._adm_key("reput.example", 1)
        _r1 = dict(guard._ADM_CACHE[_k])
        # 同一答案（只是 qid 不同）再写一次 ⇒ 记录必须**完全不变** ✓
        w2 = bytearray(w)
        w2[0], w2[1] = 0xAB, 0xCD
        guard._adm_cache_put("reput.example", 1, bytes(w2), "accepted", "local-a", 300.0,
                             now=1_000_100.0)
        _r2 = guard._ADM_CACHE[_k]
        self.assertEqual(_r1.get("stored"), _r2.get("stored"),
                         "同一答案不得刷新 `stored` ✗（否则就是滑动续期 ✗）")
        self.assertEqual(_r1.get("until"), _r2.get("until"), "同一答案不得延长绝对截止 ✗")
        self.assertGreaterEqual(guard._stats.get("adm_cache_reput_same", 0), 1,
                                "同答案重复写回必须被记账 ✓")
        # 上游换了**答案**（rdata 不同）⇒ 必须立刻采用新期限 ✓（不得僵化 ✗）
        w3 = mk([a_rr(ttl=300), a_rr(name="x." + QNAME_STR, ttl=300)])
        guard._adm_cache_put("reput.example", 1, w3, "accepted", "local-a", 300.0,
                             now=1_000_200.0)
        self.assertEqual(guard._ADM_CACHE[_k].get("stored"), 1_000_200.0,
                         "换了答案必须按新证据重写记录 ✓")
        guard._ADM_CACHE.clear()

    def test_cache_hit_returns_aged_answer_and_deadline_is_absolute(self):
        """命中返回的答案必须**已扣减**经过秒数，且绝对截止**不随命中变化** ✓。"""
        _now = 1_000_000.0
        w = mk([a_rr(ttl=120)])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("age.example", 1, w, "accepted", "local-a", 120.0, now=_now)
        _k = guard._adm_key("age.example", 1)
        _until = float(guard._ADM_CACHE[_k]["until"])
        _w30 = guard._adm_cache_get("age.example", 1, now=_now + 30.0)
        import alt_adapter as _ALTX
        _t30, _d30 = _ALTX.rrset_validity(_w30)
        self.assertAlmostEqual(float(_t30), 90.0, delta=1.0,
                              msg="命中时必须按经过 30s 扣减（120→90）✗")
        # 再命中一次（经过 90s）⇒ 扣到 30s，而**绝对截止不动** ✓
        _w90 = guard._adm_cache_get("age.example", 1, now=_now + 90.0)
        _t90, _d90 = _ALTX.rrset_validity(_w90)
        self.assertAlmostEqual(float(_t90), 30.0, delta=1.0)
        self.assertEqual(float(guard._ADM_CACHE[_k]["until"]), _until,
                         "绝对截止不得随命中变化 ✗（命中不滑动续期 ✓）")
        guard._ADM_CACHE.clear()

    def test_age_wire_result_is_stored_back_not_original(self):
        """老化后的字节**不得**被写回缓存 ✓ —— 否则第二跳会基于"已扣过的 TTL"再扣 ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        i = src.index("def _adm_cache_get(")
        j = src.index("\ndef ", i + 10)
        seg = src[i:j]
        self.assertNotIn("_adm_cache_put(", seg,
                         "`_adm_cache_get` 内不得回写缓存 ✗（命中不重新插入 ✓）")

    def test_separate_counters_are_persist_skipped(self):
        """窗口量必须每次启动归零 ✓ —— 否则比例会被上次运行的残留污染 ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        i = src.index("_step2_keys = (")
        seg = src[i:src.index("\n\n", i)]
        for _k in ("neg_invalidated_bogus", "neg_invalidated_mark_strong",
                   "pin_invalidated_mark_new", "adm_cache_view_mismatch",
                   "ttl_zero_witness", "neg_cache_skip_zero_ttl",
                   "adm_cache_schema_reject", "adm_cache_evidence_expired"):
            self.assertIn('"%s"' % _k, seg, "`%s` 必须登记进 `_step2_keys` ✗" % _k)

    def test_old_schema_record_is_rejected(self):
        """★ 方案 §2 第 55 行："**旧 schema 拒绝加载**" ✓。

        记录结构变更后，旧记录被复用会**静默**算出错误寿命 ✗（报错看不见、答案却是错的 ✗）。
        """
        w = mk([a_rr(ttl=300)])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("schema.example", 1, w, "accepted", "local-a", 300.0,
                             now=1_000_000.0)
        _k = guard._adm_key("schema.example", 1)
        self.assertIn(_k, guard._ADM_CACHE)
        # 刚写入 ⇒ 必须命中 ✓
        self.assertIsNotNone(guard._adm_cache_get("schema.example", 1, now=1_000_001.0))
        # 把 schema 号改成更旧的号 ⇒ 必须**当作未命中**并清掉 ✓
        guard._ADM_CACHE[_k]["schema"] = int(guard._ADM_SCHEMA) - 1
        self.assertIsNone(guard._adm_cache_get("schema.example", 1, now=1_000_001.0),
                          "旧 schema 记录必须被拒绝 ✗（方案 §2 第 55 行）")
        self.assertNotIn(_k, guard._ADM_CACHE, "被拒绝的旧记录应当被清掉 ✓")
        guard._ADM_CACHE.clear()

    def test_evidence_until_is_recorded_and_enforced(self):
        """★ 方案 §2 第 48 行："**绝对证据失效时间**" ✓ 必须落盘并在命中时收口 ✓。

        `until` = "我方允许多久复用"（含策略上限）；`evidence_until` = "证据本身到何时失效" ✗→✓。
        没有它，"证据早已过期、只是策略上限还允许复用"这种错误会被 `until` 掩盖 ✗。
        """
        # 签名剩余寿命比策略上限短得多的报文
        _now = 1_000_000.0
        _exp = int(_now) + 40                       # 签名 40 秒后失效
        rr = a_rr(ttl=300)
        sig = rrsig_rr(covered=1, exp=_exp, ttl=300)
        w = mk([rr, sig])
        guard._ADM_CACHE.clear()
        guard._adm_cache_put("evid.example", 1, w, "accepted", "local-a", 300.0, now=_now)
        rec = guard._ADM_CACHE.get(guard._adm_key("evid.example", 1))
        self.assertIsNotNone(rec)
        self.assertIsNotNone(rec.get("evidence_until"), "必须记录绝对证据失效时间 ✗")
        # 证据失效时间必须 ≤ 准入 TTL 给出的上限 ✓（保守收口）
        self.assertLessEqual(float(rec["evidence_until"]), _now + 300.0)
        self.assertEqual(rec.get("evidence_kind"), "forward")
        # 证据未过期 ⇒ 命中 ✓
        self.assertIsNotNone(guard._adm_cache_get("evid.example", 1, now=_now + 5.0))
        # 造一个"证据已过期但 until 还很长"的记录 ⇒ 命中必须被拒 ✗
        _k = guard._adm_key("evid.example", 1)
        _rec = guard._ADM_CACHE[_k]
        _rec["until"] = _now + 300.0
        _rec["valid_until"] = _now + 300.0
        _rec["stored"] = _now
        _rec["stored_mono"] = guard.time.monotonic()
        _rec["evidence_until"] = _now + 1.0        # 证据 1 秒后就失效
        self.assertIsNone(guard._adm_cache_get("evid.example", 1, now=_now + 2.0),
                          "证据已过期时不得继续复用，哪怕 until 还很长 ✗")
        guard._ADM_CACHE.clear()


class CorrobPinWindow(unittest.TestCase):
    """★ 方案 §2 第 44/49 行逐字点名：`corroboration pin` 不得把窗口抬到 30s 起步 ✗。

    这是"用户观察到的旧值继续被返回"的一条**独立支路**：准入缓存修好了、但核对钉住
    窗口还是 `max(30, ...)`（生产更糟：`GUARD_CORROB_TTL=3600` ✗），旧答案照样出海 ✗。
    """

    def setUp(self):
        guard._corrob.clear()

    def tearDown(self):
        guard._corrob.clear()

    @staticmethod
    def _win_left(name, qtype=1):
        """取钉住窗口的剩余秒数（相对 now=time.time()）✓。"""
        rec = guard._corrob.get((name, qtype))
        if rec is None:
            return None
        return rec[0] - time.time()

    def test_no_thirty_second_floor(self):
        """应答自己说 5s ⇒ 窗口就只能是 5s，不得被抬到 30s ✗（旧实现 `max(30.0, win)` ✗）。"""
        w = mk([a_rr(ttl=5)])
        guard.corrob_put("short.example", 1, w, ("1.2.3.4",), 5)
        left = self._win_left("short.example")
        self.assertIsNotNone(left, "非零 TTL 的应答必须被钉住 ✓")
        self.assertLessEqual(left, 5.0 + 1.0, "窗口不得超出运营方授权（5s）✗")
        self.assertGreater(left, 0.0)

    def test_zero_ttl_never_pins(self):
        """★ 最危险的一格：`ttl=0` 在旧实现里会落回 `CORROB_TTL`（生产 3600 ✗）。

        方向完全反了 —— 零 TTL 本该是"最不该信"，旧码却给了"最长窗口" ✗。
        """
        # 报文自身 TTL=0，且调用方也传 0 ⇒ 不得钉住 ✓
        w0 = mk([a_rr(ttl=0)])
        guard.corrob_put("zero1.example", 1, w0, ("1.2.3.4",), 0)
        self.assertIsNone(self._win_left("zero1.example"),
                          "TTL=0 不得进入核对钉住（方案 §2 第 49 行）✗")
        # 调用方没有 TTL 信息（传 0）但**报文自身**有 300s ⇒ 以报文为准、按 ≤300 钉 ✓。
        # 这不是"凭空给窗口" ✗：报文自己声明的寿命就是运营方授权 ✓；
        # 真正要防的是**调用方给一个比自己长的别人的寿命** ✗（见下一条用例 ✓）。
        w300 = mk([a_rr(ttl=300)])
        guard.corrob_put("zero2.example", 1, w300, ("1.2.3.4",), 0)
        left2 = self._win_left("zero2.example")
        self.assertIsNotNone(left2)
        self.assertLessEqual(left2, 300.0 + 1.0)
        self.assertLessEqual(left2, float(guard.CORROB_TTL) + 1.0, "仍不得超过 CORROB_TTL ✓")

    def test_min_of_caller_ttl_and_response_ttl(self):
        """★ 跨来源漂移：调用方给 300 而被钉住的是只有 30s 的明文 ⇒ 必须按 30s 钉 ✗→✓。

        现场调用点是 `corrob_put(name, qtype, uresp, uips, ctt8)`（`ctt8` 来自**干净通道**
        `cresp`）⇒ 干净通道报 300s、明文只有 30s 时，旧实现会把明文钉 300s ✗。
        """
        w30 = mk([a_rr(ttl=30)])
        guard.corrob_put("cross.example", 1, w30, ("1.2.3.4",), 300)
        left = self._win_left("cross.example")
        self.assertLessEqual(left, 30.0 + 1.0, "必须取两者较小者（报文自身寿命）✗")

    def test_corroboration_ttl_cap_still_applies(self):
        """另一方向也要守住：报文说 86400s ⇒ 仍不得超过 `CORROB_TTL` ✓。"""
        w = mk([a_rr(ttl=86400)])
        guard.corrob_put("long.example", 1, w, ("1.2.3.4",), 86400)
        left = self._win_left("long.example")
        self.assertLessEqual(left, float(guard.CORROB_TTL) + 1.0)

    def test_source_guard_no_forced_floor(self):
        """源码守卫：`corrob_put` 的**可执行代码**里不得再出现 30s 强制下限 ✗。

        ★ 不能对整段源码做字符串匹配 —— 函数 docstring 里**正当地**引用了旧写法
        （用于说明它为什么被删 ✗），字符串断言会把注释/文档也算进去 ✗（同类坑在
        `test_negative_cache_no_forced_30s_floor` 上已经踩过一次 ✗）。
        所以这里走 AST：只在**调用节点**里查 `max(30.0, win)` / `max(30, win)` ✓。
        """
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "corrob_put":
                fn = node
                break
        self.assertIsNotNone(fn, "`corrob_put` 必须存在 ✓")
        calls = [ast.unparse(n) for n in ast.walk(fn) if isinstance(n, ast.Call)] \
            if hasattr(ast, "unparse") else []
        if calls:
            joined = "\n".join(calls)
            self.assertNotIn("max(30.0, win)", joined,
                             "不得有 30s 强制下限 ✗（方案 §2 第 44 行）")
            self.assertNotIn("max(30, win)", joined,
                             "不得有 30s 强制下限 ✗（方案 §2 第 44 行）")
            self.assertIn("min(win, _t)", joined, "窗口必须以应答自身寿命为上限 ✓")
        # 兜底（py3.6 没有 `ast.unparse`、也没有 `end_lineno` ✓）：按行扫，跳过注释行 ✓。
        # 用「下一个顶层 `def`」界定函数体，避免依赖 `end_lineno` ✗。
        else:
            lines = src.split("\n")
            start = fn.lineno - 1
            stop = len(lines)
            for _i in range(start + 1, len(lines)):
                if lines[_i].startswith("def ") or lines[_i].startswith("class ") or \
                        lines[_i].startswith("@") or lines[_i].startswith("_SRC = ") or \
                        lines[_i].startswith("_ADM_"):
                    stop = _i
                    break
            body = lines[start:stop]
            code_lines = [ln.split("#")[0] for ln in body]
            joined = "\n".join(code_lines)
            self.assertNotIn("max(30.0, win)", joined)
            self.assertIn("min(win, _t)", joined)

    def test_zero_ttl_does_not_mark_verified(self):
        """★ 零 TTL 连 `_r8_stable` 也不得更新 ✗ —— 那等于"永久跳过实时核对" ✗。

        `_r8_stable` 是"最近一次成功认证核对"的时间戳，`stable_fast` 分支据此跳过
        实时 R8 核对 ⇒ 给它盖章比窗口本身更危险 ✗。
        """
        w0 = mk([a_rr(ttl=0)])
        guard._r8_stable.pop(("novalid.example", 1), None)
        guard.corrob_put("novalid.example", 1, w0, ("1.2.3.4",), 0)
        self.assertNotIn(("novalid.example", 1), guard._r8_stable,
                         "无可用寿命的答案不得被标记为'已核对成功' ✗")

    def test_k_branch_does_not_hardcode_300(self):
        """源码守卫：ASN gate K 分支不得再写死 `300` ✗（方案 §2 第 49 行）。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        self.assertNotIn("corrob_put(name, qtype, uresp, uips, 300)", src,
                         "不得用固定 300 覆盖短 TTL ✗")


# ══════════════════════════════════════════════════════════════════════════════
# §3「消除 CN 路径重复取数与重复重试」—— 完成门首轮暴露的两个**真实缺陷** ✓
# ══════════════════════════════════════════════════════════════════════════════
class SingleFlightResultHandoff(unittest.TestCase):
    """方案 §3 第 73 行：同 question/view/flags/policy 的并发请求必须**结果贯穿** ✓。

    现场缺陷（`gt_s3.py` 完成门首轮 ⑤ `A=100/100` ✗）：
      · 原实现**只对 CN 名**接入单飞 ✗，非 CN 名照样各查各的 ✗；
      · 更根本：等待者只是"等锁 + 再探一次准入缓存"✗，而准入缓存到
        `_finalize_return()` 才写入 ✗ ⇒ 等待者醒来时缓存**通常是空的** ✗
        ⇒ 100 个并发请求把 A 打了 100 次 ✗（方案第 76 行明令禁止 ✗）。
    修法：**把领跑者的结果直接交给等待者** ✓（`_SfSlot` 结果盒 ✓）。
    """

    def test_sf_key_includes_qtype_and_view(self):
        """键必须含 qtype 与 view 维度 ✗ —— 否则 A 的字节会被当 AAAA 发出去 ✗。"""
        k1 = guard._sf_key("a.example", 1)
        k2 = guard._sf_key("a.example", 28)
        self.assertNotEqual(k1, k2, "不同 qtype 绝不能共用一次上游查询 ✗")
        self.assertEqual(len(k1), len(k2))
        for i, (x, y) in enumerate(zip(k1, k2)):
            if i == 2:
                self.assertNotEqual(x, y)
            else:
                self.assertEqual(x, y)
        self.assertEqual(guard._sf_key("A.Example", 1)[1], "a.example",
                         "名字大小写必须归一 ✓（否则同一次查询被当成两个键 ✗）")

    def test_waiter_reuses_leader_result(self):
        """等待者必须复用到领跑者的**字节** ✓，且**零外部查询** ✓。"""
        slot = guard._SfSlot()
        entered = time.monotonic()
        slot.publish((b"LEADER-WIRE", "A"))
        got = slot.recv(1.0, entered)
        self.assertIsNotNone(got, "领跑者已发布 ⇒ 等待者必须拿到结果 ✓（否则就是串行重查 ✗）")
        self.assertEqual(got[0], b"LEADER-WIRE")
        self.assertEqual(got[1], "A")

    def test_stale_publish_is_never_reused(self):
        """★ **旧结果绝不能被新请求复用** ✗ —— 那等于绕过准入门闩与 TTL 老化 ✗。

        `done_ts < entered_at` ⇒ 该结果属于**上一轮**，必须拒绝 ✓
        （方案第 55 行：反复命中不能延长原始期限 ✗）。
        """
        slot = guard._SfSlot()
        slot.publish((b"OLD-WIRE", "A"))
        time.sleep(0.01)
        entered = time.monotonic()          # 进入时间**晚于**发布 ⇒ 是旧结果 ✗
        self.assertIsNone(slot.recv(1.0, entered),
                          "上一轮的结果绝不能被当作新答案 ✓")
        self.assertIsNone(slot.reuse(entered))

    def test_leader_no_answer_also_publishes(self):
        """领跑者"确实没答案"必须发布 ✓ —— 否则等待者会把同一件事再打一轮 ✗。"""
        slot = guard._SfSlot()
        entered = time.monotonic()
        slot.publish(("__none__", None))
        self.assertIsNone(slot.recv(1.0, entered),
                          "领跑者无答案 ⇒ 等待者自己查 ✓（不是复用假答案 ✗）")
        self.assertIsNotNone(slot.done_ts, "成败都要发布 ✓（否则又重复取数 ✗）")

    def test_handoff_drops_lock_instead_of_serializing(self):
        """源码守卫：`_sf_enter` 必须在"等锁成功但领跑者已发布"时**放锁**当等待者 ✓。

        这是 `A=100/100` 的直接根因 ✗：把"等到锁"当成"轮到我了" ⇒ 串行重查 ✗。
        """
        src = open(GUARD_SRC, encoding="utf-8").read()
        tree = ast.parse(src)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_sf_enter":
                fn = node
                break
        self.assertIsNotNone(fn, "_sf_enter 必须存在 ✓")
        lines = src.split("\n")
        start = fn.lineno - 1
        stop = len(lines)
        for _i in range(start + 1, len(lines)):
            if lines[_i].startswith(("def ", "class ", "@")):
                stop = _i
                break
        body = "\n".join(ln.split("#")[0] for ln in lines[start:stop])
        self.assertIn("reuse(entered_at)", body, "必须以'进入时刻'判定结果新旧 ✓")
        self.assertIn("lk.release()", body, "等锁成功但结果已就绪 ⇒ 必须放锁当等待者 ✓")

    def test_general_not_cn_only(self):
        """源码守卫：单飞必须对**所有 name** 生效 ✗，不能只对 CN 名 ✗。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        self.assertNotIn("if name and is_cn_domain(name):\n            _cn_sf_lk", src,
                         "单飞不得只挂在 CN 判定下 ✗")
        self.assertIn("_sf_lk, _sf_slot, _sf_owned = _sf_enter(name, qtype)", src,
                      "handle() 必须以通用形态接入单飞 ✓")


class UpstreamFailureNeverSilentDrops(unittest.TestCase):
    """方案 §3 第 67 行：`left≤0` **立即结束** ✓，但"结束"必须给出明确结论 ✗。

    现场缺陷（完成门首轮 ③④ 暴露）：上游全部超时时 `handle()` 走到
    `if uresp is None: r = dot_query(...); if not r: return None` ⇒ 回复侧
    `if resp:` 为假 ⇒ **一个字节都不发** ✗ ⇒ 客户端只能等自己的 i/o timeout
    （实测 9s / 12s / 15s ✗）。这不是"慢"✗，是"静默丢包"✗ ——
    对上层是黑盒超时，无法重试/降级，比 SERVFAIL **更糟** ✗。
    """

    def test_both_reply_paths_build_servfail_on_none(self):
        """源码守卫：UDP 与 TCP 两条回复路径都必须把"无结论"兜成 SERVFAIL ✓。"""
        src = open(GUARD_SRC, encoding="utf-8").read()
        n = src.count("if not resp:\n            resp = mk_servfail(msg)")
        self.assertGreaterEqual(n, 2,
                                "UDP 与 TCP 回复路径都要兜 SERVFAIL ✓（现在只有 %d 处 ✗）" % n)
        self.assertIn("resp_servfail_built", src, "必须有可见计数 ✓（否则又成静默行为 ✗）")

    def test_mk_servfail_is_a_gate_call(self):
        """`mk_servfail` 必须仍在 handle() 的闸门允许列表里 ✓（否则 AST 断言会挡住 ✓）。"""
        t = open(os.path.join(RELEASE_DIR, "tests", "test_guard_finalizer.py"),
                 encoding="utf-8").read()
        self.assertIn('GATE_CALLS = ("_finalize_return", "mk_servfail")', t)


if __name__ == "__main__":
    unittest.main(verbosity=2)
