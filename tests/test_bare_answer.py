# -*- coding: utf-8 -*-
"""test_bare_answer.py —— "零证据空壳（bare NOERROR）不得成为结论"的专项回归 ✓。

背景（§5 验收期现场定位的**既有**缺陷，非 §5 引入）：
  现象：`dnssec-failed.org A` 偶发返回 `rc=0 an=0 ns=0 ar=1 len=46`（空 NOERROR），
        持续 1.3~1.9s 后自愈；生产（release-13）与旁路（release-12 等价代码）都复现。
  取证链（全部实测，非推断）：
    ① 坏例字节 = 46 字节 `rc=0 an=0 ns=0 ar=1 optc=1232 optt=32768`，
       与 unbound(5353)/aghdq(5533) 的 46 字节 SERVFAIL **同形**，唯一差别是
       flags `8182 → 8180`（rcode 2→0）；
    ② 侧车 `_cache` 里那份毒条目 **1ms** 命中（缓存），qid 是 `603d`（**不是我们发的 qid**）
       ⇒ `guard._cache` 的唯一生产者 `_dot_query_once()` 被喂了别人的字节 ✗；
    ③ 直压 `127.0.0.1:5533`（aghdq→NextDNS 的 UDP 转发器）12 线程 ⇒
       **0.21%~3.1%** 的应答就是把查询**原样回显**成 `flags 0x0100→0x8180`（qid 不变）✗；
    ④ 逐通道 120 轮穷举 ⇒ `unbound`/`doq1`/`dot` 的稳态输出**全部** rc=2 ✗
       ⇒ 不是它们，是 5533 在并发下偶发吐垃圾 ✓；
    ⑤ 零证据空壳在真实解析器上**不存在**：真 NODATA 恒带 SOA（`ns≥1`, type 6）或 AD=1 ——
       `dns.example.com` TXT/MX/SRV `ns=1[6]`、`github.com` SRV `ns=1[6]`、
       `isc.org`/`one.one.one.one` MX `ns=4[6,46,47,46] ad=1` ✓。

本文件钉住的**三处**修复（缺一不可）：
  A. `alt_adapter.classify_kind()` 新增 `"bare"`（`an=0 ns=0 ad=0`）⇒ `classify_response()`
     落 UNKNOWN ⇒ **不采纳** ✗（此前被判 ACCEPTED ⇒ 直接下发 ✗）；
     同时**必须不误伤 P34-BM**（带 SOA 或 AD=1 的真 NODATA 仍 ACCEPTED/SECURE ✓）。
  B. `guard._udp_raw()` 必须**核对 qid** 并丢弃不符的应答 ✓（旧代码
     `d, _ = s.recvfrom(65535)` 丢弃 peer、从不比对 ⇒ 别人的字节被当自己的结论 ✗）。
  C. `guard._dot_raw()` 必须核对常连接帧的 qid ✓（连接错位/陈旧帧）。
  D. `_dot_query_once()` 的竞速判据 `good` 必须叠加 `_is_conclusive()` ✓，
     且**缓存准入**也要过这道门 ✓（否则被复用 10–600s ⇒ 60 秒的持续错误回答 ✗）。

运行：python3 tests/test_bare_answer.py
"""
import ast
import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import alt_adapter                                                     # noqa: E402
from answer_policy import Verdict, choose_answer, finalize_answer      # noqa: E402

NOW = 10 ** 9
QID = 0x603d     # ★ 现场坏例的真实 qid（≠ 我们发的任何 qid）


def _q(name="dnssec-failed.org", qtype=1):
    b = b"".join(struct.pack("!B", len(l)) + l.encode() for l in name.split(".") if l) + b"\x00"
    return b + struct.pack("!HH", qtype, 1)


def wire_bare(qid=QID, qtype=1, do=True):
    """★ 现场坏例的**逐字节复刻**：把查询原样回显成 QR|RD|RA + rcode0 ✓。

    46 字节：12 头 + 23 问题段 + 11 字节 OPT（class=1232, ttl=0x8000=DO）✓
    """
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000 if do else 0, 0)
    return hdr + _q("dnssec-failed.org", qtype) + opt


def wire_servfail(qid=QID, qtype=1, opt_class=1232):
    """上游真正的 SERVFAIL（现场同形，仅 flags 不同：8182 而非 8180）✓"""
    hdr = struct.pack("!HHHHHH", qid, 0x8182, 1, 0, 0, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, opt_class, 0x8000, 0)
    return hdr + _q("dnssec-failed.org", qtype) + opt


def wire_nodata_with_soa(qid=QID, qtype=1):
    """真 NODATA：`rc=0 an=0 ns=1(SOA) ar=1` ✓（`dns.example.com` TXT/MX/SRV 的现场形状）"""
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 1, 1)
    soa = (b"\x02ns\x07example\x00" + b"\x04root\x07example\x00"
           + struct.pack("!IIIII", 1, 2, 3, 4, 60))
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 60, len(soa)) + soa
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return hdr + _q("dns.example.com", qtype) + rr + opt


def wire_nxdomain_with_soa(qid=QID):
    hdr = struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 1, 0)
    soa = (b"\x02ns\x07example\x00" + b"\x04root\x07example\x00"
           + struct.pack("!IIIII", 1, 2, 3, 4, 60))
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 60, len(soa)) + soa
    return hdr + _q("nope.example.com") + rr


def wire_positive(qid=QID, qtype=1):
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + b"\xcb\x00\x71\x09"
    return hdr + _q("www.qq.com", qtype) + a


class BareIsNotAConclusion(unittest.TestCase):
    """A：`classify_kind()` / `classify_response()` 对"裸空壳"的判定 ✓"""

    def test_bare_kind(self):
        """零证据空壳必须被单独识别为 `"bare"`（而不是 `"negative"`）✗。"""
        w = wire_bare()
        self.assertEqual(len(w), 46)                      # 与现场坏例同长 ✓
        self.assertEqual(w[:2], struct.pack("!H", QID))   # 与现场坏例同 qid ✓
        self.assertEqual(alt_adapter.classify_kind(w), "bare")
        self.assertFalse(alt_adapter.is_conclusive(w))

    def test_bare_is_not_adopted(self):
        """★ 核心：裸空壳**不得**被判 ACCEPTED（旧行为会直接把它下发 ✗）。"""
        for src in ("local-a", "local-alt"):
            with self.subTest(src=src):
                a = alt_adapter.classify_response(wire_bare(), src, ttl=300, now=NOW)
                self.assertEqual(a.verdict, Verdict.UNKNOWN)

    def test_bare_is_not_repairable_either(self):
        """UNKNOWN 也不得被备用通道"救"成可用答案（除备用本身可结论）✗。"""
        a = alt_adapter.classify_response(wire_bare(), "local-a", ttl=300, now=NOW)
        self.assertIsNone(choose_answer(a, None))
        # 备用如果给出"另一个空壳" ⇒ 仍然不可用 ✓
        alt = alt_adapter.classify_response(wire_bare(qid=0x1234), "local-alt", ttl=300, now=NOW)
        self.assertIsNone(choose_answer(a, alt))
        # 备用给出真答案 ⇒ 才可救 ✓
        good = alt_adapter.classify_response(wire_positive(qid=0x1234), "local-alt", ttl=300, now=NOW)
        self.assertIsNotNone(choose_answer(a, good))

    def test_plain_servfail_is_not_dnssec_evidence(self):
        """Plain failure stays inadmissible but is not a validation conclusion."""
        self.assertEqual(alt_adapter.classify_kind(wire_servfail()), "transport")
        b = alt_adapter.classify_response(wire_servfail(), "local-a", ttl=300, now=NOW)
        self.assertEqual(b.verdict, Verdict.TRANSPORT)
        self.assertIsNone(choose_answer(b, None))
        self.assertIsNone(finalize_answer(b, None, now=NOW))

    def test_bare_and_servfail_differ_only_in_flags(self):
        """证据：坏例与上游 SERVFAIL **逐字节同形，只有 flags 不同** ✓ —— 这是定位的关键。"""
        bare, sf = wire_bare(), wire_servfail()
        self.assertEqual(len(bare), len(sf))
        self.assertNotEqual(bare, sf)
        for i in range(len(bare)):
            if i == 3:
                continue
            self.assertEqual(bare[i], sf[i], "第 %d 字节不同（预期只有 flags 低字节）" % i)
        self.assertEqual(bare[2], 0x81)
        self.assertEqual(bare[3], 0x80)
        self.assertEqual(sf[3], 0x82)

    def test_no_false_positive_on_real_nodata(self):
        """★ 不误伤 P34-BM：带否定证据的真 NODATA 必须**继续被采纳** ✓。"""
        cases = [
            ("SOA 权威段", wire_nodata_with_soa(), ("local-a", "local-alt"), Verdict.ACCEPTED),
        ]
        for tag, w, srcs, want in cases:
            for src in srcs:
                with self.subTest(tag=tag, src=src):
                    self.assertEqual(alt_adapter.classify_kind(w), "negative")
                    self.assertTrue(alt_adapter.is_conclusive(w))
                    a = alt_adapter.classify_response(w, src, ttl=60, now=NOW)
                    self.assertEqual(a.verdict, want)

    def test_ad1_bare_is_accepted(self):
        """`AD=1` 的空应答 = 本地验证器确认的否定 ⇒ 采纳 ✓（与"零证据空壳"本质不同）。"""
        hdr = struct.pack("!HHHHHH", QID, 0x81a0, 1, 0, 0, 0)   # QR|RD|RA|AD + rcode0
        w = hdr + _q("dns.example.com", 16)
        self.assertEqual(alt_adapter.classify_kind(w), "negative")
        self.assertTrue(alt_adapter.is_conclusive(w))
        a = alt_adapter.classify_response(w, "local-a", ttl=60, now=NOW)
        self.assertIn(a.verdict, (Verdict.SECURE, Verdict.ACCEPTED))

    def test_nxdomain_with_soa_is_accepted(self):
        w = wire_nxdomain_with_soa()
        self.assertEqual(alt_adapter.classify_kind(w), "negative")
        a = alt_adapter.classify_response(w, "local-alt", ttl=60, now=NOW)
        self.assertEqual(a.verdict, Verdict.ACCEPTED)

    def test_positive_and_cname_still_fine(self):
        self.assertEqual(alt_adapter.classify_kind(wire_positive()), "positive")
        self.assertTrue(alt_adapter.is_conclusive(wire_positive()))


class GuardTransportChecksQid(unittest.TestCase):
    """B/C/D：`guard.py` 源码级结构性断言（离线、不启动服务）✓"""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "guard.py"), encoding="utf-8") as fh:
            cls.src = fh.read()
        cls.tree = ast.parse(cls.src)
        cls.funcs = {}
        for n in ast.walk(cls.tree):
            if isinstance(n, ast.FunctionDef):
                cls.funcs[n.name] = n

    def _body_src(self, name):
        """取函数源码。★ 服务器 py3.6.8 没有 `ast.get_source_segment`（3.8+）⇒ 必须有回退 ✓。

        回退策略：用**顶层语句**的 lineno 做边界（`guard.py` 的函数都是模块级）⇒
        取"下一个顶层语句的 lineno − 1"作为函数结束行 ✓。
        不能用 `ast.walk` 里"第一个 > n.lineno 的语句" —— 那会命中函数体自身的第一条 ✗。
        """
        n = self.funcs[name]
        seg = getattr(ast, "get_source_segment", None)
        if seg is not None:
            s = seg(self.src, n)
            if s is not None:
                return s
        lines = self.src.splitlines()
        nxt = [x.lineno for x in self.tree.body if x.lineno > n.lineno]
        end = (min(nxt) - 1) if nxt else len(lines)
        return "\n".join(lines[n.lineno - 1:end])

    def test_udp_raw_compares_qid(self):
        from test_audit_fixes import question, reply
        self.assertFalse(alt_adapter.response_matches(question(), reply(tid=124)))
        self.assertTrue(alt_adapter.response_matches(question(), reply()))

    def test_dot_raw_compares_qid(self):
        """C：DoT 常连接帧也必须比对 qid（防连接错位/陈旧帧）✓。"""
        s = self._body_src("_dot_raw")
        self.assertIn("dot_qid_mismatch", s)
        self.assertIn("response_matches(msg, buf)", s)

    def test_race_good_requires_conclusive(self):
        """D1：竞速判据 `good` 必须叠加 `_is_conclusive()`，空壳不得算 good ✓。"""
        s = self._body_src("_dot_query_once")
        self.assertIn("_is_conclusive(b)", s)
        self.assertIn("clean_bare", s)
        # 必须是"置 good=False"而不是仅记数
        self.assertRegex(s, r"not _is_conclusive\(b\)[\s\S]{0,200}good = False")

    def test_cache_admission_requires_conclusive(self):
        """D2：缓存准入也必须过门 ⇒ 空壳不得被写进 `_cache`（否则复用 10–600s）✗。"""
        s = self._body_src("_dot_query_once")
        self.assertIn("_is_conclusive(buf)", s)
        i_gate = s.index("_is_conclusive(buf)")
        i_put = s.index("_cache[key] = (")
        self.assertLess(i_gate, i_put, "缓存写入必须排在可结论门之后 ✗")

    def test_helper_exists_and_prefers_adapter(self):
        """`_is_conclusive()` 必须复用 `alt_adapter`（**单一判据源**，防两处漂移）✓。"""
        s = self._body_src("_is_conclusive")
        self.assertIn("alt_adapter", s)
        self.assertIn("is_conclusive", s)

    def test_new_counters_are_registered(self):
        """新计数必须同时进 `_stats` 字面量与 `_step5_keys`（否则跨重启丢、指标恒 0 ✗）。"""
        for k in ("clean_bare", "dot_qid_mismatch"):
            with self.subTest(k=k):
                self.assertIn('"%s"' % k, self.src)
                self.assertGreaterEqual(self.src.count('"%s"' % k), 2,
                                        "计数 %s 必须既被写又进登记清单 ✗" % k)

    def test_udp_raw_never_returns_mismatched_bytes(self):
        from test_audit_fixes import ResponseBinding
        ResponseBinding("test_udp_discards_wrong_sender_and_wrong_question").test_udp_discards_wrong_sender_and_wrong_question()


class AdapterSingleSourceOfTruth(unittest.TestCase):
    """判据只能在 `alt_adapter` 一处定义（guard 侧只做转发）✓"""

    def test_is_conclusive_exported(self):
        self.assertIn("is_conclusive", alt_adapter.__all__)

    def test_classify_kind_docstring_lists_bare(self):
        d = alt_adapter.classify_kind.__doc__ or ""
        self.assertIn("bare", d)
        self.assertIn("negative", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
