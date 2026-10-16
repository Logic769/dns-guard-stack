# -*- coding: utf-8 -*-
"""test_alt_adapter.py —— 认证 A/alt 适配器的离线用例（方案任务2）

方案硬性要求：**`ACCEPTED` 只能由批准的认证 A/alt 适配器产生；B=AD0 不能被适配器标成 ACCEPTED** ✓。
本用例全部离线（不触网 ✓）：用自造报文验证分类，再用 `answer_policy` 验证裁决衔接 ✓。

运行：python3 -m unittest discover -s tests -p 'test*.py' -v
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import alt_adapter
from answer_policy import Verdict, choose_answer, finalize_answer

NOW = 10 ** 9


def mk_wire(rcode=0, ad=False, answers=1, qtype=1, rdata=b"\x01\x02\x03\x04", authority=0):
    """构造最小合法报文：1 个问题 + N 个（A/AAAA）答案 + 可选 M 条权威段 SOA ✓。

    ★ 2026-10-11：`authority` 参数用于区分**真 NODATA**（带 SOA 否定证据）与
      **零证据空壳**（`an=0 ns=0 ad=0`）—— 后者是 5533 UDP 转发器在并发下把查询
      原样回显的产物 ✗（现场实测），必须与前者分开断言 ✓。
    """
    flags = 0x8180 | (0x20 if ad else 0) | (rcode & 0xF)
    q = b"\x03www\x07example\x03com\x00" + struct.pack("!HH", qtype, 1)
    body = q
    for _ in range(answers):
        body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata
    for _ in range(authority):
        # 权威段 SOA（type=6）；rdata 内容不必真实，只为让 ns>0 ✓
        soa = b"\x02ns\x07example\x00" + b"\x04root\x07example\x00" + struct.pack("!IIIII", 1, 2, 3, 4, 60)
        body += b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 60, len(soa)) + soa
    return struct.pack("!HHHHHH", 0x1234, flags, 1, answers, authority, 0) + body


class ClassifyResponse(unittest.TestCase):

    def test_ad1_is_secure(self):
        a = alt_adapter.classify_response(mk_wire(ad=True), "local-alt", ttl=300, now=NOW)
        self.assertEqual(a.verdict, Verdict.SECURE)
        self.assertEqual(a.source, "local-alt")

    def test_rc0_no_ad_with_address_is_accepted(self):
        a = alt_adapter.classify_response(mk_wire(ad=False, answers=1), "local-a", ttl=300, now=NOW)
        self.assertEqual(a.verdict, Verdict.ACCEPTED)

    def test_nxdomain_is_accepted_negative(self):
        a = alt_adapter.classify_response(mk_wire(rcode=3, answers=0, authority=1), "local-alt",
                                          ttl=300, now=NOW)
        self.assertEqual(a.verdict, Verdict.ACCEPTED)

    def test_plain_servfail_is_transport(self):
        a = alt_adapter.classify_response(mk_wire(rcode=2, answers=0), "local-alt", ttl=300, now=NOW)
        self.assertEqual(a.verdict, Verdict.TRANSPORT)

    def test_noerror_without_address_from_authenticated_is_accepted(self):
        """P34-BM（2026-10-10）：**认证源的裸 NODATA 被采纳** ✓。

        原用例断言 UNKNOWN ✗ —— 那是**有意变更前**的行为：它会把这个
        "域名确实没有 A 记录"的正常结论变成 SERVFAIL ✗（实测 `dns.example.com` 每分钟一次 ✓，
        属本实现"只信正向、不信否定"的不对称造成的真实回归 ✗）。
        方案原文允许："认证源给出经过本地验证的否定 ⇒ 返回认证源否定" ✓。
        安全边界不变 ✓：B（local-b）的 NODATA 仍恒为 UNKNOWN ✗ ——
        见 `test_local_b_never_becomes_adoptable`（必须继续通过 ✓）。

        ★ 2026-10-11 收窄（新增"否定证据"前提，**不误伤 P34-BM** ✗）：
          真 NODATA 必须带否定证据（权威段有 RR，或 AD=1）。现场实测证据：
            · `dns.example.com` TXT/MX/SRV ⇒ `rc=0 an=0 ns=1 [SOA] ar=1` ✓
            · `github.com` SRV         ⇒ `rc=0 an=0 ns=1 [SOA] ar=1` ✓
            · `isc.org` / `one.one.one.one` MX ⇒ `ns=4 [SOA,RRSIG,NSEC,RRSIG] ad=1` ✓
          而 **零证据空壳**（`an=0 ns=0 ad=0`）在真实解析器上**不存在** ✗ ——
          它只来自本机 UDP 转发器 `127.0.0.1:5533` 在并发下把查询原样回显
          （flags `0x0100→0x8180`，qid 不变；实测复现率 0.21%~3.1%）✗，
          旧代码把它当"认证源的否定"采纳 ⇒ 持续 10–600s 告诉客户端"该域名没有 A 记录"，
          而真相是 **DNSSEC bogus ⇒ SERVFAIL** ✗（安全结论被降级）。
        """
        # ① 带否定证据的真 NODATA ⇒ 仍然采纳 ✓（P34-BM 不受影响）
        a = alt_adapter.classify_response(mk_wire(rcode=0, answers=0, authority=1), "local-alt",
                                          ttl=300, now=NOW)
        self.assertEqual(a.verdict, Verdict.ACCEPTED)
        # ② AD=1 的空应答（本地验证器确认的否定）⇒ 同样被采纳 ✓（`AD` 优先 ⇒ 判 SECURE）
        a_ad = alt_adapter.classify_response(mk_wire(rcode=0, answers=0, ad=True), "local-a",
                                             ttl=300, now=NOW)
        self.assertIn(a_ad.verdict, (Verdict.SECURE, Verdict.ACCEPTED))
        # ③ 零证据空壳 ⇒ **不采纳** ✗（必须变成可识别的中间态，由上层 fail-closed 或重试）
        a2 = alt_adapter.classify_response(mk_wire(rcode=0, answers=0), "local-a", ttl=300, now=NOW)
        self.assertEqual(a2.verdict, Verdict.UNKNOWN)
        self.assertEqual(alt_adapter.classify_kind(mk_wire(rcode=0, answers=0)), "bare")
        self.assertFalse(alt_adapter.is_conclusive(mk_wire(rcode=0, answers=0)))
        self.assertTrue(alt_adapter.is_conclusive(mk_wire(rcode=0, answers=0, authority=1)))
        self.assertTrue(alt_adapter.is_conclusive(mk_wire(answers=1)))
        self.assertFalse(alt_adapter.is_conclusive(mk_wire(rcode=2, answers=0)))

    def test_truncated_or_none_is_none(self):
        self.assertIsNone(alt_adapter.classify_response(None, "local-alt"))
        self.assertIsNone(alt_adapter.classify_response(b"\x00" * 5, "local-alt"))

    def test_local_b_never_becomes_adoptable(self):
        """★ 方案硬要求：B(AD=0) 不能被适配器标成 ACCEPTED/SECURE ✓。"""
        for rcode, ad in ((0, False), (0, True), (3, False)):
            with self.subTest(rcode=rcode, ad=ad):
                a = alt_adapter.classify_response(mk_wire(rcode=rcode, ad=ad), "local-b", ttl=300, now=NOW)
                self.assertEqual(a.verdict, Verdict.UNKNOWN)
                self.assertIsNone(a.wire)          # 连字节都不给 ⇒ 无法被误采用 ✓
                self.assertIsNone(choose_answer(a, None))


class AnswerPolicyIntegration(unittest.TestCase):

    def test_bogus_alt_cannot_repair_local_b(self):
        b = alt_adapter.classify_response(mk_wire(ad=False), "local-b", ttl=300, now=NOW)
        alt_bogus = alt_adapter.classify_response(mk_wire(rcode=2, answers=0), "local-alt", ttl=300, now=NOW)
        self.assertIsNone(finalize_answer(b, alt_bogus, now=NOW))

    def test_secure_alt_rescues_when_b_is_unvalidated(self):
        b = alt_adapter.classify_response(mk_wire(ad=False), "local-b", ttl=300, now=NOW)
        alt = alt_adapter.classify_response(mk_wire(ad=True), "local-alt", ttl=300, now=NOW)
        self.assertIs(finalize_answer(b, alt, now=NOW), alt)

    def test_accepted_alt_rescues(self):
        b = alt_adapter.classify_response(mk_wire(ad=False), "local-b", ttl=300, now=NOW)
        alt = alt_adapter.classify_response(mk_wire(ad=False, answers=1), "local-alt", ttl=300, now=NOW)
        picked = finalize_answer(b, alt, now=NOW)
        self.assertIsNotNone(picked)
        self.assertEqual(picked.verdict, Verdict.ACCEPTED)

    def test_local_a_accepted_used_when_b_unvalidated(self):
        b = alt_adapter.classify_response(mk_wire(ad=False), "local-b", ttl=300, now=NOW)
        a = alt_adapter.classify_response(mk_wire(ad=False, answers=2), "local-a", ttl=300, now=NOW)
        picked = finalize_answer(a, b, now=NOW)      # 注意：B 不能当 alternate 用 ✓
        self.assertEqual(picked.verdict, Verdict.ACCEPTED)
        self.assertEqual(picked.source, "local-a")


class AltGating(unittest.TestCase):

    def test_query_alt_disabled_returns_none(self):
        old = alt_adapter.ALT_ENABLED
        try:
            alt_adapter.ALT_ENABLED = False
            self.assertIsNone(alt_adapter.query_alt("www.iana.org", 1, timeout=0.2, now=NOW))
        finally:
            alt_adapter.ALT_ENABLED = old

    def test_default_addr_is_loopback_5357(self):
        self.assertTrue(alt_adapter.ALT_ADDR.startswith("127.0.0.1"))

    def test_count_answers_handles_aaaa(self):
        w = mk_wire(ad=False, answers=2, qtype=28, rdata=b"\x20\x01" + b"\x00" * 14)
        self.assertEqual(alt_adapter.count_answers(w), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
