# -*- coding: utf-8 -*-
"""N3 精细分档测试（2026-10-16）。

背景（第四份审计 N3）：`classify_response()` 原本"只要 AD=1 就判 SECURE" ——
而 AD 位在第三方通道（见证 `witness` / 国内 `local-cn`）只是**运营方声明**，
不是本地可验凭据 ⇒ 声明被当成硬证据。

精细分档后的口径（只降不升 ✓）：

  | 通道                          | 报文证据            | 档位              |
  |-------------------------------|---------------------|-------------------|
  | `local-a` / `local-alt`（本机）| AD=1                | SECURE（local_ad）|
  | 第三方（witness / local-cn）  | AD=1 + 有效 RRSIG   | SECURE（signed）  |
  | 第三方                        | AD=1 + RRSIG 已过期 | ACCEPTED          |
  | 第三方                        | AD=1 + 无任何签名   | ACCEPTED（核心）  |

并锁定：四档计数进入 guard 的 `_stats`，且指标键已登记。
"""
import io
import os
import socket
import struct
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import alt_adapter  # noqa: E402
import guard  # noqa: E402

TMP = tempfile.mkdtemp(prefix="n3grade-")


def _wname(n):
    out = b""
    for p in n.split("."):
        if p:
            out += bytes([len(p)]) + p.encode("ascii")
    return out + b"\x00"


def mk_wire(name="a.example", ip="1.2.3.4", ad=False, sig=None, now=None, rcode=0, with_a=True):
    """构造一条 DNS 应答。`sig` ∈ None / "valid" / "expired"（覆盖被问类型 A 的 RRSIG）。"""
    now = float(now if now is not None else time.time())
    flags = 0x8180 | (0x0020 if ad else 0) | (rcode & 0xF)
    q = _wname(name) + struct.pack("!HH", 1, 1)
    ans = b""
    n = 0
    if with_a:
        ans += _wname(name) + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
        n += 1
    if sig:
        exp = int(now + 3600) if sig == "valid" else int(now - 3600)
        rd = (struct.pack("!H", 1) + bytes([8, 2]) + struct.pack("!I", 300) +
              struct.pack("!I", exp) + struct.pack("!I", int(now - 86400)) +
              struct.pack("!H", 12345) + b"\xab" * 8)
        ans += _wname(name) + struct.pack("!HHIH", 46, 1, 300, len(rd)) + rd
        n += 1
    return struct.pack("!HHHHHH", 0x4321, flags, 1, n, 0, 0) + q + ans


class AdGradeMatrix(unittest.TestCase):
    """分档矩阵：四档 × 通道。"""

    def test_local_a_ad_without_signature_stays_secure(self):
        w = mk_wire(ad=True)
        v, why = alt_adapter.ad_grade(w, "local-a")
        self.assertEqual((v.value, why), ("secure", "local_ad"))

    def test_local_alt_is_also_local_verified(self):
        w = mk_wire(ad=True)
        v, why = alt_adapter.ad_grade(w, "local-alt")
        self.assertEqual((v.value, why), ("secure", "local_ad"))

    def test_witness_ad_without_signature_is_accepted(self):
        """★ N3 核心：见证通道仅凭 AD 位自称 ⇒ 降级 ACCEPTED。"""
        w = mk_wire(ad=True)
        v, why = alt_adapter.ad_grade(w, "witness")
        self.assertEqual((v.value, why), ("accepted", "ad_declared"))

    def test_local_cn_ad_without_signature_is_accepted(self):
        w = mk_wire(ad=True)
        v, why = alt_adapter.ad_grade(w, "local-cn")
        self.assertEqual((v.value, why), ("accepted", "ad_declared"))

    def test_witness_ad_with_valid_signature_is_secure(self):
        w = mk_wire(ad=True, sig="valid")
        v, why = alt_adapter.ad_grade(w, "witness")
        self.assertEqual((v.value, why), ("secure", "signed"))

    def test_witness_expired_signature_is_accepted(self):
        w = mk_wire(ad=True, sig="expired")
        v, why = alt_adapter.ad_grade(w, "witness")
        self.assertEqual((v.value, why), ("accepted", "sig_expired"))

    def test_local_a_expired_signature_still_secure(self):
        """本机验证通道：AD 由本地 Unbound 验证产生 ⇒ 仍 SECURE（签名剩余只影响 TTL）。"""
        w = mk_wire(ad=True, sig="expired")
        v, why = alt_adapter.ad_grade(w, "local-a")
        self.assertEqual((v.value, why), ("secure", "local_ad"))

    def test_ad_zero_positive_is_accepted(self):
        """回归：AD=0 的正常正答案不受分档影响。"""
        w = mk_wire(ad=False)
        a = alt_adapter.classify_response(w, "witness", ttl=300.0)
        self.assertEqual(a.verdict.value, "accepted")

    def test_ad_zero_returns_no_grade(self):
        """AD=0 ⇒ 不产生档位（防止把普通 accepted 误算成"仅凭 AD 声明"）。"""
        v, why = alt_adapter.ad_grade(mk_wire(ad=False), "witness")
        self.assertIsNone(v)
        self.assertEqual(why, "ad_zero")

    def test_unparseable_returns_no_grade(self):
        v, why = alt_adapter.ad_grade(b"\x00", "witness")
        self.assertIsNone(v)
        self.assertEqual(why, "unparseable")

    def test_ad_zero_creates_no_bucket(self):
        """AD=0 的报文不进入任何 AD 分档桶（计数严格 ⇒ 生产不再出现假计数）。"""
        before = dict(alt_adapter.AD_GRADE)
        alt_adapter.classify_response(mk_wire(ad=False), "witness", ttl=300.0)
        self.assertEqual(alt_adapter.AD_GRADE, before)

    def test_classify_response_uses_grade_for_witness(self):
        w = mk_wire(ad=True)
        a = alt_adapter.classify_response(w, "witness", ttl=300.0)
        self.assertEqual(a.verdict.value, "accepted")

    def test_classify_response_keeps_secure_for_local_a(self):
        w = mk_wire(ad=True)
        a = alt_adapter.classify_response(w, "local-a", ttl=300.0)
        self.assertEqual(a.verdict.value, "secure")

    def test_counts_increase(self):
        before = dict(alt_adapter.AD_GRADE)
        alt_adapter.classify_response(mk_wire(ad=True), "witness", ttl=300.0)
        alt_adapter.classify_response(mk_wire(ad=True, sig="valid"), "witness", ttl=300.0)
        self.assertEqual(alt_adapter.AD_GRADE["ad_declared"], before["ad_declared"] + 1)
        self.assertEqual(alt_adapter.AD_GRADE["signed"], before["signed"] + 1)


class GuardSync(unittest.TestCase):
    """guard 侧：`_alt_classify()` 把四档计数同步进 `_stats`，且键已登记。"""

    def setUp(self):
        guard._stats["ad_grade_ad_declared"] = 0
        guard._stats["ad_grade_local_ad"] = 0

    def test_guard_classify_syncs_ad_grade(self):
        a = guard._alt_classify(mk_wire(ad=True), "witness")
        self.assertIsNotNone(a)
        self.assertEqual(a.verdict.value, "accepted")
        self.assertGreaterEqual(guard._stats.get("ad_grade_ad_declared", 0), 1)

    def test_guard_classify_syncs_local_ad(self):
        a = guard._alt_classify(mk_wire(ad=True), "local-a")
        self.assertIsNotNone(a)
        self.assertEqual(a.verdict.value, "secure")
        self.assertGreaterEqual(guard._stats.get("ad_grade_local_ad", 0), 1)

    def test_guard_counter_only_counts_real_ad_declared(self):
        """接线护栏：guard 的分档计数只认 `ad_declared`/`sig_expired`
        ⇒ AD=0 的普通 accepted（`ad_zero`）永不计入 ✓。"""
        import re
        src = io.open(os.path.join(ROOT, "guard.py"), "r", encoding="utf-8").read()
        self.assertIn('if _w_why in ("ad_declared", "sig_expired"):', src)
        self.assertRegex(src, r"cn_witness_ad_declared_accepted")

    def test_metric_keys_registered(self):
        for k in ("ad_grade_local_ad", "ad_grade_signed", "ad_grade_ad_declared",
                  "ad_grade_sig_expired", "cn_witness_ad_declared_accepted"):
            self.assertIn(k, guard._cn_list_keys, k)
            self.assertIn(k, guard._stats, k)

    def test_source_wiring_has_no_unconditional_ad_secure(self):
        """源码护栏：`classify_response()` 里不得再出现"AD=1 直接 SECURE"。"""
        p = os.path.join(ROOT, "alt_adapter.py")
        with io.open(p, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("    elif ad:\n        v = Verdict.SECURE\n", src)
        self.assertIn("v, _ad_why = ad_grade(wire, source, now)", src)


if __name__ == "__main__":
    unittest.main()
