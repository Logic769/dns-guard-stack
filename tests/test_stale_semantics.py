# -*- coding: utf-8 -*-
"""§3.2 统一 stale 出口语义的回归用例（2026-10-15）。

覆盖：
  · `alt_adapter.stale_flags()` 的识别边界（EDE 3/19 = stale；EDE 15 = bogus 不是 stale；
    无 OPT / 无 EDE 的 TTL=0 **不是** stale；畸形报文不可判定 ⇒ -1）；
  · `guard._stale_of()` 的委托与"绝不 fail-closed"；
  · `guard._finalize_return()` **两条出口路径**（可采纳快路 + 终局快路）都接入统一判定
    —— 用源码守卫断言，避免依赖运行期状态。
"""
import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import alt_adapter  # noqa: E402


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _wire(ttl=0, ede=None, rcode=0, an=True, with_opt=True):
    """构造一个 A 响应；`ede` 非 None 时在 OPT 里带 EDE（info-code）。"""
    q = _name("example.com") + struct.pack("!HH", 1, 1)
    an_count = 1 if an else 0
    ar = 1 if with_opt else 0
    body = b""
    if an:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes([1, 2, 3, 4])
    if with_opt:
        rdata = b""
        if ede is not None:
            rdata = struct.pack("!HHH", 15, 2, ede)
        body += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(rdata)) + rdata
    hdr = struct.pack("!HHHHHH", 0x1234, (0x8180 | rcode) & 0xFFFF, 1, an_count, 0, ar)
    return hdr + q + body


class StaleFlagsRecognition(unittest.TestCase):
    def test_ede3_stale_answer(self):
        self.assertEqual(alt_adapter.stale_flags(_wire(ttl=0, ede=3)), (True, 3, 0))

    def test_ede19_stale_nxdomain(self):
        self.assertEqual(alt_adapter.stale_flags(_wire(ttl=0, ede=19)), (True, 19, 0))

    def test_ede15_bogus_is_not_stale(self):
        isst, ede, mttl = alt_adapter.stale_flags(_wire(ttl=30, ede=15))
        self.assertFalse(isst)
        self.assertEqual(ede, 0)
        self.assertEqual(mttl, 30)

    def test_no_opt_is_not_stale(self):
        isst, ede, mttl = alt_adapter.stale_flags(_wire(ttl=300, with_opt=False))
        self.assertFalse(isst)
        self.assertEqual(ede, 0)
        self.assertEqual(mttl, 300)

    def test_zero_ttl_without_ede_is_not_stale(self):
        """审计明确要求：TTL=0 本身不是伪造证据 ⇒ 不得判成 stale、不得拒答。"""
        isst, ede, mttl = alt_adapter.stale_flags(_wire(ttl=0, ede=None))
        self.assertFalse(isst)
        self.assertEqual(ede, 0)
        self.assertEqual(mttl, 0)

    def test_undeciable_wire_is_safe(self):
        for bad in (b"", b"\x00" * 5, None, b"\x12\x34"):
            self.assertEqual(alt_adapter.stale_flags(bad), (False, 0, -1))

    def test_stale_codes_constant(self):
        self.assertEqual(tuple(alt_adapter.STALE_EDE_CODES), (3, 19))


class GuardUnifiedStale(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = os.path.join(ROOT, "guard.py")
        with open(src, "rb") as fh:
            cls.guard_src = fh.read().decode("utf-8", "replace")

    def test_stale_of_is_defined_and_delegates(self):
        self.assertIn("def _stale_of(wire):", self.guard_src)
        self.assertIn("_A.stale_flags(wire)", self.guard_src)
        self.assertIn("def _stale_note(kind, name, ede, min_ttl):", self.guard_src)

    def test_both_exit_paths_call_unified_check(self):
        # 定义 1 次 + 可采纳快路 1 次 + 终局快路 1 次
        self.assertGreaterEqual(self.guard_src.count("_stale_of("), 3)
        self.assertIn("_stale_note(None, name, _ede, _mttl)", self.guard_src)
        self.assertIn("_stale_note(kind, name, _ede, _mttl)", self.guard_src)

    def test_admissible_fast_path_skips_cache_on_stale(self):
        """可采纳快路遇显式 stale ⇒ 先记账并直接返回，**不写准入缓存**。"""
        fn = self.guard_src.split("def _finalize_return(", 1)[1]
        seg = fn.split('if a_ans.verdict.value in ("secure", "accepted"):', 1)[1]
        seg = seg.split("_adm_cache_put", 1)[0]
        self.assertIn("_stale_of(wire)", seg)
        self.assertIn("if _ist:", seg)
        self.assertIn("return rewrite_id(wire, qid)", seg)

    def test_counter_names_present(self):
        self.assertIn('_stats["stale_out"]', self.guard_src)
        self.assertIn('"stale_out_" + _lbl', self.guard_src)


class GuardRuntimeDelegation(unittest.TestCase):
    def test_guard_stale_of_matches_adapter(self):
        try:
            import guard  # noqa: F401
        except Exception as exc:                       # pragma: no cover
            self.skipTest("guard 不可导入: %s" % exc)
        self.assertEqual(guard._stale_of(_wire(ttl=0, ede=3))[0], True)
        self.assertEqual(guard._stale_of(_wire(ttl=0, ede=19))[1], 19)
        self.assertEqual(guard._stale_of(_wire(ttl=60, ede=None))[0], False)
        # 绝不 fail-closed：坏字节也只当作"非 stale"
        self.assertEqual(guard._stale_of(b"\x00" * 7), (False, 0, -1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
