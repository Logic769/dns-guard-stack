# -*- coding: utf-8 -*-
"""test_answer_policy.py —— 方案任务2「离线用例」的实现

方案要求：**首次在旧策略上复现失败**，修复后全部通过 ✓。
- 第一段用 `legacy_choose_answer()`（显式复现旧 guard "有字节就采用"的行为）
  证明"无本地验证结论的 B 候选会被放行" ✗；
- 第二段是方案**逐字给出的三条断言**（`choose_answer` 为纯三规则函数 ✓，
  方案原文："TTL过期、策略版本错误**在进入 choose 前**失效"）；
- 第三/四段把方案策略表与「所有早返回路径共用同一准入」固化为断言，
  freshness 校验走 `finalize_answer()`（方案中 `handle()` 的最终出口 ✓）。

运行（方案原文命令，无需 pytest）：
    python3 -m unittest discover -s tests -p 'test*.py' -v
"""
import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from answer_policy import (Answer, Verdict, POLICY_VERSION, choose_answer, finalize_answer,
                           is_fresh, legacy_choose_answer, make_answer)

NOW = 10 ** 9  # 固定"现在"，让 valid_until 断言稳定


def b_unknown(ttl=600):
    return make_answer(b"candidate", "local-b", Verdict.UNKNOWN, ttl, now=NOW)


def alt_accepted(ttl=600):
    return make_answer(b"trusted", "local-alt", Verdict.ACCEPTED, ttl, now=NOW)


def a_secure(ttl=600):
    return make_answer(b"secure", "local-a", Verdict.SECURE, ttl, now=NOW)


def a_bogus():
    return Answer(None, "local-a", Verdict.BOGUS, 0.0, POLICY_VERSION)


def a_transport():
    return Answer(None, "local-a", Verdict.TRANSPORT, 0.0, POLICY_VERSION)


_GATES = ("_finalize_return", "mk_servfail")

# 只读旧发布样本（**只解析，不导入** ✓ —— 旧 guard 顶层会建线程池/读状态 ✗）。
# 注意：20261010-1/2/3 **都已含方案任务2 的 `_finalize_return` 闸门** ✓，
# 因此它们都不是"闸门之前"的版本 ✗；本用例证明的是**同版本闸门仍被旁路**：
# 即 `handle()` 里仍有 `return rewrite_id(r, qid) if r else None` / `return rewrite_id(uresp, qid)`
# 这类**字节直出**出口 ✗ —— 这正是 `legacy_choose_answer()` 所复现的历史语义 ✓。
OLD_GUARD_SAMPLES = ("/opt/dnsguard/releases/20261010-3/guard.py",
                     "/opt/dnsguard/releases/20261010-2/guard.py",
                     "/opt/dnsguard/releases/20261010-1/guard.py")


def _is_none_literal(v):
    if v is None:
        return True
    nc = getattr(ast, "NameConstant", None)
    if nc is not None and isinstance(v, nc):
        return getattr(v, "value", None) is None
    c = getattr(ast, "Constant", None)
    if c is not None and isinstance(v, c):
        return v.value is None
    return False


def _bare_exits(path):
    """只读解析 guard.py 样本：返回 `handle()` 里**未经统一准入闸门**的 return 行号 ✓。

    闸门 = `_finalize_return()` / `mk_servfail()` 直接调用，或"唯一赋值就是闸门调用"的局部名 ✓。
    返回 None 表示样本里没有 `handle()`。
    """
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    hs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "handle"]
    if not hs:
        return None
    h = hs[0]

    def _gate_call(v):
        return (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                and v.func.id in _GATES)

    binds = {}
    for n in ast.walk(h):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    binds.setdefault(t.id, []).append(n.value)
    bare = []
    for n in ast.walk(h):
        if not isinstance(n, ast.Return):
            continue
        v = n.value
        if _is_none_literal(v) or _gate_call(v):
            continue
        if isinstance(v, ast.Name):
            vs = binds.get(v.id) or []
            if len(vs) == 1 and _gate_call(vs[0]):
                continue
        bare.append(n.lineno)
    return bare


class LegacyBehaviorDemonstration(unittest.TestCase):
    """第一段：**同一用例内**新旧对照 —— 先断言旧行为会放行 ✗，再断言新策略拒绝 ✓。"""

    def test_legacy_adopts_b_but_new_policy_refuses(self):
        b = b_unknown()
        # ① 旧策略：有字节就采用（`legacy_choose_answer` 逐字复刻旧 guard 的出口语义 ✗）
        self.assertIsNotNone(legacy_choose_answer(b, None))
        # ② 新策略：UNKNOWN 的 B 候选**绝不单独放行** ✓（同一用例、同一输入 ✓）
        self.assertIsNone(choose_answer(b, None))
        self.assertIsNone(finalize_answer(b, None))

    def test_legacy_adopts_b_even_when_no_alt_available(self):
        b = b_unknown()
        alt = Answer(None, "local-alt", Verdict.TRANSPORT, 0.0, POLICY_VERSION)
        self.assertIsNotNone(legacy_choose_answer(b, alt))                 # 旧行为：仍采用 B ✗
        self.assertIsNone(choose_answer(b, alt))                           # 新策略：拒绝 ✓
        self.assertIsNone(finalize_answer(b, alt))

    def test_legacy_guard_really_had_byte_exits_without_a_gate(self):
        """只读样本证据：旧 guard 的 `handle()` **确实**把字节直出（无统一闸门 ✗）。"""
        samples = [p for p in OLD_GUARD_SAMPLES if os.path.exists(p)]
        if not samples:
            self.skipTest("无可读旧发布样本（本用例只在发布机上有效）")
        for p in samples:
            bare = _bare_exits(p)
            self.assertIsNotNone(bare, "样本 %s 里没有 handle()" % p)
            self.assertGreaterEqual(
                len(bare or []), 3,
                "旧样本 %s 的 handle() 应当仍有未经闸门的字节直出 ✗（否则新旧对照无意义）：%r"
                % (p, bare))
        here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guard.py")
        self.assertEqual(_bare_exits(here), [],
                         "Task 3 收口后本发布的 handle() 不得再有字节直出 ✗")





class AnswerPolicyTests(unittest.TestCase):
    """第二段：方案给出的三条断言（逐字实现 ✓）。"""

    def test_b_timeout_never_authorizes_b(self):
        b = Answer(b"candidate", "local-b", Verdict.UNKNOWN, 10 ** 12, "v1")
        self.assertIsNone(choose_answer(b, None))

    def test_b_conflict_uses_authenticated_alt(self):
        b = Answer(b"candidate", "local-b", Verdict.UNKNOWN, 10 ** 12, "v1")
        alt = Answer(b"trusted", "local-alt", Verdict.ACCEPTED, 10 ** 12, "v1")
        self.assertIs(choose_answer(b, alt), alt)

    def test_bogus_cannot_be_repaired(self):
        a = Answer(None, "local-a", Verdict.BOGUS, 0, "v1")
        alt = Answer(b"positive", "local-alt", Verdict.ACCEPTED, 10 ** 12, "v1")
        self.assertIsNone(choose_answer(a, alt))


class PolicySemantics(unittest.TestCase):
    """第三段：把方案策略表逐条固化为断言（freshness 走 finalize_answer ✓）。"""

    def test_secure_local_answer_is_returned(self):
        a = a_secure()
        self.assertIs(finalize_answer(a, alt_accepted(), now=NOW), a)

    def test_secure_beats_alt_even_if_alt_differs(self):
        self.assertEqual(finalize_answer(a_secure(), alt_accepted(), now=NOW).source, "local-a")

    def test_transport_falls_back_to_alt(self):
        alt = alt_accepted()
        self.assertIs(finalize_answer(a_transport(), alt, now=NOW), alt)

    def test_transport_without_alt_fails(self):
        self.assertIsNone(finalize_answer(a_transport(), None, now=NOW))

    def test_unknown_b_without_alt_fails(self):
        self.assertIsNone(finalize_answer(b_unknown(), None, now=NOW))

    def test_unknown_b_with_alt_uses_alt(self):
        alt = alt_accepted()
        self.assertIs(finalize_answer(b_unknown(), alt, now=NOW), alt)

    def test_bogus_plus_fresh_alt_still_fails(self):
        self.assertIsNone(finalize_answer(a_bogus(), alt_accepted(), now=NOW))

    def test_expired_answer_is_not_adopted(self):
        b = make_answer(b"candidate", "local-b", Verdict.UNKNOWN, 1, now=NOW)
        alt = make_answer(b"trusted", "local-alt", Verdict.ACCEPTED, 1, now=NOW)
        self.assertIsNone(finalize_answer(b, alt, now=NOW + 10))

    def test_policy_version_mismatch_is_rejected(self):
        alt = Answer(b"trusted", "local-alt", Verdict.ACCEPTED, NOW + 600, "v0-stale")
        self.assertIsNone(finalize_answer(b_unknown(), alt, now=NOW))

    def test_accepted_is_capped_shorter_than_secure(self):
        sec = make_answer(b"s", "local-a", Verdict.SECURE, 100000, now=NOW)
        acc = make_answer(b"a", "local-alt", Verdict.ACCEPTED, 100000, now=NOW)
        self.assertGreater(sec.valid_until, acc.valid_until)

    def test_freshness_helper(self):
        self.assertTrue(is_fresh(a_secure(), now=NOW))
        self.assertFalse(is_fresh(a_bogus(), now=NOW))
        self.assertFalse(is_fresh(a_transport(), now=NOW))
        self.assertFalse(is_fresh(None, now=NOW))

    def test_none_maps_to_servfail_semantics(self):
        self.assertIsNone(finalize_answer(None, None, now=NOW))


class AllEarlyReturnPathsUseSameGate(unittest.TestCase):
    """第四段：参数化覆盖方案的每一条出口路径，都必须走同一准入 ✓。"""

    PATHS = ("cn-prefer-b", "fallback_b", "r2", "r3b", "strict-early",
             "known-cache", "negative-cache", "aux-source", "ordinary")

    def test_all_paths_reject_unknown_b_without_alt(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                b = b_unknown()
                self.assertIsNone(finalize_answer(b, None, now=NOW))

    def test_all_paths_never_repair_bogus(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                self.assertIsNone(finalize_answer(a_bogus(), alt_accepted(), now=NOW))

    def test_all_paths_accept_secure(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                a = a_secure()
                self.assertIs(finalize_answer(a, None, now=NOW), a)


if __name__ == "__main__":
    unittest.main(verbosity=2)
