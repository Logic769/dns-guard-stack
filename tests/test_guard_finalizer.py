# -*- coding: utf-8 -*-
"""test_guard_finalizer.py —— Task 3「统一并验证答案准入出口」的回归用例。

本文件覆盖审计清单的 P0-1 / P0-2 / P1-1 / P1-2 / P2-1 / P0-3：

  ① 行为面（`FinalizerBehavior`）——参数化 `qtype ∈ (1,28,15,16,5,64,65)`：
       · `local-b` 来源**恒 SERVFAIL**（B 的候选恒为 UNKNOWN ⇒ 不可下发 ✓）；
       · BOGUS **恒 SERVFAIL**（不可被 alt / 准入缓存 / 认证源重试"修复" ✓）；
       · SECURE / ACCEPTED 来源**原样通过**并写入准入缓存 ✓；
       · 准入缓存命中时**重写 qid** ✓。
  ② 静态面（`HandleHasNoBypass`）★最重要★ —— 用 `ast` 遍历 `guard.handle()` 的**每一个**
     `Return`，断言它只可能是 `_finalize_return(...)` / `mk_servfail(...)` / `None`
     （或"唯一赋值就是闸门调用"的局部名 ✓）。这是防止 P0-1 回退的**唯一有效手段** ✓。
     规则是**收紧**而非放宽 ✓：没有任何人工白名单；任何裸变量 / 裸 `rewrite_id(...)` /
     `IfExp` 出口都会 FAIL 并打印行号 ✓。
  ③ `_policy_cn_answer()` 只返回 `Answer` / None（P0-2）✓ —— 用 AST 断言它**不含任何
     直接产出字节的 return**（无 `Attribute`/`Subscript`/`Call` 出口，且函数体内无 `rewrite_id`）。
  ④ `domestic()` 的 `src` 标签 与 `_LABEL_MAP` **一一对应**（P1-1）✓ —— §6 起含
      `_pol_label()` 动态折算的 `CNB`（⇒ `local-cn` ✓，见 `test_cn_domestic.py` ✓）。
  ⑤ 准入缓存字段与 TTL（P1-2）✓。

**状态隔离**：本文件在 `import guard` **之前**把 `GUARD_STATE_DIR` / `GUARD_LOG` 指到
`tempfile.mkdtemp()` ✓ —— 绝不触碰 `/opt/dnsguard`、`/opt/dnsguard/verifier-state` 等生产目录 ✓。
不触网 ✓（`alt_adapter.query_alt` 与 `guard._retry_authenticated` 在用例内被替换为桩 ✓）。

运行（与发布约定一致）：
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
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
sys.path.insert(0, RELEASE_DIR)

# ⚠️ 必须在 import guard 之前：生产状态目录 / 日志全部隔离到临时目录 ✓
_TMP = tempfile.mkdtemp(prefix="guard-finalizer-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)

import alt_adapter                                        # noqa: E402
import guard                                              # noqa: E402
from answer_policy import (Answer, POLICY_VERSION, Verdict, choose_answer,   # noqa: E402
                           finalize_answer, make_answer)

# 双保险：即使 guard 已被别的用例导入过，也强制隔离并开启策略模式 ✓
guard.STATE_DIR = _TMP
guard.LOG = os.environ["GUARD_LOG"]
guard.POLICY_MODE = True

QID = 0x1234
NAME = "unit.test.example"
QTYPES = (1, 28, 15, 16, 5, 64, 65)
GATE_CALLS = ("_finalize_return", "mk_servfail")

# 旧（未收口）只读样本：生产前身 20261010-3 ✓（sha256 2caddce6… 见报告）
OLD_SAMPLE = "/opt/dnsguard/releases/20261010-3/guard.py"
QNAME = b"\x04unit\x04test\x07example\x00"


# ---------------------------------------------------------------- 报文工具
def mk_query(qtype=1, qid=QID):
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + QNAME + struct.pack("!HH", qtype, 1))


def mk_wire(qtype=1, rcode=0, ad=False, answers=1, qid=QID, ttl=300):
    """最小合法**应答**：1 个问题 + N 条（qtype 类型的）记录 ✓。"""
    flags = 0x8180 | (0x20 if ad else 0) | (rcode & 0xF)
    rdata = {1: b"\x01\x02\x03\x04", 28: b"\x20\x01" + b"\x00" * 14}.get(qtype, b"\x00\x00")
    body = QNAME + struct.pack("!HH", qtype, 1)
    for _ in range(answers):
        body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return struct.pack("!HHHHHH", qid, flags, 1, answers, 0, 0) + body


def rcode_of(wire):
    return struct.unpack("!H", wire[2:4])[0] & 0xF


# ---------------------------------------------------------------- ① 行为
class FinalizerBehavior(unittest.TestCase):
    """出口闸门 `_finalize_return()` 的可观察行为 ✓。"""

    def setUp(self):
        guard._ADM_CACHE.clear()
        guard._dl_begin()
        self._alt_q = alt_adapter.query_alt
        self._alt_c = alt_adapter.classify_response
        self._retry = guard._retry_authenticated
        self._hit = guard._adm_cache_get
        alt_adapter.query_alt = lambda *a, **k: None       # 不触网 ✓
        guard._retry_authenticated = lambda *a, **k: None  # 不触网 ✓

    def tearDown(self):
        alt_adapter.query_alt = self._alt_q
        guard._retry_authenticated = self._retry
        guard._ADM_CACHE.clear()

    def _gate(self, wire, kind, qtype, qid=QID):
        return guard._finalize_return(wire, kind, NAME, qtype, qid, mk_query(qtype, qid))

    # ---- local-b：恒 SERVFAIL ✓
    def test_local_b_source_is_always_servfail(self):
        for qtype in QTYPES:
            with self.subTest(qtype=qtype):
                # 内容"完美"（AD=1 + 有记录）也绝不采纳 ✓
                w = mk_wire(qtype, ad=True, answers=1)
                b = alt_adapter.classify_response(w, "local-b", ttl=300.0)
                self.assertEqual(b.verdict, Verdict.UNKNOWN, "B 的候选必须恒为 UNKNOWN")
                self.assertIsNone(b.wire, "B 的候选不得带字节 ⇒ 无法被误采用")
                self.assertIsNone(choose_answer(b, None), "UNKNOWN 的 B 候选不可单独放行")
                self.assertEqual(rcode_of(self._gate(w, "local-b", qtype)), 2)
                self.assertIsNone(guard._ADM_CACHE.get(guard._adm_key(NAME, qtype)),
                                  "B 的候选绝不入准入缓存")

    # ---- BOGUS：恒 SERVFAIL（alt / 缓存 / 重试都不得"修复"）✓
    def test_bogus_source_is_never_repaired(self):
        for qtype in QTYPES:
            with self.subTest(qtype=qtype):
                guard._ADM_CACHE.clear()
                w = dnssec_failure(mk_wire(qtype, rcode=2, answers=0))
                a = alt_adapter.classify_response(w, "clean-channel", ttl=300.0)
                self.assertEqual(a.verdict, Verdict.BOGUS)
                alt_ok = alt_adapter.classify_response(mk_wire(qtype, ad=True, answers=1),
                                                       "local-alt", ttl=300.0)
                alt_adapter.query_alt = lambda *x, **k: alt_ok
                guard._retry_authenticated = lambda *x, **k: alt_ok
                # 策略层：BOGUS 不可被任何备用修复 ✓
                self.assertIsNone(finalize_answer(a, alt_ok))
                self.assertEqual(rcode_of(self._gate(w, "clean-channel", qtype)), 2)
                # 再验"缓存也不得修复"：先塞一个**已准入**的好答案 ✓
                self._gate(mk_wire(qtype, ad=True, answers=1), "local-a", qtype)
                self.assertIsNotNone(guard._ADM_CACHE.get(guard._adm_key(NAME, qtype)))
                self.assertEqual(rcode_of(self._gate(w, "clean-channel", qtype)), 2)

    # ---- SECURE / ACCEPTED：原样通过 + 入缓存 ✓
    def test_secure_and_accepted_pass_through_and_are_cached(self):
        for qtype in QTYPES:
            for ad, want in ((True, "secure"), (False, "accepted")):
                with self.subTest(qtype=qtype, ad=ad):
                    guard._ADM_CACHE.clear()
                    w = mk_wire(qtype, ad=ad, answers=1)
                    a = alt_adapter.classify_response(w, "local-a", ttl=300.0)
                    self.assertEqual(a.verdict.value, want)
                    self.assertEqual(self._gate(w, "local-a", qtype), w, "可采纳来源必须原样通过")
                    rec = guard._ADM_CACHE.get(guard._adm_key(NAME, qtype))
                    self.assertIsNotNone(rec, "可采纳答案必须写入准入缓存")
                    self.assertEqual(rec["verdict"], want)
                    self.assertEqual(rec["qtype"], qtype)
                    self.assertIn("valid_until", rec)
                    self.assertGreater(rec["valid_until"], time.time())

    # ---- 缓存命中：重写 qid ✓
    def test_cache_hit_rewrites_qid(self):
        for qtype in QTYPES:
            with self.subTest(qtype=qtype):
                guard._ADM_CACHE.clear()
                good = mk_wire(qtype, ad=True, answers=1, qid=0x0001)
                self._gate(good, "local-a", qtype, qid=0x0001)          # 填缓存 ✓
                self.assertIsNotNone(guard._adm_cache_get(NAME, qtype))
                out = self._gate(mk_wire(qtype, ad=False, answers=1, qid=0x0002),
                                 "local-b", qtype, qid=0xBEEF)
                self.assertEqual(out[:2], struct.pack("!H", 0xBEEF), "缓存命中必须重写 qid")
                self.assertEqual(out[2:], good[2:], "缓存命中只换 qid、不动其余字节")

    # ---- P0-2：`_policy_cn_answer` 只返回 Answer ✓
    def test_policy_cn_answer_returns_answer_object_not_bytes(self):
        guard._ADM_CACHE.clear()
        w = mk_wire(1, ad=True, answers=1)
        self._gate(w, "local-a", 1)                                     # 填缓存 ✓
        ans = guard._policy_cn_answer(NAME, 1, None, None, deadline=time.time() + 3.0)
        self.assertIsInstance(ans, Answer, "P0-2：只允许返回 Answer / None")
        self.assertNotIsInstance(ans, (bytes, bytearray))
        self.assertEqual(ans.source, "local-a")
        self.assertEqual(ans.verdict, Verdict.SECURE)
        self.assertGreater(ans.valid_until, time.time())

    # ---- P2-1：闸门自身绝不 fail-open ✓
    def test_classify_failure_is_fail_closed(self):
        for kind in ("local-a", "clean-channel", "negative-cache", "strict", "local-b"):
            with self.subTest(kind=kind):
                out = guard._finalize_return(b"\x00" * 5, kind, NAME, 1, QID, mk_query(1))
                self.assertEqual(rcode_of(out), 2, "无法分类的字节必须 SERVFAIL（fail-closed）")


# ---------------------------------------------------------------- ⑤ P1-2
class AdmCacheTTL(unittest.TestCase):
    """准入缓存：TTL 取自答案 + 字段完整 ✓（P1-2）。"""

    def test_ttl_taken_from_answer_valid_until(self):
        now = time.time()
        a = Answer(b"x", "local-alt", Verdict.ACCEPTED, now + 7.0, POLICY_VERSION)
        self.assertAlmostEqual(guard._adm_ttl_from(a, 300.0, now=now), 7.0, places=3)
        self.assertEqual(guard._adm_ttl_from(a, 3.0, now=now), 3.0, "cap 必须生效")
        dead = Answer(b"x", "local-alt", Verdict.ACCEPTED, now - 1.0, POLICY_VERSION)
        self.assertEqual(guard._adm_ttl_from(dead, 300.0, now=now), 0.0)

    def test_zero_ttl_never_cached_and_fields_present(self):
        guard._ADM_CACHE.clear()
        guard._adm_cache_put(NAME, 1, b"\x00" * 12, "accepted", "local-alt", 0.0)
        self.assertIsNone(guard._ADM_CACHE.get(guard._adm_key(NAME, 1)),
                          "零 TTL / 已过期答案**不得**入缓存（旧 60s 补丁已删除 ✓）")
        guard._adm_cache_put(NAME, 1, b"\x00" * 12, "accepted", "local-alt", 5.0)
        rec = guard._ADM_CACHE.get(guard._adm_key(NAME, 1))
        self.assertIsNotNone(rec)
        self.assertEqual(rec["qtype"], 1)
        self.assertIn("valid_until", rec)
        self.assertAlmostEqual(rec["valid_until"], rec["until"], places=3)


# ---------------------------------------------------------------- ③/④ AST
def _str_const(node):
    """取字符串字面量的值 ✓ —— 必须**同时**兼容 3.6（`ast.Str`）与 3.8+（`ast.Constant`）✓。

    现场坑：原来直接写 `isinstance(node, ast.Str)` ✗ ⇒ 在 3.14 上 `ast.Str` 已删除 ⇒
    `AttributeError: module 'ast' has no attribute 'Str'` ✗（发布环境是 py3.6.8，
    但本地开发机是 3.14，两边必须都能跑 ✓）。
    """
    sc = getattr(ast, "Str", None)
    if sc is not None and isinstance(node, sc):
        return node.s
    c = getattr(ast, "Constant", None)
    if c is not None and isinstance(node, c) and isinstance(node.value, str):
        return node.value
    return None


def _is_none_literal(node):
    if node is None:
        return True
    nc = getattr(ast, "NameConstant", None)
    if nc is not None and isinstance(node, nc):
        return getattr(node, "value", None) is None
    c = getattr(ast, "Constant", None)
    if c is not None and isinstance(node, c):
        return node.value is None
    return False


def _gate_only_returns(fn):
    """遍历 fn 的每个 Return，返回 (allowed, offenders)。

    允许且仅允许（**零人工白名单** ✓）：
      ① 实参是 `None` 字面量；
      ② 实参是 `_finalize_return(...)` / `mk_servfail(...)` 调用；
      ③ 实参是局部名字，且该名字在 fn 内的**唯一**赋值就是 ② 类调用
         （等价于直接 return 闸门结果 ⇒ 例如 P0-1 ③ 的 `_out`）。
    """
    bindings = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    bindings.setdefault(t.id, []).append(n.value)
    allowed, offenders = [], []
    for r in ast.walk(fn):
        if not isinstance(r, ast.Return):
            continue
        v = r.value
        if _is_none_literal(v):
            allowed.append((r.lineno, "None"))
        elif isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in GATE_CALLS:
            allowed.append((r.lineno, "%s(...)" % v.func.id))
        elif isinstance(v, ast.Name):
            vs = bindings.get(v.id) or []
            if (len(vs) == 1 and isinstance(vs[0], ast.Call)
                    and isinstance(vs[0].func, ast.Name) and vs[0].func.id in GATE_CALLS):
                allowed.append((r.lineno, "%s(...) → %s" % (vs[0].func.id, v.id)))
            else:
                offenders.append((r.lineno, "return %s（%d 处赋值 ⇒ 不是闸门结果 ✗）"
                                  % (v.id, len(vs))))
        else:
            offenders.append((r.lineno, "return %s ✗" % ast.dump(v)[:90]))
    return allowed, offenders


def _func(tree, name):
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise AssertionError("未找到函数 %s（源码结构可能已变）" % name)


class HandleHasNoBypass(unittest.TestCase):
    """★ 最重要 ★ 把"handle() 无旁路"固化成 AST 回归断言（P0-3 ②）。"""

    @classmethod
    def setUpClass(cls):
        with open(GUARD_SRC, encoding="utf-8") as f:
            cls.src = f.read()
        cls.tree = ast.parse(cls.src)
        cls.handle = _func(cls.tree, "handle")

    def test_every_return_in_handle_is_gate_or_servfail_or_none(self):
        allowed, offenders = _gate_only_returns(self.handle)
        self.assertGreater(len(allowed) + len(offenders), 40,
                           "handle() 的 return 数量异常 ⇒ AST 走查可能不完整")
        if offenders:
            self.fail("handle() 存在 %d 条**未经统一出口闸门**的 return（旁路 ✗）：\n%s"
                      % (len(offenders),
                         "\n".join("  L%d  %s" % (l, d) for l, d in offenders)))
        # 记账：至少要有闸门出口（防止"把 return 全删了"式的假通过 ✗）
        self.assertGreaterEqual(len([1 for _l, d in allowed if d.startswith("_finalize_return")]), 25)

    def test_legacy_label_fold_is_gone(self):
        self.assertNotIn('("local-a" if src == "A" else "local-b")', self.src,
                         "P1-1 的旧折叠表达式必须彻底消失")
        self.assertGreaterEqual(self.src.count("_src_kind(src)"), 10,
                                "Existing and new generic-failure exits use centralized labels")
        self.assertNotIn("if ttl <= 0:\n        ttl = 60.0", self.src,
                         "P1-2：零 TTL 补 60s 的旧代码必须删除")

    def test_policy_cn_answer_has_no_raw_byte_exit(self):
        """P0-2：`_policy_cn_answer()` 只返回 `Answer` / None ✓。"""
        fn = _func(self.tree, "_policy_cn_answer")
        for r in ast.walk(fn):
            if not isinstance(r, ast.Return):
                continue
            v = r.value
            self.assertTrue(_is_none_literal(v) or isinstance(v, ast.Name),
                            "L%d：_policy_cn_answer 出现了非 Answer 出口 %s ✗"
                            % (r.lineno, ast.dump(v)[:80]))
        self.assertNotIn("rewrite_id", ast.dump(fn),
                         "_policy_cn_answer 不得直接产出返回给客户端的字节 ✗")

    def test_old_release_had_bypasses_this_one_does_not(self):
        """新旧对照：旧样本有裸出口，本发布为 0 ✓（只读解析，不导入 ✓）。"""
        if not os.path.exists(OLD_SAMPLE):
            self.skipTest("只读旧样本不存在：%s" % OLD_SAMPLE)
        with open(OLD_SAMPLE, encoding="utf-8") as f:
            old_tree = ast.parse(f.read())
        _a, old_off = _gate_only_returns(_func(old_tree, "handle"))
        _b, new_off = _gate_only_returns(self.handle)
        self.assertGreaterEqual(len(old_off), 3,
                                "旧样本应当存在裸出口，否则新旧对照无意义：%r" % (old_off,))
        self.assertEqual(new_off, [])


class SourceLabelMapping(unittest.TestCase):
    """④ P1-1：`domestic()` 的 src 标签 → 出口类别的显式映射 ✓（§6 起含动态标签 `CNB` ✓）。"""

    def test_explicit_map(self):
        self.assertEqual(guard._LABEL_MAP,
                         {"A": "local-a", "B": "local-b", "POL": "local-alt",
                          "CNV": None, "POL-SF": None, "CNB": "local-cn"})
        self.assertEqual(guard._src_kind("A"), "local-a")
        self.assertEqual(guard._src_kind("B"), "local-b")
        self.assertEqual(guard._src_kind("POL"), "local-alt")
        self.assertEqual(guard._src_kind("CNB"), "local-cn",
                         "§6：国内认证加密源的诚实标签 ✓")
        self.assertIsNone(guard._src_kind("CNV"), "CNV 是终局结论 ⇒ 不过闸 ✓")
        self.assertIsNone(guard._src_kind("POL-SF"), "POL-SF 是终局结论 ⇒ 不过闸 ✓")
        self.assertEqual(guard._src_kind("未登记"), "local-a", "未登记标签走默认 ✓")

    def test_map_covers_every_domestic_src(self):
        """`_LABEL_MAP` 的键必须**恰好等于** `domestic()` 实际可达的 src 常量集 ✓。

        §6 起 `domestic()` 的 CN 采纳出口改用 `_pol_label()` **动态**折算 ✓（国内 vs 海外）⇒
        可达集 = `domestic()` 内的字面量 ∪ `_pol_label()` 的返回值常量 ✓（后者本身也被静态钉住 ✓）。
        **不放宽**"无孤儿标签 / 无未登记标签"这条规则 ✓。
        """
        with open(GUARD_SRC, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        srcs = set()
        for n in ast.walk(_func(tree, "domestic")):
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple) and len(n.value.elts) == 3:
                s = _str_const(n.value.elts[1])
                if s is not None:
                    srcs.add(s)
        # §6：`_pol_label()` 的返回常量（动态折算，AST 看不到在 `domestic()` 里 ✓）
        pol = set()
        for n in ast.walk(_func(tree, "_pol_label")):
            if isinstance(n, ast.Return):
                s = _str_const(n.value)
                if s is not None:
                    pol.add(s)
        self.assertEqual(pol, {"POL", "CNB"},
                         "§6 动态标签必须恰好是 {POL, CNB} ✓（不得偷偷扩大 ✓）")
        self.assertEqual(srcs | pol, set(guard._LABEL_MAP),
                         "domestic() 可达 src 集（字面量 + §6 动态）与 _LABEL_MAP 必须一一对应 ✓")

    def test_terminals_bypass_gate_but_still_rewrite_qid(self):
        """`kind=None`（终局结论）：不过闸、不吃缓存，但必须重写 qid ✓。"""
        guard._ADM_CACHE.clear()
        w = mk_wire(1, rcode=3, answers=0, qid=0x0001)
        out = guard._finalize_return(w, guard._LABEL_MAP["CNV"], NAME, 1, 0xBEEF, mk_query(1, 0xBEEF))
        self.assertEqual(out[:2], struct.pack("!H", 0xBEEF))
        self.assertEqual(out[2:], w[2:])
        self.assertIsNone(guard._ADM_CACHE.get(guard._adm_key(NAME, 1)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
