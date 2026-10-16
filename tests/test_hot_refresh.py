# -*- coding: utf-8 -*-
"""test_hot_refresh.py —— 方案 §5「热命中与有界刷新」的离线用例。

现场要钉住的病（逐条对方案第 92–104 行）：
  A. **"刷新器在跑、指标在动、体验没变"** ✗ —— 最坏的失效形态。三个成因各钉一条：
     a1 判据与记账写在两处 ⇒ 漂移 ⇒ 指标不再描述真实行为（本用例靠**纯函数** `_hot_decide()` 消除）
     a2 被 `_adm_same_answer` 闸门拦住 ⇒ 刷新命中的正是"答案没变、寿命快到" ⇒ 永远不生效 ✗
     a3 窗口判据写成"严格 10%–20% 带内" ⇒ tick 抖一下就整段跳过 ⇒ 短寿命热门**永远刷不到** ✗
  B. **失败却续期** ✗ —— 必须结构上不可能：失败路径**什么都不写**。
  C. **刷新把较新的答案覆盖成较旧的** ✗（"永不降低新鲜度"）。
  D. **后台任务抢业务容量** ✗ —— 必须结构上不碰 `_upstream_executor`/`_inflight_sem`/`_cold_sem`。
  E. **16 MiB 字节预算账漂移** ✗ —— `_ADM_CACHE` 有 6 处 pop，漏一处扣减会让
     `_ADM_BYTES` 单调虚高 ⇒ 预算闸门被永久触发 ⇒ 缓存再也写不进（症状是命中率无声下降 ✗）。
  F. **默认开启** ✗ —— 不设环境变量必须等于**零行为变化**。
  G. **热门榜被自家探针占满** ✗ —— 只算 `src_cls == "client"` 的流量。

全部离线、不触网 ✓、不写生产目录 ✓。
运行：PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_hot_refresh.py
"""
from __future__ import print_function

import ast
import atexit
import os
import shutil
import struct
import sys
import tempfile
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_SRC = os.path.join(RELEASE_DIR, "guard.py")
sys.path.insert(0, RELEASE_DIR)

_TMP = tempfile.mkdtemp(prefix="hot-refresh-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)

import guard                                              # noqa: E402

NOW = 10 ** 9
QNAME = "hot.example.com"
QID = 0x1234


# ------------------------------------------------------------------ 报文构造
def _name_wire(name):
    return b"".join(bytes([len(p)]) + p.encode("ascii")
                    for p in name.split(".") if p) + b"\x00"


def mk_a(ttl=300, rcode=0, ad=False, qname=QNAME, addr="203.0.113.9"):
    """构造一条 A 应答 ✓（文档段地址 ⇒ 永不是私网，不会被任何消毒器丢掉 ✓）。"""
    flags = 0x8180 | (0x20 if ad else 0) | (rcode & 0xF)
    body = _name_wire(qname) + struct.pack("!HH", 1, 1)
    if rcode == 2 or rcode == 3:
        return struct.pack("!HHHHHH", QID, flags, 1, 0, 0, 0) + body
    rd = bytes(bytearray(int(x) for x in addr.split(".")))
    rr = (_name_wire(qname) + struct.pack("!HHIH", 1, 1, ttl, len(rd)) + rd)
    return struct.pack("!HHHHHH", QID, flags, 1, 1, 0, 0) + body + rr


def _parse(path):
    with open(path, encoding="utf-8") as f:
        return ast.parse(f.read())


def _fn(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _names(node):
    """函数体里出现的所有裸名字 / 属性名（用于"有没有碰某个对象"的静态判据）。"""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _calls(node):
    """函数体里出现的调用名集合（裸名或属性名）。"""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _str_lits(node):
    """收集子树里的字符串字面量 ✓（py3.6 的 `ast.Str` 与 py3.8+ 的 `ast.Constant` 都认 ✓）。"""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
        elif type(n).__name__ == "Str":
            v = getattr(n, "s", None)
            if isinstance(v, str):
                out.append(v)
    return out


def _cache_bytes():
    return sum(int(r.get("_sz") or 0) for r in guard._ADM_CACHE.values())


class Base(unittest.TestCase):
    def setUp(self):
        guard._ADM_CACHE.clear()
        guard._ADM_BYTES[0] = 0
        guard._HOT.clear()
        guard._HOT_BYTES[0] = 0
        guard._HOT_BUCKET[0] = 0.0
        # ★ `guard._stats` 是**进程级**的 ✓ —— 用例之间会互相污染 ✗（本用例首轮就踩了：
        #   `test_race_*` 先把 `hot_skip_raced` 抬到 1，随后 `test_success_*` 断言
        #   "raced 必须为 0" 就假失败 ✗）。这里把 §5 相关计数归零，让每条用例**自证** ✓。
        for k in getattr(guard, "_step5_keys", ()):
            guard._stats[k] = 0
        for k in list(guard._stats.keys()):
            if k.startswith("hot_") or k.startswith("adm_"):
                guard._stats[k] = 0

    def _bump(self, key):
        return int(guard._stats.get(key, 0) or 0)

    def _until(self, name=None, qtype=1):
        """★ 必须**每次重新取**记录 ✓ —— `_adm_cache_put()` 是 `_ADM_CACHE[key] = {...}`
        整体替换 ✗（不是原地改字段）⇒ 测试若抱着旧 dict 引用断言，会永远看到旧值 ✗
        （本用例首轮就是这么假失败的 ✓ —— 夹具自己的 bug 会伪装成"产品没生效" ✗）。"""
        return float(guard._ADM_CACHE[guard._adm_key(name or QNAME, qtype)]["until"])


# ============================================================ ① 判据纯函数
class TestHotDecide(Base):
    """`_hot_decide()` 逐条断言 —— a1/a3 的落点 ✓（判据必须可离线验证 ✓）。"""

    def _rec(self, ttl=300.0, remain=45.0, source="local-a"):
        return {"ttl": float(ttl), "until": NOW + float(remain), "source": source}

    def test_no_record_is_skip_stale(self):
        self.assertEqual(guard._hot_decide(None, NOW, False), ("skip", "stale"))

    def test_short_ttl_never_prewarmed(self):
        """§5 第 3 项：寿命 <60s ⇒ 不全量预热 ✓（哪怕已经在窗口内 ✓）。"""
        self.assertEqual(guard._hot_decide(self._rec(ttl=59.0, remain=5.0), NOW, False),
                         ("skip", "ttl"))
        self.assertEqual(guard._hot_decide(self._rec(ttl=30.0, remain=1.0), NOW, False),
                         ("skip", "ttl"))

    def test_ttl_exactly_60_is_allowed(self):
        """边界：60s 是"寿命 ≥60s"的下沿 ⇒ 不算短 TTL ✓（`_HOT_MIN_TTL` 用 `<` 不用 `<=` ✓）。"""
        self.assertEqual(guard._hot_decide(self._rec(ttl=60.0, remain=9.0), NOW, False),
                         ("refresh", "in_window"))

    def test_expired_record_is_skip_stale(self):
        self.assertEqual(guard._hot_decide(self._rec(remain=0.0), NOW, False),
                         ("skip", "stale"))
        self.assertEqual(guard._hot_decide(self._rec(remain=-5.0), NOW, False),
                         ("skip", "stale"))

    def test_non_local_a_source_is_refused(self):
        """只能用 **A 认证源**重取 ✓：别的来源各带自己的采纳条件，A-only 重取等于绕过它们 ✗。"""
        for src in ("local-alt", "local-b", "clean-channel", "", "POL"):
            self.assertEqual(guard._hot_decide(self._rec(source=src), NOW, False),
                             ("skip", "source"), "来源 %r 必须拒绝 ✓" % src)

    def test_cn_domain_is_refused(self):
        """CN 名的采纳含 **B 国内存在性/就近性否决** ✗ ⇒ A-only 重取会绕过它 ⇒ 一律不刷 ✓。"""
        self.assertEqual(guard._hot_decide(self._rec(), NOW, True), ("skip", "cn"))

    def test_out_of_window_not_refreshed(self):
        """剩余寿命还早 ⇒ 这一轮不刷 ✓（否则等于"提前消耗上游请求"✗）。"""
        # 剩余 100s / 300s = 33% > 20%
        self.assertEqual(guard._hot_decide(self._rec(remain=100.0), NOW, False),
                         ("skip", "out_window"))

    def test_window_upper_edge_is_inclusive(self):
        """边界：剩余恰为 20% ⇒ **刷** ✓（判据是 `frac > _HOT_HI` ✗，不是 `>=` ✓）。"""
        self.assertEqual(guard._hot_decide(self._rec(remain=60.0), NOW, False),
                         ("refresh", "in_window"))

    def test_below_lower_edge_still_refreshes(self):
        """★ a3 的落点：低于 10% 下沿仍必须刷 ✓ —— 否则"tick 恰好跨过整个窗口"的
        短寿命热门**永远不被刷新** ✗（最坏形态：刷新器在跑、指标在动、体验没变 ✗）。"""
        self.assertEqual(guard._hot_decide(self._rec(remain=15.0), NOW, False),
                         ("refresh", "in_window"))          # 5%
        self.assertEqual(guard._hot_decide(self._rec(remain=1.0), NOW, False),
                         ("refresh", "in_window"))          # 0.3%，仍有效 ⇒ 仍刷 ✓

    def test_check_order_is_stable(self):
        """顺序本身是判据的一部分 ✓ —— 全部条件同时踩中时必须报**最便宜的那条** ✓。

        为什么在意：顺序若变，"为什么没刷"的归因就变了 ✗ ⇒ 现场拿到的
        `hot_skip_*` 分布会指向错误的根因 ✗（本项目已因"指标指向错误根因"踩过坑 ✓）。
        """
        # ttl 短 + 已过期 + 来源不对 + CN ⇒ 必须报 ttl（第一个判据 ✓）
        r = {"ttl": 10.0, "until": NOW - 1.0, "source": "local-alt"}
        self.assertEqual(guard._hot_decide(r, NOW, True), ("skip", "ttl"))
        # 来源不对 + CN + 在窗口内 ⇒ 报 source（②在 ③之前 ✓）
        r = {"ttl": 300.0, "until": NOW + 15.0, "source": "local-alt"}
        self.assertEqual(guard._hot_decide(r, NOW, True), ("skip", "source"))
        # 来源对 + CN + 在窗口内 ⇒ 报 cn（③在 ④之前 ✓）
        r = {"ttl": 300.0, "until": NOW + 15.0, "source": "local-a"}
        self.assertEqual(guard._hot_decide(r, NOW, True), ("skip", "cn"))
        # 全对 ⇒ refresh ✓
        self.assertEqual(guard._hot_decide(r, NOW, False), ("refresh", "in_window"))

    def test_is_pure(self):
        """纯函数：同样输入 ⇒ 同样输出，且**不碰**任何缓存/计数 ✓。"""
        r = self._rec()
        before = (len(guard._ADM_CACHE), _cache_bytes(), dict(guard._stats))
        for _ in range(5):
            self.assertEqual(guard._hot_decide(r, NOW, False), ("refresh", "in_window"))
        self.assertEqual((len(guard._ADM_CACHE), _cache_bytes()), before[:2])
        self.assertEqual(dict(guard._stats), before[2], "纯函数不得改任何计数 ✓")


# ============================================================ ② 失败零副作用
class TestRefreshNeverRenewsOnFailure(Base):
    """B 的落点：**失败什么都不写** ✓ —— 必须是结构性的，而不是"分支写得对" ✓。"""

    def _put(self, ttl=300.0):
        w = mk_a(ttl=int(ttl))
        guard._adm_cache_put(QNAME, 1, w, "secure", "local-a", ttl)
        r = guard._ADM_CACHE.get(guard._adm_key(QNAME, 1))
        self.assertIsNotNone(r, "前置条件：必须先有一条可刷新的记录 ✓")
        return r, float(r["until"])

    def test_timeout_does_not_renew(self):
        _r, until = self._put()
        guard.udp_query = lambda server, msg, timeout=0: None       # 上游无应答 ✓
        guard._hot_refresh_one(QNAME, 1, until)
        self.assertEqual(self._until(), until, "失败绝不可续期 ✓")
        self.assertGreater(self._bump("hot_failed"), 0, "必须可见计数 ✓（否则又是静默行为 ✗）")
        self.assertEqual(self._bump("hot_refreshed"), 0)

    def test_bogus_upstream_does_not_renew(self):
        """上游回 rc=2（安全结论明确）⇒ 刷新路径必须**拒绝写入** ✓（不得借刷新"修好"bogus ✗）。"""
        _r, until = self._put()
        guard.udp_query = lambda server, msg, timeout=0: mk_a(ttl=300, rcode=2)
        guard._hot_refresh_one(QNAME, 1, until)
        self.assertEqual(self._until(), until, "bogus 绝不可被刷新采纳 ✓")
        self.assertEqual(self._bump("hot_refreshed"), 0)

    def test_zero_ttl_upstream_does_not_renew(self):
        """零 TTL ⇒ 拒绝 ✓（"绝不用固定值延长零 TTL"是与 §2 同一条铁律 ✓）。"""
        _r, until = self._put()
        guard.udp_query = lambda server, msg, timeout=0: mk_a(ttl=0)
        guard._hot_refresh_one(QNAME, 1, until)
        self.assertEqual(self._until(), until)
        self.assertEqual(self._bump("hot_refreshed"), 0)

    def test_exception_does_not_renew(self):
        """刷新路径自己抛异常也不能改缓存 ✓（异常绝不能变成"续期"✗）。"""
        _r, until = self._put()

        def _boom(*a, **k):
            raise RuntimeError("boom")
        guard.udp_query = _boom
        guard._hot_refresh_one(QNAME, 1, until)
        self.assertEqual(self._until(), until)
        self.assertGreater(self._bump("hot_failed"), 0)


# ============================================================ ③ 成功与竞态
class TestRefreshSuccessAndRace(Base):
    def test_success_pushes_until_back(self):
        """a2 的落点：**同一答案**也必须能重写 ✓ —— 否则刷新永远不生效 ✗。"""
        w = mk_a(ttl=300)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0, now=NOW)
        old_until = self._until()
        guard.udp_query = lambda server, msg, timeout=0: w
        guard._hot_refresh_one(QNAME, 1, old_until)
        self.assertEqual(self._bump("hot_refreshed"), 1, "同答案刷新必须生效 ✓")
        self.assertGreater(self._until(), old_until, "寿命必须被推回满 ✓")
        self.assertEqual(self._bump("hot_skip_raced"), 0)

    def test_refresh_true_bypasses_same_answer_gate(self):
        """直接对 `_adm_cache_put` 验证：`refresh=True` 是**唯一**的合法例外 ✓。"""
        w = mk_a(ttl=300)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0, now=NOW)
        first = self._until()
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 120.0, now=NOW + 10)
        self.assertEqual(self._until(), first, "同答案未开 refresh ⇒ 不得重写 ✓")
        self.assertGreater(self._bump("adm_cache_reput_same"), 0)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0, now=NOW + 10,
                             refresh=True)
        self.assertGreater(self._until(), first, "开 refresh ⇒ 必须重写 ✓")
        self.assertEqual(self._bump("adm_cache_reput_same"), 1,
                         "只记一次 ⇒ 证明第二次确实走了 refresh 路径 ✓")

    def test_race_never_lowers_freshness(self):
        """C 的落点：记录已被别处换成**更新**的一条 ⇒ 刷新必须退让 ✓。"""
        w = mk_a(ttl=300)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0, now=NOW)
        fresh_until = self._until()
        guard.udp_query = lambda server, msg, timeout=0: w
        # 传一个**比现存更旧**的 expect ⇒ 说明"我看到的视图是旧的" ⇒ 必须退让 ✓
        guard._hot_refresh_one(QNAME, 1, fresh_until - 100.0)
        self.assertEqual(self._bump("hot_skip_raced"), 1, "必须被记为 raced ✓")
        self.assertEqual(self._until(), fresh_until, "绝不可降低新鲜度 ✓")
        self.assertEqual(self._bump("hot_refreshed"), 0)


# ============================================================ ④ 字节预算账
class TestAdmBytesAccounting(Base):
    """E 的落点：`_ADM_BYTES` 必须**始终**等于缓存内 `_sz` 之和 ✓。"""

    def test_put_then_drop_is_exact(self):
        w = mk_a(ttl=300)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0)
        self.assertEqual(guard._ADM_BYTES[0], _cache_bytes())
        self.assertGreater(guard._ADM_BYTES[0], 0)
        guard._adm_drop(guard._adm_key(QNAME, 1))
        self.assertEqual(guard._ADM_BYTES[0], 0, "弹出必须等量扣减 ✓")
        self.assertEqual(_cache_bytes(), 0)

    def test_drop_missing_key_is_harmless(self):
        guard._adm_drop(("nope.example.com", 1))
        self.assertEqual(guard._ADM_BYTES[0], 0)
        self.assertFalse(guard._ADM_BYTES[0] < 0, "绝不可为负 ✓")

    def test_all_pop_sites_go_through_drop(self):
        """静态：`_ADM_CACHE` 的 pop **只允许**出现在 `_adm_drop()` 内 ✓ ——
        这是"账不漂移"的**结构性**保证（新增一处裸 pop 会让本用例失败 ✓）。"""
        tree = _parse(GUARD_SRC)
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for c in ast.walk(node):
                if not isinstance(c, ast.Call):
                    continue
                f = c.func
                if isinstance(f, ast.Attribute) and f.attr == "pop" \
                        and isinstance(f.value, ast.Name) and f.value.id == "_ADM_CACHE":
                    if node.name != "_adm_drop":
                        offenders.append((node.name, c.lineno))
        self.assertEqual(offenders, [],
                         "这些位置绕过了 `_adm_drop()` ⇒ `_ADM_BYTES` 会漂移 ✗：%r" % offenders)

    def test_expiry_path_also_credits(self):
        """过期弹出（`_adm_cache_get` 的第一条分支）也必须扣账 ✓。"""
        w = mk_a(ttl=300)
        guard._adm_cache_put(QNAME, 1, w, "accepted", "local-a", 300.0, now=NOW)
        self.assertEqual(guard._adm_cache_get(QNAME, 1, now=NOW + 1.0) is not None, True)
        self.assertIsNone(guard._adm_cache_get(QNAME, 1, now=NOW + 400.0), "过期必须未命中 ✓")
        self.assertEqual(guard._ADM_BYTES[0], 0, "过期弹出后账必须归零 ✓")

    def test_byte_budget_is_enforced(self):
        """§5 第 4 项：**条数**与**字节**两个限额任一先到即淘汰 ✓。"""
        old_max = guard._ADM_BYTES_MAX
        guard._ADM_BYTES_MAX = 6000
        try:
            for i in range(60):
                w = mk_a(ttl=300, qname="h%d.example.com" % i)
                guard._adm_cache_put("h%d.example.com" % i, 1, w, "accepted", "local-a",
                                     300.0, now=NOW + i)
            self.assertLessEqual(guard._ADM_BYTES[0], guard._ADM_BYTES_MAX,
                                 "字节预算必须被强制 ✓（实际 %d）" % guard._ADM_BYTES[0])
            self.assertEqual(guard._ADM_BYTES[0], _cache_bytes(), "账必须与缓存一致 ✓")
            self.assertGreater(self._bump("adm_bytes_high"), 0, "必须可见计数 ✓")
        finally:
            guard._ADM_BYTES_MAX = old_max

    def test_hot_ledger_is_bounded(self):
        """频次账本有界 ✓（条数或字节任一超限即淘汰 ✓）。"""
        old_max, old_on = guard._HOT_MAX, guard._HOT_ON
        guard._HOT_MAX = 50
        guard._HOT_ON = True            # ★ 账本写入受开关门控 ⇒ 测试必须显式打开 ✓
        try:
            for i in range(300):
                guard._hot_note("n%d.example.com" % i, 1)
            self.assertLessEqual(len(guard._HOT), guard._HOT_MAX + 1,
                                 "频次账本必须有界 ✓（实际 %d）" % len(guard._HOT))
            self.assertGreater(self._bump("hot_evict"), 0)
        finally:
            guard._HOT_MAX = old_max
            guard._HOT_ON = old_on


# ============================================================ ⑤ 结构性约束
class TestStructural(Base):
    """D / F / G 的落点：靠**静态检查**钉住"结构上做不到"，而不是靠运行时观察 ✓。"""

    def test_default_off(self):
        """F：不设环境变量 ⇒ 零行为变化 ✓。"""
        self.assertIn('_flag("GUARD_HOT_REFRESH", False)', open(GUARD_SRC, encoding="utf-8").read(),
                      "默认必须是关 ✓（否则升级即改行为 ✗）")
        self.assertFalse(getattr(guard, "_HOT_ON"), "默认 _HOT_ON 必须为假 ✓")

    def test_off_means_no_ledger(self):
        """关掉时**连频次账本都不写** ✓ ⇒ 关闭态的额外开销是零（不是"记了不刷"✓）。"""
        if guard._HOT_ON:
            self.skipTest("本机环境显式开启了 §5 ✓")
        guard._hot_note("x.example.com", 1)
        self.assertEqual(len(guard._HOT), 0, "关闭态不得产生任何账本条目 ✓")
        guard._hot_note("x.example.com", 1)
        self.assertEqual(guard._HOT_BYTES[0], 0, "关闭态字节账也必须为 0 ✓")

    def test_never_touches_business_capacity(self):
        """D：刷新的**任何一个**函数都不得碰业务容量对象 ✓。"""
        tree = _parse(GUARD_SRC)
        forbidden = {"_upstream_executor", "_inflight_sem", "_dispatch_sem", "_cold_sem",
                     "_r8_executor", "_shadow_sem"}
        for fn in ("hot_refresh", "_hot_refresh_one", "_hot_get_exec", "_hot_note",
                   "_hot_decide"):
            node = _fn(tree, fn)
            self.assertIsNotNone(node, "找不到 %s ✓" % fn)
            hit = _names(node) & forbidden
            self.assertEqual(hit, set(),
                             "%s() 碰了业务容量对象 %r ⇒ 后台任务会加剧业务排队 ✗" % (fn, hit))

    def test_uses_its_own_executor(self):
        """D：必须用自己的小执行器 ✓（而不是提交到业务执行器 ✗）。"""
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "_hot_get_exec")
        self.assertIn("_HOT_EXEC", _names(node))
        self.assertIn("ThreadPoolExecutor", _names(node))
        # 提交点必须是 `_hot_get_exec()`
        self.assertIn("_hot_get_exec", _calls(_fn(tree, "hot_refresh")))

    def test_thread_is_started(self):
        """必须真的被启动 ✓（否则"实现了但没接线"✗ —— 本项目已踩过同类坑 ✓）。"""
        tree = _parse(GUARD_SRC)
        started = False
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "start"):
                continue
            if any(isinstance(a, ast.Name) and a.id == "hot_refresh" for a in ast.walk(n)):
                started = True
        self.assertTrue(started, "必须有一处 `threading.Thread(target=hot_refresh).start()` ✓")

    def test_only_client_traffic_feeds_the_ledger(self):
        """G：热门榜只由 **client** 类流量喂 ✓（否则会被自家探针占满 ✗）。

        ★ 判据必须直接读 AST 的**字符串字面量**，不能用 `ast.dump()` 里的 `'"client"'` ✗ ——
        `ast.dump()` 对 str 常量输出**单引号**（`Constant(value='client')`）✗
        ⇒ 那个写法在本机（py3.14）恒不匹配、在 py3.6 上碰巧匹配 ⇒ 用例不可移植 ✗。
        ★ 也不能找 `ast.Attribute(attr="src_cls")` ✗ —— 现场写法是 `t.get("src_cls")` ✓
        ⇒ 键名是**字面量实参**、不是属性访问 ✗（本用例首轮就错在这里 ✓）。
        """
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "_tr_finish")
        self.assertIsNotNone(node)
        ok = False
        for n in ast.walk(node):
            if not isinstance(n, ast.If):
                continue
            lits = _str_lits(n.test)
            if "src_cls" not in lits or "client" not in lits:
                continue
            if "_hot_note" in _calls(n):
                ok = True
        self.assertTrue(ok, "`_tr_finish()` 必须在 `src_cls == 'client'` 的**保护下**"
                            "调 `_hot_note()` ✓")
        total = sum(1 for n in ast.walk(node)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "_hot_note")
        self.assertEqual(total, 1,
                         "`_hot_note()` 只允许出现 1 次 ✓（多出来的必然未受保护 ✗，实际 %d）" % total)

    def test_refresh_write_is_guarded_by_try(self):
        """B：`_adm_cache_put` 的**唯一**调用必须包在 `try` 里，且 **绝不**出现在 `except` 分支 ✓
        —— 否则"上游炸了反而续期"就成立了 ✗。"""
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "_hot_refresh_one")
        self.assertIsNotNone(node)
        in_except = []
        inside_try = 0
        for h in ast.walk(node):
            if not isinstance(h, ast.Try):
                continue
            exc = set()
            for e in h.handlers:
                for x in ast.walk(e):
                    exc.add(id(x))
            tg = set()
            for x in ast.walk(h):
                tg.add(id(x))
            for c in ast.walk(h):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) \
                        and c.func.id == "_adm_cache_put":
                    if id(c) in exc:
                        in_except.append(c.lineno)
                    else:
                        inside_try += 1
        self.assertEqual(in_except, [],
                         "`_adm_cache_put` 出现在 except 分支 ⇒ 失败会续期 ✗：行 %r" % in_except)
        self.assertEqual(inside_try, 1, "恰有 1 处写入点、且在 try 内 ✓")

    def test_all_counters_are_registered(self):
        """新增计数必须进 `_stats` 与 `PERSIST_SKIP` ✓
        （否则重启后恢复不了、或跨重启累积 ⇒ 比率算错 ✗）。"""
        missing = []
        for k in guard._step5_keys:
            if k not in guard._stats:
                missing.append(k)
            if k not in guard.PERSIST_SKIP:
                missing.append(k + "(PERSIST_SKIP)")
        self.assertEqual(missing, [], "§5 计数未登记：%r" % missing)

    def test_resource_gate_only_gates_refresh(self):
        """§5 第 6 项：资源闸门**只**决定"是否刷新" ✗，绝不影响安全准入 ✓。"""
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "_res_gate")
        self.assertIsNotNone(node)
        hit = _names(node) & {"_adm_cache_put", "fail_closed", "mk_servfail", "classify_response"}
        self.assertEqual(hit, set(), "资源闸门碰了安全路径 %r ✗（方案明令禁止）" % hit)
        # 调用侧：只有 hot_refresh 用它的返回值决定 continue ✓
        callers = []
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and "_res_gate" in _calls(fn):
                callers.append(fn.name)
        self.assertEqual(sorted(callers), ["hot_refresh"],
                         "`_res_gate()` 的调用点应只有 hot_refresh ✓（实际 %r）" % callers)

    def test_rate_is_capped_by_business_share(self):
        """§5 第 2 项：速率上限必须**同时**受 `<1 QPS` 与 `<业务 10%` 约束 ✓。"""
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "hot_refresh")
        src = ast.dump(node)
        self.assertIn("_HOT_QPS", src, "必须受固定 1 QPS 约束 ✓")
        self.assertIn("_HOT_SHARE", src, "必须受业务比例约束 ✓")
        self.assertIn("min", _calls(node), "两者必须取 min ✓（低流量时更严 ✓）")

    def test_pss_uses_smaps_rollup(self):
        """完成门"PSS ≤32MiB"的取数方式必须是 PSS ✓（RSS 会把共享页重复计算 ⇒ 高估 ✗）。"""
        tree = _parse(GUARD_SRC)
        node = _fn(tree, "_pss_kb")
        src = ast.dump(node)
        self.assertIn("smaps_rollup", src, "必须读 smaps_rollup ✓")
        self.assertIn("Pss:", src)
        for bad in ("statm", "status"):
            self.assertNotIn(bad, src, "不得退回 %s（那是 RSS/VmRSS ⇒ 高估 ✗）" % bad)

    def test_no_forbidden_system_actions(self):
        """§5 第 7 项：不执行 `swapoff` / `drop_caches` ✓。

        ★ 判据必须只看**字符串字面量** ✗，不能对源码全文 `assertNotIn("drop_caches")` ✗ ——
        本文件里既有同名的自有函数 `_drop_caches_for()`（**准入缓存三清**，与内核的
        `drop_caches` 毫无关系 ✓），也有"明令不执行"的注释 ✓ ⇒ 全文匹配会假失败 ✗
        （本用例首轮就踩了这个 ✓：夹具自己的判据错会伪装成"产品违规" ✗）。
        """
        tree = _parse(GUARD_SRC)
        lits = []
        for n in ast.walk(tree):
            v = None
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                v = n.value
            elif type(n).__name__ == "Str":          # py3.6 兼容 ✓
                v = getattr(n, "s", None)
            if v:
                lits.append(v)
        bad = [s for s in lits if "swapoff" in s or "drop_caches" in s]
        self.assertEqual(bad, [],
                         "出现了会被系统执行的禁用动作字符串 %r ✗（方案第 102 行明令）" % bad)
        # 反面证据：确实**没有**任何 shell/子进程出口指向它们 ✓
        for fn in ("hot_refresh", "_hot_refresh_one", "_res_gate", "_pss_sample"):
            node = _fn(tree, fn)
            if node is None:
                continue
            calls = _calls(node)
            self.assertEqual(calls & {"system", "popen", "run", "check_output", "call"},
                             set(), "%s() 不得起子进程 ✓" % fn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
