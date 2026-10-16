# -*- coding: utf-8 -*-
"""test_alt_readiness.py —— 方案 §4「补齐 alt readiness 和连接保持」的离线用例。

现场问题（本用例逐条钉住）：
  A. **guard 从不看 readiness** ✗ —— 全仓只有 `_tag_bucket()` 的字符串白名单里预留了
     `alt_ready` / `alt_not_ready` 两个名字，**没有任何函数驱动它们** ⇒ 备用永远可查 ✗
     （bundle/release-7 里做过，但从未进入 release-8/9/10/11 ✗）。
  B. **ready 记录不绑定配置** ✗ —— 原 `write_state()` 只有 boot_id / container_id /
     started_at；改配置（换上游、改 DNSSEC 策略）后旧 ready 照旧生效 ✗。
  C. **有效期初值 30s 而非方案要求的 90s** ✗（bundle 版 `ALT_READY_MAX_AGE` 默认 30 ✗）。
  D. **无运输断路器** ✗ —— alt 连续运输失败时会不断重复付超时 ✗。
  E. **"未就绪" 与 "每请求只启动一次" 是两回事** ✗ —— 若未就绪也去消耗
     `_src_once("alt")` 名额，readiness 恢复后同一请求反而用不上 ✓。

全部离线、不触网 ✓、不写生产目录 ✓。
运行：PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
"""
import atexit
import ast
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_SRC = os.path.join(RELEASE_DIR, "guard.py")
READY_SRC = os.path.join(RELEASE_DIR, "unbound-alt-readiness.py")
sys.path.insert(0, RELEASE_DIR)

_TMP = tempfile.mkdtemp(prefix="alt-ready-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
# ★ 每个用例都从"未就绪"起步 ⇒ 断言才有意义 ✓
os.environ["GUARD_ALT_READY_STATE"] = os.path.join(_TMP, "ready-missing.json")
atexit.register(shutil.rmtree, _TMP, True)

import alt_adapter                                        # noqa: E402
import guard                                              # noqa: E402

BOOT = alt_adapter._boot_id()


def write_ready(path, **over):
    """写一份"本应 ready"的状态文件，再用 `over` 覆盖个别字段 ✓。"""
    st = {
        "ready": True,
        "boot_id": BOOT,
        "container_id": "cid-abc",
        "started_at": "2026-10-10T00:00:00Z",
        "config_hash": "hashA",
        "checked_monotonic": time.monotonic(),
        "checked_wall": time.time(),
        "consecutive_ok": 2,
        "reason": "ready",
        "checks": [],
    }
    st.update(over)
    with open(path, "w") as fh:
        json.dump(st, fh)
    return path


def expect_ready(path):
    """用**干净的缓存**读一次（绕开 1 秒节流 ✓）。"""
    alt_adapter._READY_CACHE["t"] = 0.0
    return alt_adapter.read_ready_state(path)


# ---------------------------------------------------------------- A：readiness 读侧
class ReadReadyState(unittest.TestCase):
    def setUp(self):
        self.p = os.path.join(_TMP, "ready-%s.json" % self._testMethodName)

    def test_healthy_record_is_ready(self):
        write_ready(self.p)
        ok, why = expect_ready(self.p)
        self.assertTrue(ok, why)
        self.assertEqual(why, "ready")

    def test_missing_file_is_not_ready(self):
        ok, why = expect_ready(os.path.join(_TMP, "definitely-missing.json"))
        self.assertFalse(ok)
        self.assertTrue(why.startswith("state_unreadable"), why)

    def test_broken_json_is_not_ready(self):
        with open(self.p, "w") as fh:
            fh.write("{not json")
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertTrue(why.startswith("state_unreadable"), why)

    def test_json_non_object_is_not_ready(self):
        with open(self.p, "w") as fh:
            json.dump([1, 2, 3], fh)
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertEqual(why, "state_not_object")

    def test_ready_false_is_not_ready(self):
        write_ready(self.p, ready=False, reason="warming")
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertTrue(why.startswith("not_ready"), why)

    def test_single_round_is_not_ready(self):
        # 方案第 2 项：连续**两轮**全部合格才算 ✓ —— 写侧 `ready = consecutive_ok >= 2` ✓，
        # 读侧再加一道 `consecutive_ok >= 2` 纵深防御 ✓（伪造/手写文件的场景 ✓）。
        write_ready(self.p, consecutive_ok=1, ready=True)
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertIn("consecutive_ok", why)

    def test_default_max_age_is_90_not_30(self):
        # 方案第 2 项：「有效期初值 90 秒」✓ —— bundle 版是 30 ✗
        self.assertAlmostEqual(float(alt_adapter.ALT_READY_MAX_AGE), 90.0, places=6)

    def test_just_inside_max_age_is_ready(self):
        write_ready(self.p, checked_monotonic=time.monotonic() - 80.0)
        ok, why = expect_ready(self.p)
        self.assertTrue(ok, why)

    def test_past_max_age_is_not_ready(self):
        write_ready(self.p, checked_monotonic=time.monotonic() - 91.0)
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertTrue(why.startswith("state_stale"), why)

    def test_future_timestamp_is_not_ready(self):
        write_ready(self.p, checked_monotonic=time.monotonic() + 30.0)
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertTrue(why.startswith("state_from_future"), why)

    def test_missing_checked_monotonic_is_not_ready(self):
        p = write_ready(self.p)
        st = json.load(open(p))
        del st["checked_monotonic"]
        json.dump(st, open(p, "w"))
        ok, why = expect_ready(p)
        self.assertFalse(ok)
        self.assertEqual(why, "checked_monotonic_missing")

    def test_boot_id_change_is_not_ready(self):
        # §4 第 1 项：宿主重启后旧 ready **立即失效** ✓
        write_ready(self.p, boot_id="00000000-0000-0000-0000-000000000000")
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertEqual(why, "boot_id_changed")

    def test_identity_missing_is_not_ready(self):
        # §4 第 1 项：container_id / started_at 是身份的**必需**部分 ✓
        write_ready(self.p, container_id="")
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertEqual(why, "identity_missing")
        write_ready(self.p, started_at="")
        ok, why = expect_ready(self.p)
        self.assertFalse(ok)
        self.assertEqual(why, "identity_missing")

    def test_config_hash_change_is_not_ready(self):
        # §4 第 1 项：**配置变化后旧 ready 立即失效** ✓
        write_ready(self.p, config_hash="hashA")
        old = alt_adapter.ALT_CONFIG_HASH
        try:
            alt_adapter.ALT_CONFIG_HASH = "hashA"
            ok, why = expect_ready(self.p)
            self.assertTrue(ok, why)
            alt_adapter.ALT_CONFIG_HASH = "hashB"
            ok, why = expect_ready(self.p)
            self.assertFalse(ok)
            self.assertEqual(why, "config_hash_changed")
        finally:
            alt_adapter.ALT_CONFIG_HASH = old

    def test_empty_config_hash_on_both_sides_skips_check(self):
        # 两侧都为空 ⇒ 不比（离线单测可用 ✓），**不是** fail-open ✗
        write_ready(self.p, config_hash="")
        old = alt_adapter.ALT_CONFIG_HASH
        try:
            alt_adapter.ALT_CONFIG_HASH = ""
            ok, why = expect_ready(self.p)
            self.assertTrue(ok, why)
        finally:
            alt_adapter.ALT_CONFIG_HASH = old

    # ── pid_fp：容器自身 pid 文件指纹（§4 第 1 项"重启后旧 ready 立即失效"的读侧兜底）──
    def test_pidfile_gone_is_not_ready(self):
        # ★ 现场依据（`probe_pidfile.py`）：`docker restart` 的瞬间 pid 文件**消失** ⇒
        #   即便 `container_id`/`started_at` 都还没刷新（原地重启、ID 不变 ✗），
        #   读侧也必须立刻判 not-ready ✓。这条正是 10/10 误报 ready 缺陷的回归哨兵 ✓。
        write_ready(self.p, pid_fp=[12345, 67890])
        old = alt_adapter.ALT_PIDFILE
        try:
            alt_adapter.ALT_PIDFILE = os.path.join(_TMP, "no-such-unbound.pid")
            ok, why = expect_ready(self.p)
            self.assertFalse(ok)
            self.assertEqual(why, "pidfile_gone")
        finally:
            alt_adapter.ALT_PIDFILE = old

    def test_pidfile_fingerprint_change_is_not_ready(self):
        # 文件还在但 (inode, mtime_ns) 变了 ⇒ 容器已重启 ✓
        pid = os.path.join(_TMP, "fake-unbound.pid")
        with open(pid, "w") as fh:
            fh.write("12\n")
        old = alt_adapter.ALT_PIDFILE
        try:
            alt_adapter.ALT_PIDFILE = pid
            cur = alt_adapter._pidfile_fp()
            self.assertIsNotNone(cur, "应能 stat 到刚写的 pid 文件")
            write_ready(self.p, pid_fp=[int(cur[0]), int(cur[1]) + 999999])
            ok, why = expect_ready(self.p)
            self.assertFalse(ok)
            self.assertEqual(why, "pidfile_changed")
            # 与磁盘一致 ⇒ 放行 ✓（证明不是"有 pid_fp 就永远不 ready" ✗）
            write_ready(self.p, pid_fp=[int(cur[0]), int(cur[1])])
            ok, why = expect_ready(self.p)
            self.assertTrue(ok, why)
        finally:
            alt_adapter.ALT_PIDFILE = old

    def test_pid_fp_absent_on_either_side_is_skipped(self):
        # 记录里没有 `pid_fp`（老状态文件）⇒ 跳过比对 ⇒ **不**变成"永远不 ready" ✗
        write_ready(self.p, pid_fp=None)
        old = alt_adapter.ALT_PIDFILE
        try:
            alt_adapter.ALT_PIDFILE = os.path.join(_TMP, "no-such-unbound.pid")
            ok, why = expect_ready(self.p)
            self.assertTrue(ok, why)
        finally:
            alt_adapter.ALT_PIDFILE = old


# ---------------------------------------------------------------- A2：节流
class ReadyThrottle(unittest.TestCase):
    def setUp(self):
        # ★ 每个用例都换**自己的**状态路径并复原 —— 否则别的用例写到共享默认路径后
        #   会污染这里（本轮实测踩到：`QueryAltNeverSends` 写的就是默认路径 ✗）。
        self._old_path = alt_adapter.ALT_READY_STATE
        alt_adapter.ALT_READY_STATE = os.path.join(_TMP, "throttle-missing.json")
        alt_adapter._READY_CACHE["t"] = 0.0
        alt_adapter._READY_CACHE["ready"] = False
        alt_adapter._READY_CACHE["reason"] = "uninit"

    def tearDown(self):
        alt_adapter.ALT_READY_STATE = self._old_path
        alt_adapter._READY_CACHE["t"] = 0.0

    def test_alt_ready_is_throttled(self):
        # 热路径不能每请求读盘 ✗ —— 1 秒内第二次必须直接吃缓存 ✓
        self.assertFalse(alt_adapter.alt_ready(now=1000.0))
        p = write_ready(os.path.join(_TMP, "throttle.json"))
        old = alt_adapter.ALT_READY_STATE
        try:
            alt_adapter.ALT_READY_STATE = p
            # 同一时刻（节流窗口内）⇒ 仍返回上一次的 False ✓
            self.assertFalse(alt_adapter.alt_ready(now=1000.5))
            # 越过节流窗口 ⇒ 读到新文件 ⇒ True ✓
            self.assertTrue(alt_adapter.alt_ready(now=1002.0))
        finally:
            alt_adapter.ALT_READY_STATE = old


# ---------------------------------------------------------------- B：运输断路器
class TransportBreaker(unittest.TestCase):
    def setUp(self):
        alt_adapter._BREAKER.update({"fails": 0, "open_until": 0.0, "half_open": False,
                                     "trips": 0, "half_ok": 0, "half_fail": 0,
                                     "transport_fail": 0, "transport_ok": 0})

    def test_closed_by_default(self):
        allowed, state = alt_adapter.breaker_state(now=100.0)
        self.assertTrue(allowed)
        self.assertEqual(state, "closed")

    def test_three_transport_failures_open_for_15s(self):
        # §4 第 3 项：连续运输失败 3 次 ⇒ 断路 15 秒 ✓
        for i in range(3):
            alt_adapter.breaker_note(False, now=100.0 + i)
        allowed, state = alt_adapter.breaker_state(now=100.0 + 3)
        self.assertFalse(allowed)
        self.assertEqual(state, "open")
        # 15 秒内一直挡 ✓
        self.assertFalse(alt_adapter.breaker_state(now=100.0 + 10)[0])
        # 越界后放行**一个**半开试探 ✓
        allowed, state = alt_adapter.breaker_state(now=100.0 + 30.0)
        self.assertTrue(allowed)
        self.assertEqual(state, "half_open")
        self.assertGreaterEqual(alt_adapter._BREAKER["trips"], 1)

    def test_half_open_lets_exactly_one_probe(self):
        for i in range(3):
            alt_adapter.breaker_note(False, now=100.0 + i)
        self.assertEqual(alt_adapter.breaker_state(now=200.0)[1], "half_open")
        allowed, state = alt_adapter.breaker_state(now=200.0)
        self.assertFalse(allowed)
        self.assertEqual(state, "half_open_busy")

    def test_success_closes_breaker_and_resets_fails(self):
        alt_adapter.breaker_note(False, now=100.0)
        alt_adapter.breaker_note(False, now=101.0)
        alt_adapter.breaker_note(True, now=102.0)
        self.assertEqual(alt_adapter._BREAKER["fails"], 0)
        allowed, state = alt_adapter.breaker_state(now=103.0)
        self.assertTrue(allowed)
        self.assertEqual(state, "closed")

    def test_half_open_failure_reopens_immediately(self):
        for i in range(3):
            alt_adapter.breaker_note(False, now=100.0 + i)
        self.assertEqual(alt_adapter.breaker_state(now=200.0)[1], "half_open")
        alt_adapter.breaker_note(False, now=200.0)     # 半开试探也失败
        self.assertEqual(alt_adapter._BREAKER["half_fail"], 1)
        allowed, state = alt_adapter.breaker_state(now=201.0)
        self.assertFalse(allowed)
        self.assertEqual(state, "open")

    def test_bogus_is_not_a_transport_failure(self):
        # ★ DNSSEC bogus = **运输成功 + 拿到安全结论** ⇒ 绝不计运输故障 ✗ ——
        #   否则攻击者可用一个 bogus 名把整条 alt 通道关掉 ✓。
        src = open(os.path.join(RELEASE_DIR, "alt_adapter.py"), encoding="utf-8").read()
        # `query_alt` 只在 except（发包/收包异常）里记失败 ✓
        seg = src[src.index("def query_alt("):]
        seg = seg[:seg.index("\n__all__")]
        self.assertIn("breaker_note(False)", seg)
        self.assertIn("breaker_note(True)", seg)
        # 收到报文后（含 rc=2）不许再记运输失败 ✗
        tail = seg[seg.index("breaker_note(True)"):]
        self.assertNotIn("breaker_note(False)", tail)

    def test_snapshot_is_read_only(self):
        before = dict(alt_adapter._BREAKER)
        alt_adapter.breaker_snapshot()
        self.assertEqual(before, alt_adapter._BREAKER)


# ---------------------------------------------------------------- C：不发包
class QueryAltNeverSendsWhenUnavailable(unittest.TestCase):
    """★ 判据是"**有没有真的发包**"，不是"有没有返回 None" ✗（空测比没测更坏 ✓）。"""

    def setUp(self):
        self.sent = []
        self._orig_socket = socket.socket
        self._orig_path = alt_adapter.ALT_READY_STATE
        # ★ 用**本类自己的**状态文件 ⇒ 绝不写共享默认路径 ✗（否则会污染其它用例 ✓）
        self.ready_path = os.path.join(_TMP, "queryalt-%s.json" % self._testMethodName)

        def _fake(*a, **kw):
            raise AssertionError("未就绪/断路时**不得创建 socket** ✗")

        socket.socket = _fake
        alt_adapter._BREAKER.update({"fails": 0, "open_until": 0.0, "half_open": False,
                                     "trips": 0, "half_ok": 0, "half_fail": 0,
                                     "transport_fail": 0, "transport_ok": 0})

    def tearDown(self):
        socket.socket = self._orig_socket
        alt_adapter.ALT_READY_STATE = self._orig_path
        alt_adapter._READY_CACHE["t"] = 0.0

    def _point_at_missing(self):
        alt_adapter._READY_CACHE["t"] = 0.0
        alt_adapter.ALT_READY_STATE = os.path.join(_TMP, "queryalt-missing-%d.json" % time.time())

    def test_not_ready_does_not_query(self):
        self._point_at_missing()
        self.assertIsNone(alt_adapter.query_alt("www.example.com", 1,
                                                deadline=time.monotonic() + 4.0))

    def test_exhausted_budget_does_not_query(self):
        # ★ 必须让 readiness **为真** ⇒ 这样"不发包"的唯一原因才真的是预算已尽 ✓
        #   （否则是空测 —— 两个闸门都能挡住它，测不出预算纪律 ✓）。
        write_ready(self.ready_path)
        alt_adapter.ALT_READY_STATE = self.ready_path
        alt_adapter._READY_CACHE["t"] = 0.0
        self.assertTrue(alt_adapter.alt_ready())
        # 剩余预算 <= 保留量 ⇒ 立刻结束、不发包 ✓（§3 第 67 行 left<=0 立即结束 ✓）
        self.assertIsNone(alt_adapter.query_alt("www.example.com", 1,
                                                deadline=time.monotonic() - 1.0))

    def test_open_breaker_does_not_query(self):
        write_ready(self.ready_path)
        alt_adapter.ALT_READY_STATE = self.ready_path
        alt_adapter._READY_CACHE["t"] = 0.0
        for i in range(3):
            alt_adapter.breaker_note(False, now=time.monotonic() + i)
        self.assertIsNone(alt_adapter.query_alt("www.example.com", 1,
                                                deadline=time.monotonic() + 4.0))


# ---------------------------------------------------------------- D：guard 侧接线
class GuardReadinessGate(unittest.TestCase):
    def setUp(self):
        alt_adapter._READY_CACHE["t"] = 0.0
        alt_adapter._READY_CACHE["ready"] = False
        self._old = alt_adapter.ALT_READY_STATE
        alt_adapter.ALT_READY_STATE = os.path.join(_TMP, "gate-missing.json")
        for k in ("alt_ready", "alt_not_ready", "alt_unavailable_skip",
                  "alt_ready_missing", "alt_ready_stale"):
            guard._stats[k] = 0

    def tearDown(self):
        alt_adapter.ALT_READY_STATE = self._old

    def test_gate_blocks_when_not_ready(self):
        self.assertFalse(guard._alt_gate())
        self.assertEqual(guard._stats["alt_not_ready"], 1)
        self.assertEqual(guard._stats["alt_ready"], 0)
        self.assertEqual(guard._stats["alt_unavailable_skip"], 1)
        self.assertEqual(guard._stats["alt_ready_missing"], 1)

    def test_gate_allows_when_ready(self):
        p = write_ready(os.path.join(_TMP, "gate-ok.json"))
        alt_adapter.ALT_READY_STATE = p
        alt_adapter._READY_CACHE["t"] = 0.0
        self.assertTrue(guard._alt_gate())
        self.assertEqual(guard._stats["alt_ready"], 1)
        self.assertEqual(guard._stats["alt_not_ready"], 0)

    def test_gate_reason_buckets_are_bounded(self):
        write_ready(alt_adapter.ALT_READY_STATE, checked_monotonic=time.monotonic() - 91.0)
        alt_adapter._READY_CACHE["t"] = 0.0
        self.assertFalse(guard._alt_gate())
        self.assertEqual(guard._stats["alt_ready_stale"], 1)

    def test_gate_does_not_consume_the_alt_slot(self):
        # ★ 未就绪时**不得**消耗 `_src_once("alt")` 名额 ✗ ——
        #   否则 readiness 恢复后同一请求反而用不上备用 ✓。
        guard._tr_begin(b"\x00" * 12, "udp", "probe")
        self.assertFalse(guard._alt_gate())
        t = guard._tr()
        self.assertEqual(t.get("src_tries", {}).get("alt"), None)

    def test_gate_runs_before_src_once_at_every_call_site(self):
        src = open(GUARD_SRC, encoding="utf-8").read()
        for fn in ("_policy_cn_answer", "_retry_authenticated", "_finalize_return"):
            i = src.index("def %s(" % fn)
            seg = src[i:i + 20000]
            self.assertIn("_alt_gate()", seg, fn)
            # 顺序：闸门必须在 `_src_once("alt")` **之前** ✓
            self.assertLess(seg.index("_alt_gate()"), seg.index('_src_once("alt")'), fn)

    def test_gate_does_not_consume_half_open_slot(self):
        # ★ `_alt_gate()` 只能读 `breaker_snapshot()`，**绝不能调** `breaker_state()` ✗ ——
        #   后者会把"半开名额"消费掉 ⇒ 试探永不发出、断路器永不恢复 ✗。
        # ★ 判据用 **AST 调用点**而不是整段字符串 ✗ —— 函数里的注释/文档**正当地**
        #   提到了被禁的那个名字（用来解释为什么不许调 ✗）⇒ `assertNotIn` 必然误报 ✗
        #   （本项目在 `test_negative_cache_no_forced_30s_floor` 上已踩过同一个坑 ✓）。
        tree = ast.parse(open(GUARD_SRC, encoding="utf-8").read())
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_alt_gate":
                fn = node
                break
        self.assertIsNotNone(fn)
        called = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute):
                    called.add(f.attr)          # `_A.breaker_state`
                elif isinstance(f, ast.Name):
                    called.add(f.id)            # `breaker_state`
        self.assertIn("breaker_snapshot", called)
        self.assertNotIn("breaker_state", called)

    def test_step4_counters_are_persist_skipped(self):
        # 窗口量 ⇒ 必须每次启动归零（比率一律用两次快照 delta ✓）
        for k in ("alt_ready", "alt_not_ready", "alt_unavailable_skip", "alt_breaker_trips",
                  "alt_transport_ok", "alt_transport_fail",
                  "alt_half_open_ok", "alt_half_open_fail",
                  "alt_ready_missing", "alt_ready_stale", "alt_ready_identity_changed",
                  "alt_ready_config_changed", "alt_ready_other"):
            self.assertIn(k, guard.PERSIST_SKIP, k)
            self.assertIn(k, guard._stats, k)

    def test_readiness_keys_are_in_the_flag_whitelist(self):
        # 否则 `_tr_flag("alt_ready")` 会落进 `other` ⇒ 指标上看不出闸门是否生效 ✗
        self.assertEqual(guard._tag_bucket("alt_ready"), "alt_ready")
        self.assertEqual(guard._tag_bucket("alt_not_ready"), "alt_not_ready")


# ---------------------------------------------------------------- E：readiness 脚本
class ReadinessScriptConfigHash(unittest.TestCase):
    def test_script_has_config_hash_plumbing(self):
        src = open(READY_SRC, encoding="utf-8").read()
        self.assertIn("def config_hash(", src)
        self.assertIn('"config_hash": config_hash() if cfg_hash is None else cfg_hash', src)
        self.assertIn("def identity_matches(", src)
        self.assertIn("identity_matches(old, boot, cid, started, cfg, pid_fp)", src)
        # ★ pid_fp 必须**带 container** 反查（写侧要为被测容器取指纹）；不带就会写进
        #   生产容器的指纹 ⇒ 副本冷启动门 10/10 假失败 ✗（本块实测踩到 ✓）。
        self.assertIn("pid_fp = _pid_fp(container=container)", src)
        self.assertIn('"pid_fp": _pid_fp(container=container)', src)
        self.assertIn("def alt_pidfile(", src)

    def test_identity_matches_covers_config_hash(self):
        # 生产路径与 mock 共用同一函数 ⇒ 断言才有意义 ✓
        sys.path.insert(0, RELEASE_DIR)
        import importlib
        mod = importlib.import_module("unbound-alt-readiness")
        rec = {"boot_id": "b", "container_id": "c", "started_at": "s", "config_hash": "h"}
        self.assertTrue(mod.identity_matches(rec, "b", "c", "s", "h"))
        self.assertFalse(mod.identity_matches(rec, "b", "c", "s", "h2"))
        self.assertFalse(mod.identity_matches(rec, "b", "c", "s2", "h"))
        self.assertFalse(mod.identity_matches(rec, "b", "c2", "s", "h"))
        self.assertFalse(mod.identity_matches(rec, "b2", "c", "s", "h"))
        self.assertFalse(mod.identity_matches(None, "b", "c", "s", "h"))
        # 第 5 项：pid_fp（容器自身 pid 文件指纹）—— 存在即严比 ✓
        rec2 = dict(rec, pid_fp=[1, 2])
        self.assertTrue(mod.identity_matches(rec2, "b", "c", "s", "h", [1, 2]))
        self.assertFalse(mod.identity_matches(rec2, "b", "c", "s", "h", [1, 3]))
        # 任一侧为 None ⇒ 跳过（不变成"永远不 ready" ✗）
        self.assertTrue(mod.identity_matches(rec2, "b", "c", "s", "h", None))
        self.assertTrue(mod.identity_matches(rec, "b", "c", "s", "h", [1, 2]))

    def test_config_hash_ignores_pid_files(self):
        sys.path.insert(0, RELEASE_DIR)
        import importlib
        mod = importlib.import_module("unbound-alt-readiness")
        d = os.path.join(_TMP, "cfgdir")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "unbound.conf"), "w") as fh:
            fh.write("server:\n")
        old = mod.CONFIG_DIRS
        try:
            mod.CONFIG_DIRS = [d]
            h1 = mod.config_hash()
            self.assertNotEqual(h1, "unavailable")
            with open(os.path.join(d, "unbound.pid"), "w") as fh:
                fh.write("12345")                     # 运行期文件 ⇒ 不参与哈希 ✓
            self.assertEqual(mod.config_hash(), h1)
            with open(os.path.join(d, "unbound.conf"), "w") as fh:
                fh.write("server:\n  do-not-query-localhost: no\n")
            self.assertNotEqual(mod.config_hash(), h1)   # 实质变化 ⇒ 哈希必须变 ✓
        finally:
            mod.CONFIG_DIRS = old

    def test_config_hash_never_opens_non_regular_files(self):
        """★★ 现场血案回归（2026-10-10）：`/opt/unbound-alt/dev/` 是**设备节点目录**
        （`null`/`random`/`urandom`）⇒ 原实现 `open(fp,"rb").read()` 读 `/dev/random`
        **永不返回**、内存爆掉 ⇒ 进程被 OOM killer 干掉 ✗：
          `Out of memory: Killed process (python3) total-vm:806668kB anon-rss:532880kB`
        而 `config_hash()` 排在 `write_state()` **之前** ⇒ **状态文件永远写不出去** ⇒
        guard 侧永远 not-ready ⇒ §4 的备用通道静默失效 ✗（比报错更坏 ✗）。

        判据：**任何非常规文件（字符设备/FIFO/socket）都不得被 `open()`** ✓ ——
        用假的 `os.stat` 造一个"字符设备"并把 `builtins.open` 换成会炸的桩 ✓。
        """
        sys.path.insert(0, RELEASE_DIR)
        import importlib
        import stat as _stat
        mod = importlib.import_module("unbound-alt-readiness")
        d = os.path.join(_TMP, "devdir")
        os.makedirs(d, exist_ok=True)
        real = os.path.join(d, "urandom")
        with open(real, "w") as fh:
            fh.write("pretend-device")
        opened = []
        real_open = open
        real_stat = os.stat

        def fake_open(path, *a, **kw):
            if os.path.abspath(str(path)) == os.path.abspath(real):
                raise AssertionError("非常规文件被 open() ✗ —— 会读到死 ✗")
            return real_open(path, *a, **kw)

        def fake_stat(path, *a, **kw):
            st = real_stat(path, *a, **kw)
            if os.path.abspath(str(path)) == os.path.abspath(real):
                # 伪装成字符设备（S_IFCHR）✓
                return os.stat_result((_stat.S_IFCHR | 0o666,) + tuple(st)[1:])
            return st

        old_dirs = mod.CONFIG_DIRS
        try:
            mod.CONFIG_DIRS = [d]
            import builtins
            builtins.open = fake_open
            os.stat = fake_stat
            os.stat = fake_stat
            try:
                h = mod.config_hash()          # 必须**立刻返回**、绝不阻塞 ✓
            finally:
                builtins.open = real_open
                os.stat = real_stat
            # 没有常规文件 ⇒ 返回 unavailable（而不是挂死 ✓）
            self.assertEqual(h, "unavailable")
        finally:
            mod.CONFIG_DIRS = old_dirs

    def test_dev_dir_is_structurally_skipped(self):
        # `dev/` 直接在目录白名单里排除 ✓ ⇒ 即便里面某天变成常规文件也不影响哈希语义 ✓
        sys.path.insert(0, RELEASE_DIR)
        import importlib
        mod = importlib.import_module("unbound-alt-readiness")
        self.assertIn("dev", mod.CONFIG_SKIP_DIRS)
        d = os.path.join(_TMP, "devskip")
        os.makedirs(os.path.join(d, "dev"), exist_ok=True)
        with open(os.path.join(d, "unbound.conf"), "w") as fh:
            fh.write("server:\n")
        with open(os.path.join(d, "dev", "whatever"), "w") as fh:
            fh.write("v1")
        old = mod.CONFIG_DIRS
        try:
            mod.CONFIG_DIRS = [d]
            h1 = mod.config_hash()
            with open(os.path.join(d, "dev", "whatever"), "w") as fh:
                fh.write("v2-CHANGED")
            self.assertEqual(mod.config_hash(), h1)
        finally:
            mod.CONFIG_DIRS = old


if __name__ == "__main__":
    unittest.main()
