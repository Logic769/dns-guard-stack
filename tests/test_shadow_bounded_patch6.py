# -*- coding: utf-8 -*-
"""test_shadow_bounded_patch6.py —— 方案 §1.2「shadow 采样 + 有界提交」的离线回归用例。

方案来源：docs/superpowers/plans/2026-10-10-dns-remaining-concrete-plan.md §1.3

硬性约束（§1.3 第 1 条）：
  · **不 import 完整 guard**（会启动它的后台线程 / 触碰生产状态目录）。本文件用 `ast`
    从 guard.py 源码中**只切出 shadow 相关函数与常量**（保持原文件顺序），再 exec 到一个
    注入了桩的普通 dict 命名空间 ✓。
  · mock UDP（`_udp_raw`）、executor（`_shadow_pool`）、随机数（`random.randrange`）✓。
  · 固定随机序列 0..99 重复 10 轮：普通候选 pct=10 → 选中 100/1000；pct=50 → 500/1000；
    always 域名 pct>0 全选、pct=0 全跳过 ✓。
  · 有界：4 个未完成任务时第 5 次提交必须被拒；释放后 pending 归零；
    submit 异常 / worker 异常都不泄漏槽位 ✓。
  · 不变量：`submitted == completed + pending`、`pending_peak <= 4` ✓。

运行：PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
"""
import ast
import io
import os
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASE_DIR = os.path.dirname(TESTS_DIR)
GUARD_SRC = os.path.join(RELEASE_DIR, "guard.py")

WANTED_ASSIGN = ("SHADOW_DNSCRYPT", "SHADOW_PCT", "SHADOW_TARGET", "_shadow_pool",
                 "_SHADOW_MAX", "_shadow_sem", "_SHADOW_ALWAYS", "_shadow_recent")
WANTED_FUNC = ("_shadow_target", "_shadow_always", "_shadow_worker", "_shadow_done",
               "shadow_note", "shadow_snapshot")
WANTED = set(WANTED_FUNC) | set(WANTED_ASSIGN)

DEFAULT_ALWAYS = "googlevideo.com,tiktokcdn.com,tiktokvcdn.com"
TARGET = "127.0.0.1:5443"


# ---------------------------------------------------------------- AST 提取

def _node_start(node):
    start = getattr(node, "lineno", None)
    if start is None:
        return None
    for d in (getattr(node, "decorator_list", None) or []):
        if d.lineno < start:
            start = d.lineno
    return start


def _single_name(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.name
    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def extract_shadow_source(path=GUARD_SRC):
    """用 ast 只切出 shadow 相关的**顶层**语句，保持文件原顺序（顺序很关键）。"""
    with io.open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    lines = src.splitlines(True)
    tree = ast.parse(src)
    entries = []
    for node in tree.body:
        start = _node_start(node)
        if start is not None:
            entries.append((start, node))
    entries.sort(key=lambda x: x[0])
    picked = []
    seen = set()
    for idx, (start, node) in enumerate(entries):
        name = _single_name(node)
        if name in WANTED and name not in seen:
            seen.add(name)
            end = entries[idx + 1][0] - 1 if idx + 1 < len(entries) else len(lines)
            picked.append((name, "".join(lines[start - 1:end])))
    missing = sorted(WANTED - seen)
    if missing:
        raise RuntimeError("guard.py 里找不到这些 shadow 定义：%s" % missing)
    return picked


def shadow_source_text():
    return "\n".join(seg for _n, seg in extract_shadow_source())


# ---------------------------------------------------------------- 桩 / 假件

class _LegacyGateError(BaseException):
    """旧双门若复活，用 BaseException 让它穿透 shadow_note 的 `except Exception`。"""


class _RandomSeq(object):
    """固定随机序列 0..99 循环；记录调用次数与参数宽度。"""

    def __init__(self, seq=None):
        self.seq = list(range(100)) if seq is None else list(seq)
        self.i = 0
        self.calls = 0
        self.widths = []

    def randrange(self, n):
        self.calls += 1
        self.widths.append(n)
        v = self.seq[self.i % len(self.seq)]
        self.i += 1
        return v

    def randint(self, a, b):
        raise _LegacyGateError("legacy random.randint gate is back (must be deleted)")


class _FakeFuture(object):
    def __init__(self):
        self.cbs = []
        self.exc = None

    def add_done_callback(self, cb):
        self.cbs.append(cb)

    def cancelled(self):
        return False

    def exception(self):
        return self.exc


class _FakePool(object):
    """记录提交但**不运行** worker；由测试显式 fire() 触发完成回调（可精确控制时点）。"""

    def __init__(self):
        self.calls = []
        self.futures = []
        self.raise_on_submit = None

    def submit(self, fn, *args):
        if self.raise_on_submit is not None:
            raise self.raise_on_submit
        self.calls.append((fn, args))
        fut = _FakeFuture()
        self.futures.append(fut)
        return fut

    def fire_all(self):
        fired = 0
        for fut in self.futures:
            while fut.cbs:
                cb = fut.cbs.pop(0)
                cb(fut)
                fired += 1
        return fired


class _InlineFuture(object):
    """已完成 future：add_done_callback 当场回调（覆盖‘提交瞬间就完成’的竞态）。"""

    def __init__(self, exc=None):
        self.exc = exc

    def add_done_callback(self, cb):
        cb(self)

    def cancelled(self):
        return False

    def exception(self):
        return self.exc


class _InlinePool(object):
    def __init__(self, exc=None):
        self.calls = 0
        self.exc = exc

    def submit(self, fn, *args):
        self.calls += 1
        return _InlineFuture(self.exc)


class _OsShim(object):
    def __init__(self, env):
        self.environ = dict(env)


class _StatsView(dict):
    """计数观察视图：未出现过的键按 0 读（guard 只在自增时建键）。"""

    def __missing__(self, key):
        return 0


class ShadowHarness(object):
    """把 guard.py 的 shadow 片段 exec 进注入桩的命名空间（**不 import guard**）。"""

    def __init__(self, pct=10, target=TARGET, always=DEFAULT_ALWAYS, pool=None,
                 udp=None, norm=None, parse=None):
        self.stats_d = {}
        self.logs = []
        self.udp_calls = []
        self.random = _RandomSeq()
        self.pool = pool
        if udp is None:
            udp = self._default_udp
        if norm is None:
            norm = lambda x: str(x)
        if parse is None:
            parse = lambda b: (0, ["1.2.3.4"], False, 300)
        env = {"GUARD_SHADOW_DNSCRYPT": target or "", "GUARD_SHADOW_PCT": str(pct),
               "GUARD_SHADOW_MAX": "4", "GUARD_SHADOW_ALWAYS": always or ""}
        ns = {"os": _OsShim(env), "threading": threading, "time": time,
              "ThreadPoolExecutor": ThreadPoolExecutor, "random": self.random,
              "log": self.logs.append, "_lock": threading.RLock(),
              "_stats": self.stats_d, "_udp_raw": udp, "parse_a": parse, "_norm_ip": norm}
        exec(compile(shadow_source_text(), GUARD_SRC, "exec"), ns)
        self.ns = ns
        if pool is not None:
            ns["_shadow_pool"] = pool
        self.swap_udp = lambda f: ns.__setitem__("_udp_raw", f)
        self.swap_norm = lambda f: ns.__setitem__("_norm_ip", f)

    def _default_udp(self, msg, host, port, timeout):
        self.udp_calls.append((host, port, timeout))
        return b"\x00\x00\x81\x80" + b"\x00" * 8

    # --- 便捷入口
    def pct(self, v):
        self.ns["SHADOW_PCT"] = v

    def note(self, name, qtype=1, uset8=None, cset8=None, msg=b"m"):
        self.ns["shadow_note"](msg, name, qtype,
                               set(["9.9.9.9"] if uset8 is None else uset8),
                               set(["1.2.3.4"] if cset8 is None else cset8))

    def stats(self):
        return _StatsView(self.stats_d)

    def get(self, key):
        return self.stats_d.get(key, 0)

    def sem_value(self):
        return self.ns["_shadow_sem"]._value

    def closed(self):
        """不变量：submitted == completed + pending。"""
        return self.get("shadow_submitted") == self.get("shadow_completed") + self.get("shadow_pending")

    def wait_drained(self, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.get("shadow_pending") == 0 and self.get("shadow_completed") == self.get("shadow_submitted"):
                return True
            time.sleep(0.01)
        return False

    def close(self):
        p = self.ns.get("_shadow_pool")
        if p is not None and hasattr(p, "shutdown"):
            try:
                p.shutdown(wait=True)
            except Exception:
                pass


# ---------------------------------------------------------------- §1.3-2 采样率

class SamplingRateTest(unittest.TestCase):
    """固定随机序列 0..99 重复 10 轮（=1000 次），executor 为假件（立即释放槽位）。"""

    ROUNDS, N = 10, 100

    def _run(self, pct, name, target=TARGET, always=DEFAULT_ALWAYS):
        pool = _FakePool()
        h = ShadowHarness(pct=pct, target=target, always=always, pool=pool)
        for _ in range(self.ROUNDS):
            for _v in range(self.N):
                h.note(name)
                pool.fire_all()          # 槽位即取即还 ⇒ 只测抽样门
        return h, pool

    def test_pct10_selects_100_of_1000(self):
        h, pool = self._run(10, "example.com")
        st = h.stats()
        print("\n[sampling] pct=10 eligible=%d submitted=%d/1000 sample_skip=%d capacity_skip=%d "
              "pending=%d rand_calls=%d" % (st["shadow_eligible"], st["shadow_submitted"],
                                            st["shadow_sample_skip"], st["shadow_capacity_skip"],
                                            st["shadow_pending"], h.random.calls))
        self.assertEqual(1000, st["shadow_eligible"])
        self.assertEqual(100, st["shadow_submitted"])
        self.assertEqual(100, len(pool.calls))
        self.assertEqual(900, st["shadow_sample_skip"])
        self.assertEqual(0, st["shadow_capacity_skip"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertEqual(1000, h.random.calls)      # 恰好一次抽样/次
        self.assertEqual([100], sorted(set(h.random.widths)))
        self.assertTrue(h.closed())

    def test_pct50_selects_500_of_1000(self):
        h, pool = self._run(50, "example.com")
        st = h.stats()
        print("[sampling] pct=50 eligible=%d submitted=%d/1000 sample_skip=%d"
              % (st["shadow_eligible"], st["shadow_submitted"], st["shadow_sample_skip"]))
        self.assertEqual(1000, st["shadow_eligible"])
        self.assertEqual(500, st["shadow_submitted"])
        self.assertEqual(500, st["shadow_sample_skip"])
        self.assertTrue(h.closed())

    def test_pct100_selects_all(self):
        h, _pool = self._run(100, "example.com")
        self.assertEqual(1000, h.get("shadow_submitted"))
        self.assertEqual(0, h.get("shadow_sample_skip"))

    def test_always_domain_selected_all_when_pct_positive(self):
        h, _pool = self._run(10, "r1---sn-a.googlevideo.com")
        st = h.stats()
        print("[sampling] always pct=10 eligible=%d submitted=%d/1000 sample_skip=%d rand_calls=%d"
              % (st["shadow_eligible"], st["shadow_submitted"], st["shadow_sample_skip"], h.random.calls))
        self.assertEqual(1000, st["shadow_eligible"])
        self.assertEqual(1000, st["shadow_submitted"])
        self.assertEqual(0, st["shadow_sample_skip"])
        self.assertEqual(0, h.random.calls)          # always 走短路，不消耗随机数
        self.assertTrue(h.closed())

    def test_always_domain_skipped_when_pct_zero(self):
        h, pool = self._run(0, "r1---sn-a.googlevideo.com")
        st = h.stats()
        print("[sampling] always pct=0 eligible=%d submitted=%d sample_skip=%d"
              % (st.get("shadow_eligible", 0), st.get("shadow_submitted", 0),
                 st.get("shadow_sample_skip", 0)))
        self.assertEqual(0, st.get("shadow_eligible", 0))
        self.assertEqual(0, st.get("shadow_submitted", 0))
        self.assertEqual(0, len(pool.calls))
        self.assertEqual(0, h.random.calls)

    def test_plain_domain_skipped_when_pct_zero(self):
        h, _pool = self._run(0, "example.com")
        self.assertEqual(0, h.get("shadow_submitted"))
        self.assertEqual(0, h.get("shadow_eligible"))

    def test_disabled_target_never_samples(self):
        h, _pool = self._run(10, "example.com", target="")
        self.assertEqual(0, h.get("shadow_eligible"))
        self.assertEqual(0, h.get("shadow_submitted"))
        self.assertEqual(0, h.random.calls)

    def test_effective_rate_is_p_not_p_squared(self):
        """双门回归保护：pct=10 的有效采样率必须 ≈10%，而不是 ≈1%。"""
        h, _pool = self._run(10, "example.com")
        rate = h.get("shadow_submitted") / float(h.get("shadow_eligible"))
        print("[sampling] effective rate pct=10 = %.3f" % rate)
        self.assertAlmostEqual(0.10, rate, places=3)


# ---------------------------------------------------------------- §1.3-3 有界提交

class BoundedSubmitTest(unittest.TestCase):
    def test_fifth_submit_rejected_then_pending_closes(self):
        gate = threading.Event()
        entered = threading.Event()

        def blocked_udp(msg, host, port, timeout):
            entered.set()
            gate.wait(15.0)
            return b"\x00\x00\x81\x80" + b"\x00" * 8

        h = ShadowHarness(pct=100, udp=blocked_udp)
        self.addCleanup(h.close)
        self.addCleanup(gate.set)
        for i in range(4):
            h.note("blocked%d.example.com" % i)
        self.assertTrue(entered.wait(5.0))
        st = h.stats()
        print("\n[bounded] 4 submitted: submitted=%d pending=%d peak=%d capacity_skip=%d sem=%d"
              % (st["shadow_submitted"], st["shadow_pending"], st["shadow_pending_peak"],
                 st["shadow_capacity_skip"], h.sem_value()))
        self.assertEqual(4, st["shadow_submitted"])
        self.assertEqual(4, st["shadow_pending"])       # 2 运行 + 2 排队
        self.assertEqual(4, st["shadow_pending_peak"])
        self.assertEqual(0, st["shadow_capacity_skip"])
        self.assertEqual(0, h.sem_value())
        self.assertTrue(h.closed())

        h.note("fifth.example.com")                     # 第五次必须被拒
        st = h.stats()
        print("[bounded] 5th rejected: submitted=%d pending=%d capacity_skip=%d shadow_skipped=%d"
              % (st["shadow_submitted"], st["shadow_pending"], st["shadow_capacity_skip"],
                 st["shadow_skipped"]))
        self.assertEqual(4, st["shadow_submitted"])
        self.assertEqual(4, st["shadow_pending"])
        self.assertEqual(1, st["shadow_capacity_skip"])
        self.assertEqual(1, st["shadow_skipped"])       # 兼容 release-4 的旧计数
        self.assertTrue(h.closed())

        gate.set()
        self.assertTrue(h.wait_drained(15.0))
        st = h.stats()
        print("[bounded] drained: submitted=%d completed=%d pending=%d peak=%d sem=%d"
              % (st["shadow_submitted"], st["shadow_completed"], st["shadow_pending"],
                 st["shadow_pending_peak"], h.sem_value()))
        self.assertEqual(4, st["shadow_submitted"])
        self.assertEqual(4, st["shadow_completed"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertLessEqual(st["shadow_pending_peak"], 4)
        self.assertEqual(4, h.sem_value())
        self.assertTrue(h.closed())

    def test_submit_error_does_not_leak_slot(self):
        pool = _FakePool()
        pool.raise_on_submit = RuntimeError("executor is shut down")
        h = ShadowHarness(pct=100, pool=pool)
        for i in range(5):
            h.note("boom%d.example.com" % i)
        st = h.stats()
        print("[bounded] submit error x5: submitted=%d pending=%d submit_error=%d sem=%d"
              % (st["shadow_submitted"], st["shadow_pending"], st["shadow_submit_error"], h.sem_value()))
        self.assertEqual(0, st["shadow_submitted"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertEqual(5, st["shadow_submit_error"])
        self.assertEqual(4, h.sem_value())              # 槽位没有泄漏
        self.assertTrue(h.closed())

    def test_worker_exception_does_not_leak_slot(self):
        def boom(x):
            raise RuntimeError("norm failed")
        h = ShadowHarness(pct=100, norm=boom)
        self.addCleanup(h.close)
        h.note("worker-error.example.com")
        self.assertTrue(h.wait_drained(10.0))
        st = h.stats()
        print("[bounded] worker error: submitted=%d completed=%d pending=%d worker_error=%d sem=%d"
              % (st["shadow_submitted"], st["shadow_completed"], st["shadow_pending"],
                 st["shadow_worker_error"], h.sem_value()))
        self.assertEqual(1, st["shadow_submitted"])
        self.assertEqual(1, st["shadow_completed"])
        self.assertEqual(1, st["shadow_worker_error"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertEqual(4, h.sem_value())
        self.assertTrue(h.closed())

    def test_inline_done_callback_closes_immediately(self):
        """提交瞬间就完成的竞态：回调可能在场内线程直接执行，记账仍必须闭合。"""
        pool = _InlinePool()
        h = ShadowHarness(pct=100, pool=pool)
        h.note("inline.example.com")
        st = h.stats()
        self.assertEqual(1, pool.calls)
        self.assertEqual(1, st["shadow_submitted"])
        self.assertEqual(1, st["shadow_completed"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertEqual(1, st["shadow_pending_peak"])
        self.assertEqual(4, h.sem_value())
        self.assertTrue(h.closed())

    def test_peak_never_exceeds_max_under_stress(self):
        gate = threading.Event()

        def slow_udp(msg, host, port, timeout):
            gate.wait(15.0)
            return b"\x00\x00\x81\x80" + b"\x00" * 8

        h = ShadowHarness(pct=100, udp=slow_udp)
        self.addCleanup(h.close)
        self.addCleanup(gate.set)
        for i in range(25):
            h.note("stress%d.example.com" % i)
            self.assertTrue(h.closed(), "invariant broken at i=%d" % i)
            self.assertLessEqual(h.get("shadow_pending"), 4)
        self.assertEqual(4, h.get("shadow_submitted"))
        self.assertEqual(21, h.get("shadow_capacity_skip"))
        gate.set()
        self.assertTrue(h.wait_drained(15.0))
        self.assertEqual(4, h.get("shadow_completed"))
        self.assertLessEqual(h.get("shadow_pending_peak"), 4)
        self.assertTrue(h.closed())


# ------------------------------------------- §1.3-5 隔离候选流量（loopback 真 UDP）

class IsolatedCandidateTrafficTest(unittest.TestCase):
    """正常流量没有 eligible 时，用**隔离候选流量**证明代码有效。

    仅 127.0.0.1 环回 + 自建 UDP 应答器 + 真实线程池；**不宣称**任何生产 A/B 结论，
    也不接触 GUARD_SHADOW_DNSCRYPT 的真实目标（127.0.0.2:5353）。
    """

    def test_loopback_candidate_flows_through_real_worker(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        got = []
        stop = threading.Event()

        def responder():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = srv.recvfrom(2048)
                except socket.timeout:
                    continue
                except Exception:
                    return
                got.append(data)
                try:
                    srv.sendto(b"\x00\x00\x81\x80" + b"\x00" * 8, addr)
                except Exception:
                    return

        th = threading.Thread(target=responder)
        th.daemon = True
        th.start()

        def real_udp(msg, host, port_, timeout):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(msg, (host, port_))
                return s.recvfrom(4096)[0]
            finally:
                s.close()

        h = ShadowHarness(pct=100, target="127.0.0.1:%d" % port, udp=real_udp)
        self.addCleanup(srv.close)
        self.addCleanup(stop.set)
        self.addCleanup(h.close)
        for i in range(6):
            # 有界语义：等槽位空出再投第 i 个候选（4 槽 = 2 运行 + 2 排队，分两批跑完）
            deadline = time.time() + 10.0
            while h.sem_value() == 0 and time.time() < deadline:
                time.sleep(0.01)
            h.note("iso%d.example.com" % i)
        self.assertTrue(h.wait_drained(15.0))
        st = h.stats()
        print("\n[isolated] pct=100 submitted=%d completed=%d pending=%d tried=%d agree=%d udp_pkts=%d"
              % (st["shadow_submitted"], st["shadow_completed"], st["shadow_pending"],
                 st.get("shadow_tried", 0), st.get("shadow_agree", 0), len(got)))
        self.assertEqual(6, st["shadow_submitted"])
        self.assertEqual(6, st["shadow_completed"])
        self.assertEqual(0, st["shadow_pending"])
        self.assertEqual(6, st.get("shadow_tried", 0))      # worker 真的跑完了
        self.assertEqual(6, st.get("shadow_agree", 0))
        self.assertEqual(6, len(got))                        # 真的发出了 6 个 UDP 包
        self.assertTrue(h.closed())


# ---------------------------------------------------------------- 静态面（防回退）


class StaticShapeTest(unittest.TestCase):
    def test_all_shadow_definitions_found(self):
        names = set(n for n, _s in extract_shadow_source())
        self.assertEqual(WANTED, names)

    def test_exactly_one_sampling_gate_and_no_legacy_randint(self):
        tree = ast.parse(shadow_source_text())
        note = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "shadow_note":
                note = node
        self.assertIsNotNone(note)
        rand_calls = []
        for node in ast.walk(note):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
                rand_calls.append(node.func.attr)
        print("\n[static] shadow_note random calls = %s" % rand_calls)
        self.assertEqual(["randrange"], rand_calls)
        self.assertNotIn("randint", shadow_source_text())

    def test_semaphore_release_sites(self):
        tree = ast.parse(shadow_source_text())
        per_func = {}
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            rel = 0
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr == "release" and isinstance(sub.func.value, ast.Name) \
                        and sub.func.value.id == "_shadow_sem":
                    rel += 1
            per_func[node.name] = rel
        print("[static] _shadow_sem.release() sites = %s" % per_func)
        self.assertEqual(1, per_func.get("shadow_note"))    # 只在 submit 异常分支
        self.assertEqual(1, per_func.get("_shadow_done"))   # 完成回调统一释放
        self.assertEqual(0, per_func.get("_shadow_worker"))  # worker 内不得释放

    def test_limits_are_four_slots_two_workers(self):
        text = shadow_source_text()
        self.assertIn('GUARD_SHADOW_MAX", "4"', text)
        self.assertIn("max_workers=2", text)

    def test_extraction_creates_no_background_threads(self):
        before = threading.active_count()
        h = ShadowHarness(pct=10, pool=_FakePool())
        self.assertEqual(before, threading.active_count())
        self.assertTrue(callable(h.ns["shadow_note"]))

    def test_this_file_never_imports_guard(self):
        with io.open(os.path.abspath(__file__), "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertNotEqual("guard", a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual("guard", (node.module or "").split(".")[0])


if __name__ == "__main__":
    unittest.main()
