# -*- coding: utf-8 -*-
"""test_cn_metrics.py —— §6：CN 名单载入的可观测指标。

背景（2026-10-15 用户要求）：typed 名单 / veto 名单 / cn_ip 段原先只在载入那一刻打一行日志，
线上无法回答"当前生效的名单有多大、什么时候载入的、失败过几次"。现在三者都把规模与时刻
写进 `_stats`（⇒ 自动进 stats.json 与 --status 看板），并按 §6 每次启动归零。

本文件钉住的行为：
  · typed 载入成功 ⇒ cn_typed_full/domain/suffix/total 等于实际集合规模、active=1、loaded_ts>0
  · typed 文件缺失或为空 ⇒ cn_typed_fail 递增、cn_typed_active=0（并回退旧语义）
  · veto 载入成功 ⇒ cn_veto_entries 等于条目数；live 缺失走 release 快照时同样计数 + fail 递增
  · cn_ip.txt ⇒ cn_ip_nets 等于段数；文件 mtime 变化后**无需重启**即可热重载（mtime 节流）
  · 全部键都注册在 `_stats` 且登记进 `PERSIST_SKIP`（每次启动归零的状态量语义）

状态隔离：与 test_cn_typing.py 同法（tempdir + 载入后 pin 路径常量），不触网、不碰生产路径。
"""
import os
import sys
import tempfile
import time
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RELEASE_DIR)

TMP = tempfile.mkdtemp(prefix="cn-metrics-")
TYPED_F = os.path.join(TMP, "cn-domains-typed.txt")
RULES_F = os.path.join(TMP, "forwarding-rules.txt")
VETO_F = os.path.join(TMP, "cn_veto.txt")
SNAP_F = os.path.join(TMP, "cn-veto.snapshot.txt")
IP_F = os.path.join(TMP, "cn_ip.txt")

os.environ["GUARD_STATE_DIR"] = TMP
os.environ["GUARD_LOG"] = os.path.join(TMP, "guard.log")
os.environ["GUARD_CN_TYPED_FILE"] = TYPED_F
os.environ["GUARD_CN_DOMAINS_FILE"] = RULES_F
os.environ["GUARD_CN_VETO_FILE"] = VETO_F
os.environ["GUARD_CN_DOMESTIC_PRIMARY"] = "0"
os.environ["GUARD_CN_DOMESTIC_TRUST_B"] = "0"
os.environ["GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT"] = "0"

import guard  # noqa: E402

TYPED_FIX = "# typed fixture\nfull:exact.example\ndomain:dom.example\nsuffix:sfx.example\nplain.example\n"
VETO_FIX = "# veto fixture\nveto-a.example\nveto-b.example\nveto-c.example\n"
SNAP_FIX = "# veto snapshot\nsnap-a.example\nsnap-b.example\n"
IP_FIX = "1.1.8.0/24\n1.2.4.0/24\n"
IP_FIX2 = "1.1.8.0/24\n1.2.4.0/24\n1.8.1.0/24\n"


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _rm(path):
    try:
        os.remove(path)
    except Exception:
        pass


def _pin():
    """把名单路径钉回本测试的临时文件（同进程内 guard 只 import 一次）。"""
    guard.CN_TYPED_FILE = TYPED_F
    guard.CN_DOMAINS_FILE = RULES_F
    guard.CN_VETO_FILE = VETO_F
    guard.CN_VETO_SNAPSHOT = SNAP_F
    # 第三份审计 F4：typed 也有「最后有效快照」回退，必须钉到临时目录 ——
    # 否则服务器上真实存在的生产快照会把「缺文件即降级」的用例变成「成功载入」。
    guard.CN_TYPED_SNAPSHOT = os.path.join(TMP, "cn-domains-typed.snapshot.txt")
    guard.CN_FILE = IP_F
    # 测试绝不触网：CN_URL 指向必然拒绝连接的本机端口，任何误触下载都会立刻失败
    # （也不会用远端数据覆盖临时 cn_ip.txt）。
    guard.CN_URL = "http://127.0.0.1:9/all_cn.txt"


def _reset_caches():
    guard._CN_TYPED.update({"data": None, "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_VETO.update({"set": set(), "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_NETS_CHK.update({"mtime": 0.0, "checked": 0.0})
    guard._cn_nets = []
    for k in guard._cn_list_keys:
        guard._stats[k] = 0


class TypedMetrics(unittest.TestCase):
    def setUp(self):
        _pin()
        _reset_caches()

    def test_counts_written_on_success(self):
        _write(TYPED_F, TYPED_FIX)
        sets = guard._load_cn_typed()
        self.assertIsNotNone(sets)
        self.assertEqual(guard._stats["cn_typed_full"], 1)
        self.assertEqual(guard._stats["cn_typed_domain"], 2, "plain.example 按 domain 语义计入")
        self.assertEqual(guard._stats["cn_typed_suffix"], 1)
        self.assertEqual(guard._stats["cn_typed_total"], 4, "三类并集去重后为 4")
        self.assertEqual(guard._stats["cn_typed_active"], 1)
        self.assertGreater(guard._stats["cn_typed_loaded_ts"], 0)

    def test_missing_file_counts_failure(self):
        _rm(TYPED_F)
        self.assertIsNone(guard._load_cn_typed())
        self.assertEqual(guard._stats["cn_typed_fail"], 1)
        self.assertEqual(guard._stats["cn_typed_active"], 0)
        self.assertEqual(guard._stats["cn_typed_total"], 0)

    def test_empty_file_counts_failure_and_falls_back(self):
        _write(TYPED_F, "# only comments\n")
        self.assertIsNone(guard._load_cn_typed())
        self.assertEqual(guard._stats["cn_typed_fail"], 1)
        self.assertEqual(guard._stats["cn_typed_active"], 0)


class VetoMetrics(unittest.TestCase):
    def setUp(self):
        _pin()
        _reset_caches()

    def test_entries_on_live_success(self):
        _write(VETO_F, VETO_FIX)
        got = guard._load_cn_veto()
        self.assertEqual(len(got), 3)
        self.assertEqual(guard._stats["cn_veto_entries"], 3)
        self.assertGreater(guard._stats["cn_veto_loaded_ts"], 0)
        self.assertEqual(guard._stats["cn_veto_fail"], 0)

    def test_snapshot_fallback_counts_failure(self):
        _rm(VETO_F)
        _write(SNAP_F, SNAP_FIX)
        got = guard._load_cn_veto()
        self.assertEqual(sorted(got), ["snap-a.example", "snap-b.example"])
        self.assertEqual(guard._stats["cn_veto_entries"], 2)
        self.assertEqual(guard._stats["cn_veto_fail"], 1)


class IpNetsMetrics(unittest.TestCase):
    def setUp(self):
        _pin()
        _reset_caches()

    def test_nets_metric(self):
        _write(IP_F, IP_FIX)
        guard.load_cn_nets()
        self.assertEqual(len(guard._cn_nets), 2)
        self.assertEqual(guard._stats["cn_ip_nets"], 2)

    def test_reload_without_restart_on_mtime_change(self):
        _write(IP_F, IP_FIX)
        guard.load_cn_nets()
        self.assertEqual(guard._stats["cn_ip_nets"], 2)
        _write(IP_F, IP_FIX2)
        base = os.path.getmtime(IP_F)      # 保证 mtime 确实变化（避免同秒写入）
        os.utime(IP_F, (base + 1.0, base + 1.0))
        guard._CN_NETS_CHK["checked"] = 0.0   # 越过 60s 节流窗口
        guard.load_cn_nets()
        self.assertEqual(guard._stats["cn_ip_nets"], 3, "mtime 变化后应热重载，无需重启")

    def test_throttle_keeps_cache(self):
        _write(IP_F, IP_FIX)
        guard.load_cn_nets()
        _write(IP_F, IP_FIX2)
        future = time.time() + 30
        os.utime(IP_F, (future, future))
        guard.load_cn_nets()               # 节流窗口内 ⇒ 不重载
        self.assertEqual(guard._stats["cn_ip_nets"], 2)


class KeyRegistration(unittest.TestCase):
    KEYS = ("cn_typed_full", "cn_typed_domain", "cn_typed_suffix", "cn_typed_total",
            "cn_typed_active", "cn_typed_fail", "cn_typed_loaded_ts",
            "cn_veto_entries", "cn_veto_fail", "cn_veto_loaded_ts",
            "cn_ip_nets", "stale_out")

    def test_all_keys_registered(self):
        for k in self.KEYS:
            self.assertIn(k, guard._stats, k)

    def test_all_keys_are_per_boot(self):
        for k in self.KEYS:
            self.assertIn(k, guard.PERSIST_SKIP, "%s 必须是每次启动归零的状态量" % k)


class StartupMetricReplay(unittest.TestCase):
    """启动顺序缺陷的回归：`load_counters()` 会把 PERSIST_SKIP 内的键归零，而 veto 守卫
    在**模块导入时**就载入过名单 ⇒ 指标必须在 `load_counters()` 之后重放一次（否则
    stats.json 里恒为 0，运维看不到"当前生效的名单规模"）。"""

    def setUp(self):
        _pin()
        _reset_caches()

    def test_replay_restores_metrics(self):
        _write(TYPED_F, TYPED_FIX)
        _write(VETO_F, VETO_FIX)
        guard._load_cn_typed()
        guard._load_cn_veto()
        self.assertEqual(guard._stats["cn_typed_total"], 4)
        self.assertEqual(guard._stats["cn_veto_entries"], 3)
        for k in guard._cn_list_keys:               # 模拟 load_counters() 的归零
            guard._stats[k] = 0
        guard.refresh_cn_list_metrics()
        self.assertEqual(guard._stats["cn_typed_total"], 4, "重放后 typed 规模必须恢复")
        self.assertEqual(guard._stats["cn_typed_active"], 1)
        self.assertEqual(guard._stats["cn_veto_entries"], 3, "重放后 veto 条目数必须恢复")
        self.assertGreater(guard._stats["cn_veto_loaded_ts"], 0)

    def test_replay_is_idempotent(self):
        _write(TYPED_F, TYPED_FIX)
        _write(VETO_F, VETO_FIX)
        guard.refresh_cn_list_metrics()
        first = dict((k, guard._stats[k]) for k in guard._cn_list_keys)
        guard.refresh_cn_list_metrics()
        for k, v in first.items():
            if k.endswith("_loaded_ts"):
                continue                             # 时间戳本来就该更新
            self.assertEqual(guard._stats[k], v, k)

    def test_wired_after_load_counters(self):
        import io as _io
        with _io.open(os.path.join(RELEASE_DIR, "guard.py"), encoding="utf-8") as f:
            src = f.read()
        body = src[src.index('if __name__ == "__main__":'):]
        self.assertIn("load_counters()", body)
        self.assertLess(body.index("load_counters()"),
                        body.index("refresh_cn_list_metrics()"),
                        "refresh_cn_list_metrics() 必须在 load_counters() 之后调用")


if __name__ == "__main__":
    unittest.main(verbosity=2)
