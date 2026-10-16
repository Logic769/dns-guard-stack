# -*- coding: utf-8 -*-
"""「国内路由」与「国内可信解析」拆分后的信任判定测试（2026-10-15）。

背景：第三份审计 F1 显示社区名单同时决定"路由意愿"与"信任授权" —— 一次分类错误
（`tiktokcdn-*` 被判国内）会把国内上游的污染答案升级成"免见证直采"并下发公网。
本测试锁定拆分后的语义：

  · `is_cn_domain()` 只管路由（语义不变）；`is_cn_trusted()` 只管信任（能否免见证直采）
  · 信任优先级：例外清单（最高，命中即否）→ 必须是国内路由 → 档位 none 最严 →
    国别后缀 / 人工白名单（父域边界）/ 档位 all 兜底
  · 白名单缺失/失败不抛异常，且不扩大信任
  · 源码级护栏：8 处「跳过见证」的条件都必须经过 `is_cn_trusted()`
"""
import io
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import guard  # noqa: E402

TMP = tempfile.mkdtemp(prefix="cntrust-")
TYPED_F = os.path.join(TMP, "typed.txt")
RULES_F = os.path.join(TMP, "rules.txt")
VETO_F = os.path.join(TMP, "veto.txt")
SNAP_F = os.path.join(TMP, "veto.snapshot.txt")
EXC_F = os.path.join(TMP, "exceptions.txt")
ALLOW_F = os.path.join(TMP, "allow.txt")


def _write(path, lines):
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def _pin():
    guard.CN_TYPED_FILE = TYPED_F
    guard.CN_DOMAINS_FILE = RULES_F
    guard.CN_VETO_FILE = VETO_F
    guard.CN_VETO_SNAPSHOT = SNAP_F
    guard.CN_TYPED_SNAPSHOT = os.path.join(TMP, "typed.snapshot.txt")
    guard.CN_TRUST_EXC_FILE = EXC_F
    guard.CN_TRUST_ALLOW_FILE = ALLOW_F
    guard.CN_FILE = os.path.join(TMP, "cn_ip.txt")
    guard.CN_URL = "http://127.0.0.1:9/all_cn.txt"


def _reset():
    guard._CN_TYPED.update({"data": None, "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_VETO.update({"set": set(), "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_TRUST_EXC.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
    guard._CN_TRUST_ALLOW.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
    for k in guard._cn_list_keys:
        guard._stats[k] = 0


class TrustSplitBase(unittest.TestCase):
    def setUp(self):
        _pin()
        _reset()
        # bar.example / evilbar.example 同时进 typed：白名单只对「已判国内路由」的域名生效，
        # 且父域边界必须是标签级（evilbar.example 不得命中白名单里的 bar.example）✓
        _write(TYPED_F, ["full:exact.example", "domain:dom.example", "suffix:sfx.example",
                         "domain:allow.example", "domain:bar.example",
                         "domain:evilbar.example"])
        _write(RULES_F, [])
        _write(VETO_F, ["veto.example"])
        _write(EXC_F, ["exc.example"])
        _write(ALLOW_F, ["allow.example", "# 注释行", "bar.example  余项被忽略"])

    def tearDown(self):
        self.allow_patch = None
        _reset()


class TrustMatrix(TrustSplitBase):
    def test_country_suffix_is_trusted_and_routed(self):
        self.assertTrue(guard.is_cn_domain("www.example.cn"))
        self.assertTrue(guard.is_cn_trusted("www.example.cn"))

    def test_allowlist_hit_and_label_boundary(self):
        self.assertTrue(guard.is_cn_trusted("bar.example"))
        self.assertFalse(guard.is_cn_trusted("evilbar.example"))

    def test_routed_but_not_trusted(self):
        """typed 名单内的域名仍走国内路由，但默认档位下不再免见证。"""
        self.assertTrue(guard.is_cn_domain("dom.example"))
        self.assertTrue(guard.is_cn_domain("sub.dom.example"))
        self.assertFalse(guard.is_cn_trusted("dom.example"))
        self.assertFalse(guard.is_cn_trusted("sub.dom.example"))

    def test_exception_beats_suffix_and_allow(self):
        self.assertFalse(guard.is_cn_domain("exc.example"))
        self.assertFalse(guard.is_cn_trusted("exc.example"))
        self.assertFalse(guard.is_cn_trusted("sub.exc.example"))

    def test_non_cn_name_not_trusted(self):
        self.assertFalse(guard.is_cn_trusted("google.com"))
        self.assertFalse(guard.is_cn_trusted(""))

    def test_mode_all_restores_legacy_behaviour(self):
        with mock.patch.object(guard, "CN_TRUST_MODE", "all"):
            self.assertTrue(guard.is_cn_trusted("dom.example"))

    def test_mode_none_is_strictest(self):
        with mock.patch.object(guard, "CN_TRUST_MODE", "none"):
            self.assertFalse(guard.is_cn_trusted("www.example.cn"))
            self.assertFalse(guard.is_cn_trusted("bar.example"))
            self.assertFalse(guard.is_cn_trusted("dom.example"))


class AllowlistDegradation(TrustSplitBase):
    def test_missing_allow_file_is_not_failure(self):
        os.remove(ALLOW_F)
        _reset()
        _pin()
        self.assertFalse(guard.is_cn_trusted("dom.example"))
        self.assertEqual(guard._stats.get("cn_trust_allow_missing"), 1)
        self.assertEqual(guard._stats.get("cn_trust_allow_entries"), 0)

    def test_single_label_entries_are_ignored(self):
        _write(ALLOW_F, ["nodot", "ok.example"])
        guard._CN_TRUST_ALLOW.update({"loaded": False, "checked": 0.0, "mtime": 0.0})
        self.assertIn("ok.example", guard._load_cn_trust_allow())
        self.assertNotIn("nodot", guard._load_cn_trust_allow())


class MetricsAndGeneration(TrustSplitBase):
    NEW_KEYS = ("cn_trust_allow_entries", "cn_trust_allow_loaded_ts", "cn_trust_allow_missing",
                "cn_trust_allow_fail", "cn_trust_bypass", "cn_trust_witness",
                "cn_trust_class_suffix", "cn_trust_class_allow", "cn_trust_class_mode_all",
                "cn_trust_class_witness", "cn_trust_class_exception", "cn_list_gen_change_trust")

    def test_new_keys_registered(self):
        for k in self.NEW_KEYS:
            self.assertIn(k, guard._stats, k)

    def test_generation_includes_trust_component(self):
        guard._load_cn_trust_allow()
        g1 = guard._cn_gen_id()
        self.assertEqual(len(g1.split("|")), 4)
        _write(ALLOW_F, ["allow.example", "bar.example"])
        guard._CN_TRUST_ALLOW.update({"loaded": False, "checked": 0.0, "mtime": 0.0})
        guard._load_cn_trust_allow()
        self.assertNotEqual(g1, guard._cn_gen_id())

    def test_class_counter_moves(self):
        guard._stats["cn_trust_class_suffix"] = 0
        guard.is_cn_trusted("www.example.cn")
        self.assertGreater(guard._stats["cn_trust_class_suffix"], 0)

    def test_witness_counter_for_untrusted_route(self):
        guard._stats["cn_trust_class_witness"] = 0
        guard.is_cn_trusted("dom.example")
        self.assertGreater(guard._stats["cn_trust_class_witness"], 0)


class SourceWiring(unittest.TestCase):
    """源码护栏：8 处「跳过见证」的条件都必须经过 is_cn_trusted()。"""

    def test_skip_conditions_use_trust(self):
        src = io.open(os.path.join(ROOT, "guard.py"), encoding="utf-8").read()
        # 6 处快路/兜底条件是多行书写 ⇒ 不能按字面串计数：统计真实调用点（= 8 处）✓
        calls = re.findall(r"is_cn_trusted\(name\)", src)
        self.assertGreaterEqual(len(calls), 8,
                                "CN 快路/兜底路径的跳过条件未全部接入信任判定")
        self.assertEqual(src.count("if CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B:\n"), 0,
                         "仍有未接入信任判定的采纳闸门")

    def test_startup_reports_mode(self):
        src = io.open(os.path.join(ROOT, "guard.py"), encoding="utf-8").read()
        self.assertIn("CN trust split: mode=%s", src)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
