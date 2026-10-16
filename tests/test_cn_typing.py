# -*- coding: utf-8 -*-
"""test_cn_typing.py —— F5：CN 名单按 v2fly 匹配类型判定（full / domain / suffix）。

背景（审计 2026-10-15 §F5）：
  旧链路 `refresh-cn-rules.py:83` 对 `full:`/`domain:`/`suffix:` 一律去前缀合并，
  guard 的 `is_cn_domain()` 再对所有条目做「精确 + 子域」匹配 ⇒
  `full:host.example` 会连 `child.host.example` 一起判国内；国内 B 是允许直接采纳的
  信任源 ⇒ 分类范围扩大 = 信任范围扩大。

本文件钉住的行为：
  · `full:` 前缀   ⇒ 仅精确匹配（子域不判国内）
  · `domain:` 前缀 ⇒ 自身 + 子域
  · `suffix:` 前缀 ⇒ 按标签边界匹配（`evilx.com` 不因后缀 `x.com` 被判国内）
  · 无前缀条目     ⇒ 按 domain 语义（= 历史行为，向后兼容）
  · 否决优先：veto 命中的名字即便在 typed 名单里也判「非国内」
  · 无点条目丢弃；大小写 / 尾点归一化
  · typed 文件缺失或只有注释 ⇒ 回退旧语义（合并集合 + 精确/子域）

状态隔离：`GUARD_STATE_DIR` / `GUARD_LOG` / 三个名单文件路径都在 `import guard` 之前
指向 `tempfile.mkdtemp()` ⇒ 绝不触碰 /opt/dnsguard 等生产路径。不触网。

运行：PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
"""
import os
import shutil
import sys
import tempfile
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RELEASE_DIR)

TMP = tempfile.mkdtemp(prefix="cn-typing-")
TYPED_F = os.path.join(TMP, "cn-domains-typed.txt")
RULES_F = os.path.join(TMP, "forwarding-rules.txt")
VETO_F = os.path.join(TMP, "cn_veto.txt")

os.environ["GUARD_STATE_DIR"] = TMP
os.environ["GUARD_LOG"] = os.path.join(TMP, "guard.log")
os.environ["GUARD_CN_TYPED_FILE"] = TYPED_F
os.environ["GUARD_CN_DOMAINS_FILE"] = RULES_F
os.environ["GUARD_CN_VETO_FILE"] = VETO_F
os.environ["GUARD_CN_DOMESTIC_PRIMARY"] = "0"
os.environ["GUARD_CN_DOMESTIC_TRUST_B"] = "0"
os.environ["GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT"] = "0"

import guard  # noqa: E402

TYPED_FIX = "\n".join([
    "# typed fixture",
    "full:exact.example",
    "domain:dom.example",
    "suffix:sfx.example",
    "plain.example",            # 无前缀 ⇒ domain 语义
    "domain:veto.example",      # 同时出现在 veto 名单 ⇒ 否决优先
    "UPPER.Example",            # 大小写归一化
    "nodot",                    # 无点条目 ⇒ 丢弃
    "",
])
RULES_FIX = "legacy.example 127.0.0.1:5354\nchild.legacy.example 127.0.0.1:5354\n"
VETO_FIX = "# veto fixture\nveto.example\n"


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _pin_paths():
    """把 guard 的名单路径常量钉回本测试的临时文件。

    为什么必须显式钉：`unittest discover` 按文件名字母序加载，`test_audit_fixes.py`
    等文件会**先** `import guard`，此时 `CN_TYPED_FILE` / `CN_DOMAINS_FILE` /
    `CN_VETO_FILE` 已按它们的 env（或默认生产路径）定死；本文件在 import 前设置的
    os.environ 对已导入的模块不再生效。不钉就会出现「单跑绿、全量红」的假失败。
    """
    guard.CN_TYPED_FILE = TYPED_F
    guard.CN_DOMAINS_FILE = RULES_F
    guard.CN_VETO_FILE = VETO_F
    # 第三份审计 F4 起：`_load_cn_typed()` 失败会尝试**发布快照** ⇒ 必须把它也钉进本
    # tempdir（本 tempdir 下不会有快照文件），否则可能读到别的测试文件或生产发布目录的快照。
    guard.CN_TYPED_SNAPSHOT = os.path.join(TMP, "cn-domains-typed.snapshot.txt")


def _reset_caches():
    guard._CN_TYPED.update({"data": None, "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_DOMAINS.update({"set": set(), "mtime": 0.0, "checked": 0.0})
    guard._CN_VETO.update({"set": set(), "mtime": 0.0, "checked": 0.0})


class TypedCnMatching(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _write(VETO_F, VETO_FIX)

    def setUp(self):
        _pin_paths()
        _write(TYPED_F, TYPED_FIX)
        _write(RULES_F, RULES_FIX)
        _reset_caches()

    def test_full_matches_exact_only(self):
        self.assertTrue(guard.is_cn_domain("exact.example"))
        self.assertFalse(guard.is_cn_domain("child.exact.example"))

    def test_domain_matches_self_and_subdomains(self):
        self.assertTrue(guard.is_cn_domain("dom.example"))
        self.assertTrue(guard.is_cn_domain("a.dom.example"))
        self.assertTrue(guard.is_cn_domain("a.b.dom.example"))

    def test_domain_does_not_match_lookalikes(self):
        self.assertFalse(guard.is_cn_domain("notdom.example"))
        self.assertFalse(guard.is_cn_domain("dom.example.evil"))

    def test_suffix_matches_on_label_boundary(self):
        self.assertTrue(guard.is_cn_domain("sfx.example"))
        self.assertTrue(guard.is_cn_domain("a.sfx.example"))

    def test_suffix_does_not_match_bare_string_suffix(self):
        # 关键：suffix 不是裸字符串 endswith（否则 evilx.com 会被 x.com 命中）
        self.assertFalse(guard.is_cn_domain("notsfx.example"))
        self.assertFalse(guard.is_cn_domain("sfx.example.evil"))

    def test_no_prefix_is_domain_semantics(self):
        self.assertTrue(guard.is_cn_domain("plain.example"))
        self.assertTrue(guard.is_cn_domain("x.plain.example"))

    def test_nodot_entry_is_dropped(self):
        self.assertFalse(guard.is_cn_domain("nodot"))
        self.assertFalse(guard.is_cn_domain("a.nodot"))

    def test_case_and_trailing_dot_normalized(self):
        self.assertTrue(guard.is_cn_domain("EXACT.EXAMPLE."))
        self.assertTrue(guard.is_cn_domain("Upper.Example"))

    def test_veto_wins_over_typed_list(self):
        self.assertFalse(guard.is_cn_domain("veto.example"))
        self.assertFalse(guard.is_cn_domain("sub.veto.example"))

    def test_cn_suffix_still_matches(self):
        self.assertTrue(guard.is_cn_domain("some-thing.cn"))

    def test_typed_sets_are_split_by_type(self):
        sets = guard._load_cn_typed()
        self.assertIsNotNone(sets)
        self.assertIn("exact.example", sets["full"])
        self.assertIn("dom.example", sets["domain"])
        self.assertIn("sfx.example", sets["suffix"])
        self.assertIn("plain.example", sets["domain"])
        self.assertNotIn("nodot", sets["domain"])
        self.assertNotIn("exact.example", sets["domain"])


class TypedFallback(unittest.TestCase):

    def setUp(self):
        _pin_paths()
        _write(RULES_F, RULES_FIX)
        _write(VETO_F, VETO_FIX)

    def test_missing_typed_file_denies_wide_match(self):
        """第三份审计 F4：typed 与发布快照都不可用 ⇒ **不再**回退旧「精确 + 子域」宽匹配。

        旧行为会把 `full:` 的精确匹配放大成子域信任（方向是扩大国内信任）；现在这类域名
        判为"非国内"，走 A/alt 认证源（可用性略降、信任范围不扩大）。
        """
        if os.path.exists(TYPED_F):
            os.remove(TYPED_F)
        _reset_caches()
        self.assertIsNone(guard._load_cn_typed())
        self.assertFalse(guard.is_cn_domain("legacy.example"))
        self.assertFalse(guard.is_cn_domain("child.legacy.example"))
        self.assertFalse(guard.is_cn_domain("unrelated.example"))
        # .cn 国别后缀仍判国内（不受 F4 收紧影响）
        self.assertTrue(guard.is_cn_domain("www.some-site.cn"))

    def test_comment_only_typed_file_is_unavailable(self):
        _write(TYPED_F, "# only a comment\n\n")
        _reset_caches()
        self.assertIsNone(guard._load_cn_typed())
        self.assertFalse(guard.is_cn_domain("child.legacy.example"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
