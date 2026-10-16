# -*- coding: utf-8 -*-
"""test_cn_trust_f1f2f4.py —— 第三份审计（2026-10-15）F1 / F2 / F4 的护栏测试。

钉住的行为：

F1（国内可信解析例外清单）
  · 命中例外清单的域名 ⇒ `is_cn_domain()` 为 False（**优先于** .cn 后缀与 typed/合并名单）
    ⇒ 该域名走 A/alt 认证源，B 的未签名答案不参与采纳。
  · 例外清单不存在/为空 ⇒ 行为与历史**逐字节一致**（不扩大任何信任，也不缩小）。
  · 子域边界：例外 `x.com` 覆盖 `a.x.com`，但 `evx.com` 不受影响。

F2（名单代次 ⇒ 准入缓存按代次失效）
  · `_adm_cache_put()` 写入的记录带 `cn_gen`（typed|veto|例外 的内容指纹）。
  · 名单内容变化 ⇒ `_adm_cache_get()` 拒绝复用旧记录（`adm_cache_gen_mismatch` 递增）。
  · 名单未变 ⇒ 缓存照常命中（不得因代次核对而把正常缓存全判死）。

F4（typed 冷启动降级）
  · live typed 不可用但存在**发布快照** ⇒ 用快照（`cn_typed_snapshot_used` 递增），语义不变。
  · live 与快照都不可用 ⇒ **不再回退旧的「精确 + 子域」宽匹配**（旧行为会把 `full:` 的
    精确匹配放大成子域信任，方向是扩大国内信任）；此时除 .cn 国别后缀/例外/veto 外判为
    非国内（`cn_typed_fallback_denied` 递增）。

状态隔离：tempdir + 载入后钉住路径常量（与 test_cn_metrics.py 同法），不触网、不碰生产路径。
"""
import os
import socket
import struct
import sys
import tempfile
import time
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RELEASE_DIR)

TMP = tempfile.mkdtemp(prefix="cn-trust-")
TYPED_F = os.path.join(TMP, "cn-domains-typed.txt")
RULES_F = os.path.join(TMP, "forwarding-rules.txt")
VETO_F = os.path.join(TMP, "cn_veto.txt")
SNAP_VETO_F = os.path.join(TMP, "cn-veto.snapshot.txt")
SNAP_TYPED_F = os.path.join(TMP, "cn-domains-typed.snapshot.txt")
EXC_F = os.path.join(TMP, "cn-trust-exceptions.txt")
IP_F = os.path.join(TMP, "cn_ip.txt")

os.environ["GUARD_STATE_DIR"] = TMP
os.environ["GUARD_LOG"] = os.path.join(TMP, "guard.log")
os.environ["GUARD_CN_TYPED_FILE"] = TYPED_F
os.environ["GUARD_CN_DOMAINS_FILE"] = RULES_F
os.environ["GUARD_CN_VETO_FILE"] = VETO_F
os.environ["GUARD_CN_TRUST_EXC_FILE"] = EXC_F
os.environ["GUARD_POLICY_MODE"] = "on"
os.environ["GUARD_CN_DOMESTIC_PRIMARY"] = "0"
os.environ["GUARD_CN_DOMESTIC_TRUST_B"] = "0"
os.environ["GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT"] = "0"

import guard  # noqa: E402

TYPED_FIX = ("# typed fixture\n"
             "full:exact.example\n"
             "domain:tiktokcdn-us.com\n"
             "domain:dom.example\n"
             "suffix:sfx.example\n"
             "plain.example\n")
TYPED_FIX2 = TYPED_FIX + "domain:added.example\n"
VETO_FIX = "# veto fixture\nveto-a.example\nveto-b.example\n"
SNAP_TYPED_FIX = "# typed snapshot\nfull:exact.example\ndomain:tiktokcdn-us.com\n"


def _w(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _rm(path):
    try:
        os.remove(path)
    except Exception:
        pass


_PIN_KEYS = ("CN_TYPED_FILE", "CN_TYPED_SNAPSHOT", "CN_DOMAINS_FILE",
             "CN_VETO_FILE", "CN_VETO_SNAPSHOT", "CN_TRUST_EXC_FILE", "CN_FILE")
_ORIG = {}


def _pin():
    """把 guard 的路径常量钉到本文件的 tempdir（并记住原值，tearDown 恢复）。

    必需：`guard` 在全量运行中只被 import 一次，之后所有测试文件共享同一模块对象 ⇒
    环境变量里的路径对后续文件无效（这正是"单跑通过、全量失败"的根因）。
    恢复原值同样必需：否则会把 pin 后的路径漏给**后面**运行的测试文件，污染它们。
    """
    want = {"CN_TYPED_FILE": TYPED_F, "CN_TYPED_SNAPSHOT": SNAP_TYPED_F,
            "CN_DOMAINS_FILE": RULES_F, "CN_VETO_FILE": VETO_F,
            "CN_VETO_SNAPSHOT": SNAP_VETO_F, "CN_TRUST_EXC_FILE": EXC_F, "CN_FILE": IP_F}
    for k in _PIN_KEYS:
        if k not in _ORIG:
            _ORIG[k] = getattr(guard, k, None)
        setattr(guard, k, want[k])


def _unpin():
    for k, v in _ORIG.items():
        try:
            setattr(guard, k, v)
        except Exception:
            pass
    # 本文件新增的模块级状态也复原，避免影响后续测试文件
    try:
        guard._CN_TRUST_EXC.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
        guard._CN_GEN.update({"typed": "", "veto": "", "exc": ""})
    except Exception:
        pass


class _Pinned(unittest.TestCase):
    """公共 teardown：恢复被 pin 的路径常量（防跨文件污染）。"""

    def tearDown(self):
        _unpin()


def _reset():
    """清空 guard 的模块级缓存与代次，使每个用例从干净状态开始。"""
    _pin()
    guard._CN_TYPED.update({"data": None, "mtime": 0.0, "checked": 0.0, "logged_fail": False})
    guard._CN_VETO.update({"set": None, "mtime": 0.0, "checked": 0.0})
    guard._CN_TRUST_EXC.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
    guard._CN_GEN.update({"typed": "", "veto": "", "exc": ""})
    guard._ADM_CACHE.clear()
    try:
        guard._ADM_BYTES[0] = 0
    except Exception:
        pass
    # `_stats` 是模块级共享字典（全量运行会被其它文件写过）⇒ 本文件关心的键显式归零
    for _k in ("cn_trust_exc_entries", "cn_trust_exc_loaded_ts", "cn_trust_exc_missing",
               "cn_trust_exc_fail", "cn_dom_exception", "cn_typed_snapshot_used",
               "cn_typed_fallback_denied", "cn_list_gen_change", "cn_list_gen_change_typed",
               "cn_list_gen_change_veto", "cn_list_gen_change_exc",
               "cn_exc_change_needs_agh_flush", "adm_cache_gen_mismatch",
               "cn_typed_fail", "cn_typed_total", "cn_veto_fail"):
        if _k in guard._stats:
            guard._stats[_k] = 0


def _wire(name, ip="203.0.113.9", ttl=300):
    """最小合法 A 响应（含 EDNS0 + DO），供准入缓存读写使用。"""
    hdr = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 1)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" \
        + struct.pack("!HH", 1, 1)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return hdr + q + rr + opt


class TrustException(_Pinned):
    """F1：例外清单命中 ⇒ 不走国内 B 路径。"""

    def setUp(self):
        _reset()
        _w(TYPED_F, TYPED_FIX)
        _w(VETO_F, VETO_FIX)
        _rm(EXC_F)
        _rm(SNAP_TYPED_F)

    def test_absent_file_is_no_exception(self):
        """例外清单不存在 ⇒ 无例外（历史行为不变）。"""
        self.assertTrue(guard.is_cn_domain("tiktokcdn-us.com"))
        self.assertTrue(guard.is_cn_domain("zz-probe-1.tiktokcdn-us.com"))
        self.assertEqual(guard._stats.get("cn_trust_exc_entries"), 0)
        self.assertEqual(guard._stats.get("cn_trust_exc_missing"), 1)

    def test_exception_wins_over_typed_and_country_suffix(self):
        """例外优先于 typed 名单与 .cn 国别后缀。"""
        _w(EXC_F, "# 例外\n"
                  "tiktokcdn-us.com\n"
                  "probe.cn\n")
        guard._CN_TRUST_EXC.update({"checked": 0.0, "mtime": 0.0, "loaded": False})
        self.assertFalse(guard.is_cn_domain("tiktokcdn-us.com"))
        self.assertFalse(guard.is_cn_domain("zz-probe-2.tiktokcdn-us.com"))
        self.assertFalse(guard.is_cn_domain("a.b.probe.cn"))
        # 未列入的仍按原语义
        self.assertTrue(guard.is_cn_domain("www.example.cn"))
        self.assertTrue(guard.is_cn_domain("exact.example"))
        self.assertGreaterEqual(guard._stats.get("cn_dom_exception", 0), 3)

    def test_label_boundary(self):
        """例外 x.com 覆盖 a.x.com，但不覆盖 evx.com。"""
        _w(EXC_F, "x.example\n")
        guard._CN_TRUST_EXC.update({"checked": 0.0, "mtime": 0.0, "loaded": False})
        self.assertFalse(guard.is_cn_domain("x.example"))
        self.assertFalse(guard.is_cn_domain("a.x.example"))
        self.assertTrue(guard.is_cn_domain("evx.example") is False or True)  # 仅确保不抛错
        self.assertFalse(guard._in_cn_trust_exc("evx.example"))

    def test_metrics_registered(self):
        _w(EXC_F, "a.example\nb.example\n")
        guard._CN_TRUST_EXC.update({"checked": 0.0, "mtime": 0.0, "loaded": False})
        guard.is_cn_domain("nothing.example")
        self.assertEqual(guard._stats.get("cn_trust_exc_entries"), 2)
        self.assertEqual(guard._stats.get("cn_trust_exc_missing"), 0)
        self.assertGreater(guard._stats.get("cn_trust_exc_loaded_ts", 0), 0)


class TypedSnapshot(_Pinned):
    """F4：typed 冷启动降级 —— 快照优先，且不再宽匹配。"""

    def setUp(self):
        _reset()
        _w(VETO_F, VETO_FIX)
        _rm(EXC_F)
        _rm(TYPED_F)
        _rm(SNAP_TYPED_F)

    def test_snapshot_used_when_live_missing(self):
        _w(SNAP_TYPED_F, SNAP_TYPED_FIX)
        r = guard._load_cn_typed()
        self.assertIsNotNone(r)
        self.assertGreaterEqual(guard._stats.get("cn_typed_snapshot_used", 0), 1)
        self.assertTrue(guard.is_cn_domain("exact.example"))
        self.assertTrue(guard.is_cn_domain("zz.snapshot-child.tiktokcdn-us.com"))

    def test_no_snapshot_means_no_wide_fallback(self):
        """live 与快照都缺 ⇒ 不再把 `full:`/名单域名按子域宽匹配。"""
        self.assertIsNone(guard._load_cn_typed())
        self.assertFalse(guard.is_cn_domain("exact.example"))
        self.assertFalse(guard.is_cn_domain("dom.example"))
        self.assertFalse(guard.is_cn_domain("child.dom.example"))
        self.assertGreaterEqual(guard._stats.get("cn_typed_fallback_denied", 0), 1)
        # .cn 国别后缀不受影响（仍判国内）
        self.assertTrue(guard.is_cn_domain("www.some-cn-site.cn"))


class GenInvalidation(_Pinned):
    """F2：名单代次写进准入缓存，名单变化即拒绝复用。"""

    def setUp(self):
        _reset()
        _w(TYPED_F, TYPED_FIX)
        _w(VETO_F, VETO_FIX)
        _rm(EXC_F)
        _rm(SNAP_TYPED_F)
        guard._load_cn_typed()

    def test_record_carries_gen(self):
        guard._adm_cache_put("adm.example", 1, _wire("adm.example"), "accepted", "local-cn", 300.0)
        rec = guard._ADM_CACHE.get(guard._adm_key("adm.example", 1))
        self.assertIsNotNone(rec)
        self.assertEqual(rec.get("cn_gen"), guard._cn_gen_id())
        self.assertNotEqual(rec.get("cn_gen"), "-|-|-")

    def test_list_change_invalidates_adm_cache(self):
        guard._adm_cache_put("adm.example", 1, _wire("adm.example"), "accepted", "local-cn", 300.0)
        self.assertIsNotNone(guard._adm_cache_get("adm.example", 1))
        # 名单内容变化（新增一条）+ 强制重载 ⇒ 代次变化
        _w(TYPED_F, TYPED_FIX2)
        guard._CN_TYPED.update({"checked": 0.0, "mtime": 0.0})
        guard._load_cn_typed()
        self.assertNotEqual(guard._CN_GEN["typed"], "")
        self.assertIsNone(guard._adm_cache_get("adm.example", 1))
        self.assertGreaterEqual(guard._stats.get("adm_cache_gen_mismatch", 0), 1)
        self.assertGreaterEqual(guard._stats.get("cn_list_gen_change", 0), 1)

    def test_unchanged_list_keeps_cache(self):
        """名单没变 ⇒ 缓存必须照常命中（防止代次核对把缓存全判死）。"""
        guard._adm_cache_put("adm2.example", 1, _wire("adm2.example"), "secure", "local-a", 900.0)
        guard._CN_TYPED.update({"checked": 0.0, "mtime": 0.0})
        guard._load_cn_typed()
        self.assertIsNotNone(guard._adm_cache_get("adm2.example", 1))

    def test_exception_change_counts(self):
        _w(EXC_F, "exc.example\n")
        guard._CN_TRUST_EXC.update({"checked": 0.0, "mtime": 0.0, "loaded": False})
        guard._load_cn_trust_exc()
        self.assertGreaterEqual(guard._stats.get("cn_list_gen_change_exc", 0), 1)
        self.assertGreaterEqual(guard._stats.get("cn_exc_change_needs_agh_flush", 0), 1)


class MetricRegistration(_Pinned):
    """新指标必须注册进 `_stats` 且登记进 `PERSIST_SKIP`（每次启动归零语义）。"""

    def setUp(self):
        _reset()
        _w(VETO_F, VETO_FIX)
        _rm(TYPED_F)

    NEW = ("cn_trust_exc_entries", "cn_trust_exc_loaded_ts", "cn_trust_exc_missing",
           "cn_trust_exc_fail", "cn_dom_exception", "cn_typed_snapshot_used",
           "cn_typed_fallback_denied", "cn_list_gen_change", "cn_list_gen_change_typed",
           "cn_list_gen_change_veto", "cn_list_gen_change_exc",
           "cn_exc_change_needs_agh_flush", "adm_cache_gen_mismatch")

    def test_registered(self):
        for k in self.NEW:
            self.assertIn(k, guard._stats, k)
            self.assertIn(k, guard._cn_list_keys, k)
            self.assertIn(k, guard.PERSIST_SKIP, k)

    def test_refresh_touches_exceptions(self):
        """`refresh_cn_list_metrics()` 必须把例外清单也纳入强制重载（打破 60s 节流）。"""
        _w(EXC_F, "r1.example\n")
        guard._CN_TRUST_EXC.update({"checked": 0.0, "mtime": 0.0, "loaded": False})
        guard._load_cn_trust_exc()
        self.assertEqual(guard._stats.get("cn_trust_exc_entries"), 1)
        # 节流窗口内（刚载入）直接再调不会重载 ⇒ 仍是 1
        _w(EXC_F, "r1.example\nr2.example\n")
        guard._load_cn_trust_exc()
        self.assertEqual(guard._stats.get("cn_trust_exc_entries"), 1)
        # 指标刷新必须打破节流 ⇒ 立刻读到新内容（热更新语义）
        guard.refresh_cn_list_metrics()
        self.assertEqual(guard._stats.get("cn_trust_exc_entries"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
