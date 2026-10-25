# -*- coding: utf-8 -*-
"""test_cn_domestic.py —— §6 第 113/114 行「国内认证加密出口晋升为 CN 主源」的专项回归 ✓。

背景（§6 现场定位，证据见 `/root/dns-s6-witness-check.json`、`dns-s6-dot-compare.json`）：
  现象：生产对国内高频域名**系统性**返回海外 CDN 边缘（家庭出口实测 TTFB：
        sina 469ms、taobao 328.5ms、163 203ms、alicdn 359.5ms，而国内视图 31~70ms）
        —— 因为 `_policy_cn_answer()` 的 B 恒被 `alt_adapter.classify_response()`
        的 `local-b` 特判拦成 UNKNOWN（结构性"只当见证"），于是快路永远采用 A/见证
        （`GUARD_CN_VETO_WITNESS=127.0.0.1:5533` = NextDNS，**与 A 同源**）⇒ 自证 ⇒ 国内答案被永久排除 ✗。

本文件钉住的**唯一逻辑项**（开关默认关 ⇒ 不设 = 与 release-14 行为逐字节相同 ✓）：
  `GUARD_CN_DOMESTIC_PRIMARY=1` 时，CN 名下把 `unbound-B`（360 `dot.360.cn` DoT + 本机
  DNSSEC 校验）**按与 A/alt 完全相同的门槛**纳入裁决 ✓：
    · `ad=1` ⇒ SECURE ✓（方案 113 行的"国内认证加密出口 → 本地 DNSSEC 验证"）；
    · 未签名 positive ⇒ ACCEPTED（≤300s ✓，方案 114 行的"批准运营方策略接受的认证路径"）；
    · `rcode=2` ⇒ BOGUS ⇒ `is_fresh()` 恒 False ⇒ **不采纳** ⇒ 回退既有 A/alt ✓
      （**不新增 fail-closed**：国内出口不可达 ≠ 安全结论 ✓）；
    · 裸空壳（§5 的 `bare`）⇒ UNKNOWN ⇒ 不采纳 ✓（脏字节窗口不能借 CN 路径漏出 ✓）；
    · 非 CN 名 ⇒ 完全不碰 ✗（不做全局白名单 ✓，对齐方案 115 行）。
  来源标签：`_LABEL_MAP["CNB"] = "local-cn"` ⇒ 出口闸门按**真实来源**分类 ✓
  （审计里"国内 vs 海外"可分 ✓，不再借 `local-alt` ✗）。

**状态隔离**：本文件在 `import guard` **之前**把 `GUARD_STATE_DIR` / `GUARD_LOG` 指到
`tempfile.mkdtemp()` ✓ —— 绝不触碰 `/opt/dnsguard` 等生产目录 ✓。不触网 ✓
（`alt_adapter.query_alt` 与 `guard._retry_authenticated` 在用例内被替换为桩 ✓）。

运行（与发布约定一致）：
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
"""
import atexit
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RELEASE_DIR)

# ⚠️ 必须在 import guard 之前：生产状态目录 / 日志全部隔离到临时目录 ✓
_TMP = tempfile.mkdtemp(prefix="cn-domestic-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)

import alt_adapter                                        # noqa: E402
import guard                                              # noqa: E402
from answer_policy import Verdict, is_fresh               # noqa: E402

guard.STATE_DIR = _TMP
guard.LOG = os.environ["GUARD_LOG"]
guard.POLICY_MODE = True

CN_NAME = "www.qq.com"
QID = 0x4242


# ---------------------------------------------------------------- 报文工具
def mk_query(name=CN_NAME, qtype=1, qid=QID):
    q = b"".join(struct.pack("!B", len(l)) + l.encode()
                 for l in name.split(".") if l) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def wire_pos(name=CN_NAME, qtype=1, ttl=300, ad=False, qid=QID, rdata=b"\x65\x9f\x6a\xa7",
             sig=None, now=None):
    """未签名 CN 名的正地址应答（`ad=False` ⇒ ACCEPTED 档 ✓）。

    `sig` ∈ None / "valid" / "expired"（2026-10-16 N3 精细分档）：
    第三方通道（`local-cn` / `witness`）只有带**覆盖 qtype 的 RRSIG** 才保住 SECURE ✓。
    """
    now = float(now if now is not None else time.time())
    flags = 0x8180 | (0x20 if ad else 0)
    q = b"".join(struct.pack("!B", len(l)) + l.encode()
                 for l in name.split(".") if l) + b"\x00"
    body = q + struct.pack("!HH", qtype, 1)
    body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    an = 1
    if sig:
        exp = int(now + 3600) if sig == "valid" else int(now - 3600)
        rd = (struct.pack("!H", qtype) + bytes([8, 2]) + struct.pack("!I", ttl) +
              struct.pack("!I", exp) + struct.pack("!I", int(now - 86400)) +
              struct.pack("!H", 12345) + b"\xab" * 8)
        body += b"\xc0\x0c" + struct.pack("!HHIH", 46, 1, ttl, len(rd)) + rd
        an = 2
    return struct.pack("!HHHHHH", qid, flags, 1, an, 0, 0) + body


def wire_bare(name=CN_NAME, qtype=1, qid=QID):
    """§5 现场坏例的逐字节形状：零证据空壳 `rc=0 an=0 ns=0 ar=1`（46 字节）✓"""
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 1)
    q = b"".join(struct.pack("!B", len(l)) + l.encode()
                 for l in name.split(".") if l) + b"\x00"
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return hdr + q + struct.pack("!HH", qtype, 1) + opt


def wire_servfail(name=CN_NAME, qtype=1, qid=QID):
    """国内出口的 SERVFAIL（`rc=2`）—— 现场与裸空壳同形，仅 flags 差 1 位 ✓"""
    hdr = struct.pack("!HHHHHH", qid, 0x8182, 1, 0, 0, 1)
    q = b"".join(struct.pack("!B", len(l)) + l.encode()
                 for l in name.split(".") if l) + b"\x00"
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return hdr + q + struct.pack("!HH", qtype, 1) + opt


def _ans(source, wire):
    """与 `guard._alt_classify()` 同口径：**TTL 取自报文本身** ✓（绝不硬编码 ✗）。"""
    ttl, _det = alt_adapter.rrset_validity(wire, now=time.time())
    return alt_adapter.classify_response(wire, source, ttl=float(ttl), now=time.time())


# ---------------------------------------------------------------- ① 结构性门槛
class PromotionSemantics(unittest.TestCase):
    """同一条字节：`local-b` 恒 UNKNOWN（旧址）vs `local-cn` 可采纳（§6 新址）✓。"""

    def test_b_stays_witness_only(self):
        self.assertEqual(_ans("local-b", wire_pos()).verdict, Verdict.UNKNOWN,
                         "B 作为 local-b 必须恒 UNKNOWN（只当见证 ✓）")
        self.assertEqual(_ans("local-b", wire_pos(ad=True)).verdict, Verdict.UNKNOWN,
                         "local-b 特判优先于 AD 位（结构性 ✓）")

    def test_domestic_unsigned_is_accepted(self):
        a = _ans("local-cn", wire_pos())
        self.assertEqual(a.verdict, Verdict.ACCEPTED, "未签名 CN 正地址 ⇒ ACCEPTED ✓")
        self.assertEqual(a.source, "local-cn")
        self.assertTrue(is_fresh(a, time.time()), "ACCEPTED 必须有有效期（≤300s ✓）")

    def test_domestic_ad_without_signature_is_accepted(self):
        """★ 2026-10-16 N3 精细分档：`local-cn` 是**第三方通道** ⇒ AD 位只是运营方声明，
        报文里没有任何签名时不得判 SECURE（旧行为"AD=1 一律 SECURE"已废止 ✓）。"""
        a = _ans("local-cn", wire_pos(ad=True))
        self.assertEqual(a.verdict, Verdict.ACCEPTED, "AD=1 无签名 ⇒ ACCEPTED ✓")

    def test_domestic_ad_with_signature_is_secure(self):
        """带**覆盖被问类型且未过期**的 RRSIG ⇒ 有可核凭据 ⇒ SECURE ✓（国内源实测如此）。"""
        a = _ans("local-cn", wire_pos(ad=True, sig="valid"))
        self.assertEqual(a.verdict, Verdict.SECURE, "AD=1 + 有效 RRSIG ⇒ SECURE ✓")
        self.assertTrue(is_fresh(a, time.time()))

    def test_domestic_plain_servfail_is_transport_not_adopted(self):
        a = _ans("local-cn", wire_servfail())
        self.assertEqual(a.verdict, Verdict.TRANSPORT, "Bare rc=2 is not DNSSEC evidence")
        self.assertFalse(is_fresh(a, time.time()),
                         "BOGUS 恒不 fresh ⇒ 上层不采纳、回退既有 A/alt ✓（不新增 fail-closed ✓）")

    def test_domestic_bare_shell_is_unknown(self):
        a = _ans("local-cn", wire_bare())
        self.assertEqual(a.verdict, Verdict.UNKNOWN,
                         "零证据空壳 ⇒ UNKNOWN ⇒ 不采纳 ✓（§5 的 bare 门同样守住 CN 路径 ✓）")
        self.assertFalse(is_fresh(a, time.time()))

    def test_zero_ttl_not_extended(self):
        a = _ans("local-cn", wire_pos(ttl=0))
        self.assertFalse(is_fresh(a, time.time()), "TTL=0 ⇒ 不得延长、不得入缓存 ✓")


# ---------------------------------------------------------------- ② 单点裁决
class PolicySinglePoint(unittest.TestCase):
    """`_policy_cn_answer()` 是 4 条 CN 采用路径的**唯一**裁决点 ✓（改动只落在这里 ✓）。"""

    def setUp(self):
        self._flag0 = guard.CN_DOMESTIC_PRIMARY
        self._trust0 = guard.CN_DOMESTIC_TRUST_B
        self._cn0 = guard.is_cn_domain
        self._tr0 = guard.is_cn_trusted
        self._alt_q0 = alt_adapter.query_alt
        self._retry0 = guard._retry_authenticated
        self._gate0 = guard._alt_gate
        self._alt_once0 = guard._src_once
        self._veto0 = guard.cn_exist_veto
        guard.is_cn_domain = lambda n: True          # 只读生产 CN 清单不参与单测 ✓
        # 路由/信任拆分后：本类只验证「采纳路径」，故路由与信任都视为已批准 ✓
        guard.is_cn_trusted = lambda n: True
        guard.CN_DOMESTIC_TRUST_B = False
        alt_adapter.query_alt = lambda *a, **k: None  # 不触网 ✓
        guard._retry_authenticated = lambda *a, **k: None
        guard._alt_gate = lambda: False               # §4：未就绪 ⇒ 不进入长时间 alt 尝试 ✓
        guard._src_once = lambda *a, **k: False
        # 存在性见证：**默认"发过话且无否定"** ⇒ 允许采纳 ✓（真探测语义见 ④ 类 ✓）
        self.veto_ret = False
        self.veto_calls = []

        def _fake_veto(name, qtype, bresp, bips, deadline, w1_hint=None, deny_probe=False):
            self.veto_calls.append((name, qtype, deny_probe))
            return self.veto_ret

        guard.cn_exist_veto = _fake_veto
        guard._ADM_CACHE.clear()          # 用例间隔离：禁用准入缓存串味 ✓
        guard._stats.pop("cn_dom_accepted", None)

    def tearDown(self):
        guard.CN_DOMESTIC_PRIMARY = self._flag0
        guard.CN_DOMESTIC_TRUST_B = self._trust0
        guard.is_cn_domain = self._cn0
        guard.is_cn_trusted = self._tr0
        alt_adapter.query_alt = self._alt_q0
        guard._retry_authenticated = self._retry0
        guard._alt_gate = self._gate0
        guard._src_once = self._alt_once0
        guard.cn_exist_veto = self._veto0

    def _call(self, b_wire, name=CN_NAME, a_wire=None):
        return guard._policy_cn_answer(name, 1, a_wire, b_wire,
                                       deadline=time.time() + 3.0)

    def test_flag_off_keeps_legacy_behaviour(self):
        guard.CN_DOMESTIC_PRIMARY = False
        self.assertIsNone(self._call(wire_pos()),
                          "开关关 ⇒ B 仍不可采纳 ⇒ None（与 release-14 相同 ✓）")
        self.assertEqual(guard._stats.get("cn_dom_accepted", 0), 0,
                         "开关关时**不得**产生任何 cn_dom_* 记账 ✓（零行为变化 ✓）")

    def test_flag_on_adopts_domestic_unsigned(self):
        guard.CN_DOMESTIC_PRIMARY = True
        a = self._call(wire_pos())
        self.assertIsNotNone(a, "开关开 ⇒ 国内未签名正地址可采纳 ✓")
        self.assertEqual(a.source, "local-cn")
        self.assertEqual(a.verdict, Verdict.ACCEPTED)
        self.assertGreaterEqual(guard._stats.get("cn_dom_accepted", 0), 1)

    def test_flag_on_prefers_domestic_over_witness(self):
        """快路顺序：国内认证源**先于** A/见证 ⇒ 海外视图不再被默认采用 ✓（§6 的目的 ✓）。"""
        guard.CN_DOMESTIC_PRIMARY = True
        a = self._call(wire_pos(), a_wire=wire_pos(name="www.qq.com", ad=True, qid=0x77))
        self.assertEqual(a.source, "local-cn", "有可采纳国内答案时不得改采 A/见证 ✓")

    def test_flag_on_non_cn_untouched(self):
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        guard.is_cn_domain = lambda n: False
        self.assertIsNone(self._call(wire_pos(name="example.org")),
                          "非 CN 名 ⇒ 完全不走国内晋升 ✓（不做全局放行 ✓）")

    def test_flag_on_servfail_falls_through(self):
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        self.assertIsNone(self._call(wire_servfail()),
                          "国内出口 SERVFAIL ⇒ 不采纳、回退既有链路 ✓")
        self.assertGreaterEqual(guard._stats.get("cn_dom_transport", 0), 1)

    def test_flag_on_bare_falls_through(self):
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        self.assertIsNone(self._call(wire_bare()))
        self.assertGreaterEqual(guard._stats.get("cn_dom_unknown", 0), 1)

    def test_trusted_cn_bypasses_only_the_witness_wait(self):
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        self.veto_ret = True  # 若调用见证，本例会否决；信任模式必须不等待它
        ans = self._call(wire_pos())
        self.assertIsNotNone(ans)
        self.assertEqual(ans.source, "local-cn")
        self.assertEqual(self.veto_calls, [], "CN 信任模式不得发起见证等待")
        self.assertGreaterEqual(guard._stats.get("cn_dom_witness_bypass", 0), 1)

    # ---- release-16 双保险：采纳动作自身的守卫 ✓ ----
    def test_flag_on_zone_pinned_not_adopted(self):
        """被 pin 的 zone（B 侧已被判定不诚实）⇒ 绝不采纳国内源 ✓。"""
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        _z0 = guard._cn_zone_denied
        guard._cn_zone_denied = lambda n: True
        try:
            self.assertIsNone(self._call(wire_pos()),
                              "zone pin 命中 ⇒ 不采纳、回退 A/alt ✓")
            self.assertGreaterEqual(guard._stats.get("cn_dom_zone_pinned", 0), 1)
        finally:
            guard._cn_zone_denied = _z0

    def test_flag_on_suspicious_not_adopted(self):
        """B 给的地址命中已知投毒地址（R1 特征）⇒ 绝不采纳 ✓。"""
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        _s0 = guard.suspicious
        guard.suspicious = lambda ips, name: "R1 test-hit"
        try:
            self.assertIsNone(self._call(wire_pos()),
                              "suspicious 命中 ⇒ 不采纳、回退 A/alt ✓")
            self.assertGreaterEqual(guard._stats.get("cn_dom_suspicious", 0), 1)
        finally:
            guard.suspicious = _s0

    def test_flag_on_guard_exc_fails_closed(self):
        """守卫自身异常 ⇒ 保守拒绝 ✓（绝不误放行 ✗）。"""
        guard.CN_DOMESTIC_PRIMARY = True
        _z0 = guard._cn_zone_denied

        def _boom(n):
            raise RuntimeError("boom")

        guard._cn_zone_denied = _boom
        try:
            self.assertIsNone(self._call(wire_pos()), "守卫异常 ⇒ 不采纳 ✓")
            self.assertGreaterEqual(guard._stats.get("cn_dom_guard_exc", 0), 1)
        finally:
            guard._cn_zone_denied = _z0

    # ---- release-16：未签名国内答案的**存在性见证**要求（方案 114 行"多来源核对"）✓ ----
    def test_witness_deny_blocks_adoption(self):
        """见证否认该名字存在而 B 却给出地址 ⇒ **绝不采纳** ✓（release-15 的 canary 泄漏点 ✓）。"""
        guard.CN_DOMESTIC_PRIMARY = True
        self.veto_ret = True
        self.assertIsNone(self._call(wire_pos(), name="zz-canary-1.googlevideo.com"),
                          "见证否定存在 ⇒ 不采纳国内源、回落既有链路 ✓")
        self.assertGreaterEqual(guard._stats.get("cn_dom_witness_deny", 0), 1)
        self.assertTrue(self.veto_calls and self.veto_calls[-1][2] is True,
                        "必须以 `deny_probe=True` 调用见证 ✓（否则策略模式下会被跳过 ✗）")

    def test_witness_no_evidence_blocks_adoption(self):
        """见证**没发话**（超时/限流）⇒ 证据不足 ⇒ 不采纳 ✓（宁可少拿 geo，不多放一条 ✗）。"""
        guard.CN_DOMESTIC_PRIMARY = True
        self.veto_ret = None
        self.assertIsNone(self._call(wire_pos()), "无见证证据 ⇒ 不采纳 ✓")
        self.assertGreaterEqual(guard._stats.get("cn_dom_witness_nonev", 0), 1)

    def test_secure_answer_skips_witness(self):
        """带有效签名的答案（SECURE）⇒ 不需要存在性见证 ✓（不白花一次探测 ✓）。"""
        guard.CN_DOMESTIC_PRIMARY = True
        a = self._call(wire_pos(ad=True, sig="valid"))
        self.assertIsNotNone(a)
        self.assertEqual(a.verdict, Verdict.SECURE)
        self.assertEqual(self.veto_calls, [], "secure ⇒ 不得调用见证 ✓")

    def test_ad_declared_without_signature_is_not_secure(self):
        """★ N3 精细分档：AD=1 但无签名 ⇒ ACCEPTED ⇒ 不再享有"secure 免见证"待遇 ✓。"""
        guard.CN_DOMESTIC_PRIMARY = True
        a = self._call(wire_pos(ad=True))
        self.assertIsNotNone(a)
        self.assertNotEqual(a.verdict, Verdict.SECURE, "仅凭 AD 声明不得判 SECURE ✓")


# ---------------------------------------------------------------- ③ 标签与默认值
class LabelsAndDefault(unittest.TestCase):

    def test_default_is_off(self):
        self.assertFalse(guard.CN_DOMESTIC_PRIMARY,
                         "默认必须为**关** ⇒ 不设变量时零行为变化 ✓")
        self.assertFalse(guard.CN_DOMESTIC_TRUST_B,
                         "国内源信任扩展默认关闭 ✓")
        self.assertFalse(guard._flag("GUARD_CN_DOMESTIC_PRIMARY", False))

    def test_label_map_and_whitelist(self):
        self.assertEqual(guard._LABEL_MAP["CNB"], "local-cn")
        self.assertIn("local-cn", guard._SRC_WHITELIST,
                      "来源桶白名单必须登记 ✓（否则审计里被折进 other ✗）")
        self.assertEqual(guard._src_bucket("local-cn"), "local-cn")

    def test_pol_label(self):
        self.assertEqual(guard._pol_label(_ans("local-cn", wire_pos())), "CNB")
        self.assertEqual(guard._pol_label(_ans("local-alt", wire_pos(name="a.example"))), "POL")
        self.assertIsNone(guard._LABEL_MAP.get(None), "未登记键 ⇒ None（不出现在映射里）")
        self.assertEqual(guard._pol_label(None), "POL", "None ⇒ 沿用历史标签 ✓")

    def test_src_kind_cnb(self):
        self.assertEqual(guard._src_kind("CNB"), "local-cn",
                         "`domestic()` 的三元组出口必须能折算国内来源 ✓")


# ---------------------------------------------------------------- ④ 存在性探测（deny_probe）
class DenyProbeSemantics(unittest.TestCase):
    """release-15 首次打开开关时被 canary 抓到 `client_exposed=4` ✗ ⇒ release-16 的修正必须钉住 ✓。

    现场：`zz-canary-*.googlevideo.com` / `*.tiktokcdn*.com`（`cn_ip.txt` 判为 CN）在 B 侧得到
    **伪造正答案**（`rc=0 an=1`），而认证见证（unbound-a / NextDNS）对同名 `rc=3` ⇒
    未签名 ⇒ 被判 ACCEPTED 并下发到 AGH ✗。根因：采纳决策缺少"存在性见证"这一环 ✗。

    修正的**形状**（刻意最小化爆炸半径 ✓）：既有四个调用方（`deny_probe=False`）在策略模式下
    **照旧跳过** ⇒ 生产**不新增任何 fail-closed** ✓；只有 §6 的采纳决策用 `deny_probe=True`
    调一次探测，探测结果只决定"是否采纳国内源" ✓。
    """

    SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guard.py")

    def test_source_pins_gate_independent_of_flag(self):
        with open(self.SRC, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("if POLICY_MODE and not deny_probe:", src,
                      "闸门必须只由 `deny_probe` 打开 ✓")
        i = src.index("def cn_exist_veto(")
        j = src.index("\ndef ", i + 10)
        body = src[i:j]
        self.assertNotIn("CN_DOMESTIC_PRIMARY", body,
                         "`cn_exist_veto()` 的全局行为**不得**随 §6 开关变化 ✓（否则会新增 fail-closed ✗）")

    def test_policy_skip_regardless_of_flag(self):
        """`deny_probe=False` ⇒ 策略模式下**永远**跳过（开关开或关都一样 ✓）。"""
        n0 = guard._stats.get("veto_skipped_policy", 0)
        f0 = guard.CN_DOMESTIC_PRIMARY
        try:
            for _f in (False, True):
                guard.CN_DOMESTIC_PRIMARY = _f
                self.assertIsNone(guard.cn_exist_veto(
                    CN_NAME, 1, wire_pos(), ["101.159.106.167"], time.time() + 1.0))
            self.assertEqual(guard._stats.get("veto_skipped_policy", 0), n0 + 2,
                             "两个方向都必须走跳过 ✓")
        finally:
            guard.CN_DOMESTIC_PRIMARY = f0

    def test_probe_bypasses_policy_skip(self):
        c0 = guard._stats.get("cn_veto_checked", 0)
        n0 = guard._stats.get("veto_skipped_policy", 0)
        g0 = guard._cn_clean_get
        try:
            guard._cn_clean_get = lambda n: True      # 只验证"已越过跳过分支" ✓（不触网 ✓）
            # 2026-10-24 契约：清洁标记命中 ⇒ 该 zone 已被见证确认存在 ⇒ deny_probe 返回
            # **False（可采纳）**，而不是 None（无证据 ⇒ 否决）。旧断言 IsNone 对应旧契约。
            # 关键仍是"越过策略跳过"：cn_veto_checked 已 +1、veto_skipped_policy 未 +1 ✓。
            self.assertIs(guard.cn_exist_veto(
                CN_NAME, 1, wire_pos(), [], time.time() + 1.0, deny_probe=True), False)
            self.assertGreater(guard._stats.get("cn_veto_checked", 0), c0,
                               "`deny_probe=True` ⇒ 必须真正进入探测（不再跳过 ✓）")
            self.assertEqual(guard._stats.get("veto_skipped_policy", 0), n0,
                             "探测不得记策略跳过 ✓")
        finally:
            guard._cn_clean_get = g0

    def test_probe_true_on_witness_denial(self):
        """见证 rc=3 + DNSSEC 证明 ⇒ 探测返回 `True`（不采纳）✓，且**不写 pin、不 fail_closed** ✓。"""
        _u0, _w0 = guard._veto_udp, guard._veto_w2_targets
        _fc0 = guard._stats.get("fail_closed", 0)
        guard._veto_w2_targets = lambda: None
        # 2026-10-24 起清洁标记命中会让 deny_probe 直接返回 False（见 cn_exist_veto 的
        # # 2026-10-24 分支）⇒ 本用例必须先清掉同名 zone 的清洁标记，否则会按"已见证存在"
        # 早退、测不到见证否定这条路径（全量跑时会被其它用例写入的标记污染 ✗）。
        _z = CN_NAME.lower().rstrip(".")
        _cl0 = guard._CN_CLEAN.pop(_z, None)

        def _fake_udp(name, qtype, addr, to):
            return guard._VetoHint({"rc": 3, "ips": [], "proof": "nsec3", "wire": b"\x00",
                                    "src": "witness", "addr": addr, "qtype": qtype,
                                    "ok": True, "err": None})

        guard._veto_udp = _fake_udp
        try:
            self.assertIs(guard.cn_exist_veto(CN_NAME, 1, wire_pos(), [], time.time() + 1.0,
                                              deny_probe=True), True)
            self.assertEqual(guard._stats.get("fail_closed", 0), _fc0,
                             "探测**绝不** fail-closed ✓（客户端仍拿到原有链路的结果 ✓）")
            self.assertGreaterEqual(guard._stats.get("cn_dom_witness_deny", 0), 1)
        finally:
            guard._veto_udp, guard._veto_w2_targets = _u0, _w0
            if _cl0 is not None:
                guard._CN_CLEAN[_z] = _cl0

    def test_probe_false_when_witness_sees_name(self):
        """见证正向解析出地址 ⇒ `False`（不否认）⇒ 允许采纳 ✓。"""
        _u0, _w0 = guard._veto_udp, guard._veto_w2_targets
        guard._veto_w2_targets = lambda: None

        def _fake_udp(name, qtype, addr, to):
            return guard._VetoHint({"rc": 0, "ips": ["101.91.22.1"], "proof": None, "wire": b"\x00",
                                    "src": "witness", "addr": addr, "qtype": qtype,
                                    "ok": True, "err": None})

        guard._veto_udp = _fake_udp
        try:
            self.assertIs(guard.cn_exist_veto(CN_NAME, 1, wire_pos(), [], time.time() + 1.0,
                                              deny_probe=True), False)
            self.assertGreaterEqual(guard._stats.get("cn_dom_witness_ok", 0), 1)
        finally:
            guard._veto_udp, guard._veto_w2_targets = _u0, _w0


if __name__ == "__main__":
    unittest.main(verbosity=2)
