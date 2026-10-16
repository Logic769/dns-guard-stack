# -*- coding: utf-8 -*-
"""发布 10：N1（路由/信任后缀分离）、N2（按 qtype 判否定形态）、N3（见证来源标签）测试。

对应第四份报告《发布09修复验证与新增问题报告-20261015.md》第 5/6/7 节。
"""
import inspect
import io
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import guard  # noqa: E402


# ---------------- DNS 报文构造（N2 用） ----------------
def _nw(n):
    out = b""
    for lab in n.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def _rr(owner, rtype, rdata, ttl=300):
    return _nw(owner) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def _resp(qname, qtype, answers=(), rcode=0, ad=False):
    flags = 0x8000 | (0x0020 if ad else 0) | (rcode & 0xF)
    hdr = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    return hdr + _nw(qname) + struct.pack("!HH", qtype, 1) + b"".join(answers)


class _Pinned(unittest.TestCase):
    """把 CN 名单相关路径全部钉到临时目录（guard 模块只 import 一次）。"""

    def setUp(self):
        self.TMP = tempfile.mkdtemp(prefix="n1n2n3-")
        self.typed = os.path.join(self.TMP, "typed.txt")
        self.snap = os.path.join(self.TMP, "typed.snapshot.txt")
        self.doms = os.path.join(self.TMP, "rules.txt")
        self.veto = os.path.join(self.TMP, "veto.txt")
        self.vsnap = os.path.join(self.TMP, "veto.snapshot.txt")
        self.exc = os.path.join(self.TMP, "exc.txt")
        self.allow = os.path.join(self.TMP, "allow.txt")
        self.cnnets = os.path.join(self.TMP, "cn_ip.txt")
        io.open(self.typed, "w", encoding="utf-8", newline="\n").write(
            "\n".join([
                "domain:xn--3ds443g",          # .在线（通用 TLD，只应路由）
                "domain:xn--rhqv96g",          # .世界
                "domain:test.cn",
                "domain:shop-taobao.taobao",
                "domain:allow.example",
                "domain:exc.test.cn",
                "full:brand-only.test",
            ]) + "\n")
        io.open(self.veto, "w", encoding="utf-8", newline="\n").write(
            "# 空否决名单（保留一条永不命中的占位，避免被当成不可用）\nnever-match.invalid\n")
        io.open(self.vsnap, "w", encoding="utf-8", newline="\n").write(
            "# 快照占位\nnever-match.invalid\n")
        io.open(self.allow, "w", encoding="utf-8", newline="\n").write(
            "# 人工白名单\nallow.example\n")
        io.open(self.exc, "w", encoding="utf-8", newline="\n").write(
            "# 例外（最高优先）\nexc.test.cn\n")
        self._saved = {}
        for key, val in (("CN_TYPED_FILE", self.typed), ("CN_TYPED_SNAPSHOT", self.snap),
                         ("CN_DOMAINS_FILE", self.doms), ("CN_VETO_FILE", self.veto),
                         ("CN_VETO_SNAPSHOT", self.vsnap), ("CN_TRUST_EXC_FILE", self.exc),
                         ("CN_TRUST_ALLOW_FILE", self.allow), ("CN_FILE", self.cnnets)):
            self._saved[key] = getattr(guard, key)
            setattr(guard, key, val)
        self._saved["CN_URL"] = guard.CN_URL
        guard.CN_URL = "http://127.0.0.1:9/all_cn.txt"   # 任何误触下载都立刻失败
        self._reset()

    def tearDown(self):
        for key, val in self._saved.items():
            setattr(guard, key, val)
        self._reset()
        shutil.rmtree(self.TMP, ignore_errors=True)

    def _reset(self):
        guard._CN_TYPED.update({"data": None, "mtime": 0.0, "checked": 0.0})
        guard._CN_VETO.update({"set": None, "live": False, "used": "", "entries": 0,
                               "mtime": 0.0, "checked": 0.0, "fail": 0})
        guard._CN_TRUST_EXC.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
        guard._CN_TRUST_ALLOW.update({"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False})
        for k in ("cn_trust_class_exception", "cn_trust_class_suffix", "cn_trust_class_allow",
                  "cn_trust_class_witness", "cn_trust_class_mode_all", "cn_dom_exception"):
            guard._stats[k] = 0


class N1SuffixSplit(_Pinned):
    """N1：通用/中文 TLD 仍走国内路由，但不再自动免见证。"""

    def test_generic_tld_routed_but_not_trusted(self):
        for dom in ("rand.xn--3ds443g", "rand.xn--rhqv96g"):
            self.assertTrue(guard.is_cn_domain(dom), "%s 应仍判国内路由" % dom)
            self.assertFalse(guard.is_cn_trusted(dom), "%s 不应自动免见证" % dom)

    def test_country_suffix_still_trusted(self):
        self.assertTrue(guard.is_cn_domain("www.test.cn"))
        self.assertTrue(guard.is_cn_trusted("www.test.cn"))

    def test_brand_suffix_still_trusted(self):
        self.assertTrue(guard.is_cn_domain("shop.shop-taobao.taobao"))
        self.assertTrue(guard.is_cn_trusted("shop.shop-taobao.taobao"))

    def test_allowlist_still_trusted(self):
        self.assertTrue(guard.is_cn_domain("sub.allow.example"))
        self.assertTrue(guard.is_cn_trusted("sub.allow.example"))

    def test_exception_beats_everything(self):
        # 例外清单是最高优先：命中即「既不做国内信任、也不走国内路由」（F1 的既定实现）
        self.assertFalse(guard.is_cn_domain("sub.exc.test.cn"))
        self.assertFalse(guard.is_cn_trusted("sub.exc.test.cn"))

    def test_non_cn_route_is_never_trusted(self):
        self.assertFalse(guard.is_cn_domain("rand.brand-only.test"))
        self.assertFalse(guard.is_cn_trusted("rand.brand-only.test"))

    def test_trust_suffix_is_strict_subset_of_route_suffix(self):
        self.assertTrue(set(guard.CN_TRUST_SUFFIX).issubset(set(guard.CN_SUFFIX)),
                        "免见证后缀必须是路由后缀的子集")
        for puny in (".xn--3ds443g", ".xn--rhqv96g", ".xn--55qx5d", ".xn--io0a7i"):
            self.assertIn(puny, guard.CN_SUFFIX, "%s 应仍在路由后缀里" % puny)
            self.assertNotIn(puny, guard.CN_TRUST_SUFFIX, "%s 不应再免见证" % puny)


class N2QtypeAwareDenial(unittest.TestCase):
    """N2：非地址类型的正答案不得被判为否定。"""

    def test_txt_positive_with_ad_is_not_denial(self):
        wire = _resp("t.example", 16, [_rr("t.example", 16, b"\x02ok")], ad=True)
        self.assertIsNone(guard.denial_proof(wire, 16), "TXT 正答案不应被判否定")

    def test_mx_and_caa_positive_are_not_denial(self):
        mx = _resp("m.example", 15, [_rr("m.example", 15, struct.pack("!H", 10) + b"\x04mail\x00")], ad=True)
        caa = _resp("c.example", 257, [_rr("c.example", 257, b"\x00\x05issue")], ad=True)
        self.assertIsNone(guard.denial_proof(mx, 15))
        self.assertIsNone(guard.denial_proof(caa, 257))

    def test_a_positive_is_not_denial(self):
        wire = _resp("h.example", 1, [_rr("h.example", 1, b"\x01\x02\x03\x04")], ad=True)
        self.assertIsNone(guard.denial_proof(wire, 1))

    def test_type_mismatch_answer_is_not_denial(self):
        # 查询 AAAA，答案里只有 A ⇒ 仍是"有答案"，不能当否定
        wire = _resp("h6.example", 28, [_rr("h6.example", 1, b"\x01\x02\x03\x04")], ad=True)
        self.assertIsNone(guard.denial_proof(wire, 28))

    def test_cname_intermediate_is_not_denial(self):
        wire = _resp("w.example", 1, [_rr("w.example", 5, _nw("t.example"))], ad=True)
        self.assertIsNone(guard.denial_proof(wire, 1))

    def test_nxdomain_with_ad_is_denial(self):
        wire = _resp("gone.example", 16, [], rcode=3, ad=True)
        self.assertEqual(guard.denial_proof(wire, 16), "ad")

    def test_nodata_with_ad_is_denial(self):
        wire = _resp("nodata.example", 16, [], rcode=0, ad=True)
        self.assertEqual(guard.denial_proof(wire, 16), "ad")

    def test_qtype_inferred_from_question_when_omitted(self):
        # 不传 qtype 时从 question 段取：TXT 正答案仍不得判否定
        wire = _resp("t2.example", 16, [_rr("t2.example", 16, b"\x02ok")], ad=True)
        self.assertIsNone(guard.denial_proof(wire))


class N3WitnessLabel(unittest.TestCase):
    """N3：见证响应按其真实来源标注，不再冒充 local-a。"""

    def test_source_label_is_witness(self):
        src = inspect.getsource(guard._policy_cn_answer)
        self.assertIn('_alt_classify(_wc, "witness")', src)
        self.assertNotIn('_alt_classify(_wc, "local-a")', src)

    def test_witness_in_src_whitelist(self):
        self.assertIn("witness", guard._SRC_WHITELIST)

    def test_ad_declared_counter_exists(self):
        src = inspect.getsource(guard._policy_cn_answer)
        self.assertIn("cn_witness_secure_ad_declared", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
