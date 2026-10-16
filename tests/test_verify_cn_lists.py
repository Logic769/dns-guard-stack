#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify-cn-lists.py 单测：MANIFEST 覆盖/哈希、内容约束、签名缺失、退出码。

脚本文件名带横线，用 importlib.util 从路径加载；模块级常量读环境变量 ⇒ 每个用例先设 env 再加载。
"""
import importlib.util
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "verify-cn-lists.py")


def load_module():
    spec = importlib.util.spec_from_file_location("verify_cn_lists", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


KEY_RULES = ["baidu.com cn", "qq.com cn", "taobao.com cn", "jd.com cn", "gov.cn cn"]


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix="cnvcl-")
        self.hist = os.path.join(self.td, "hist")
        os.makedirs(self.hist)
        self.veto = os.path.join(self.td, "cn_veto.txt")
        self.ipf = os.path.join(self.td, "cn_ip.txt")
        self.typed = os.path.join(self.td, "cn-domains-typed.txt")
        self.rules = os.path.join(self.td, "forwarding-rules.txt")
        self.manifest = os.path.join(self.hist, "MANIFEST.sha256")
        os.environ["REFRESH_HIST_DIR"] = self.hist
        os.environ["REFRESH_VETO_FILE"] = self.veto
        os.environ["REFRESH_CN_IP_FILE"] = self.ipf
        os.environ["REFRESH_TYPED_FILE"] = self.typed
        os.environ["REFRESH_RULES_FILE"] = self.rules
        self.mod = load_module()
        self.mod.VETO_MIN_ENTRIES = 3
        self.mod.IP_MIN_ENTRIES = 2
        self.mod.DOMAIN_MIN_ENTRIES = 2
        self.build()

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def _w(self, path, lines):
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def build(self, veto=None, ip=None, typed=None, rules=None, manifest=True, paths=None):
        self._w(self.veto, veto if veto is not None else
                ["# 来源: v2fly", "google.com", "youtube.com", "facebook.com"])
        self._w(self.ipf, ip if ip is not None else ["1.1.8.0/24", "223.255.252.0/23"])
        if typed is not False:
            self._w(self.typed, typed if typed is not None else
                    ["full:exact.example", "domain:dom.example", "suffix:sfx.example"])
        elif os.path.exists(self.typed):
            os.remove(self.typed)
        self._w(self.rules, rules if rules is not None else KEY_RULES)
        if manifest:
            self.write_manifest(paths)

    def write_manifest(self, paths=None):
        paths = paths or [self.veto, self.ipf, self.typed, self.rules]
        lines = ["%s  %s" % (self.mod.sha256_file(p), p) for p in paths]
        with io.open(self.manifest, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def run_eval(self, skip_sig=True):
        return self.mod.evaluate({"skip_signature": skip_sig})


class ManifestAndHash(Base):
    def test_all_good_passes(self):
        fails, warns, detail = self.run_eval()
        self.assertEqual(fails, [])
        self.assertEqual(detail["manifest_entries"], 4)
        self.assertEqual(detail["veto_entries"], 3)
        self.assertEqual(detail["ip_entries"], 2)
        self.assertEqual(detail["typed_total"], 3)
        self.assertEqual(detail["typed_kinds"], {"full": 1, "domain": 1, "suffix": 1})
        self.assertTrue(any("--no-signature" in w for w in warns))
        self.assertEqual(detail["signature"], "skipped")

    def test_missing_manifest_fails(self):
        os.remove(self.manifest)
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("MANIFEST 缺失" in f for f in fails))

    def test_hash_mismatch_detected(self):
        self.build(manifest=False)
        self.write_manifest()
        with io.open(self.veto, "a", encoding="utf-8") as f:
            f.write("extra.example\n")
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("哈希校验失败" in f and "cn_veto.txt" in f for f in fails))

    def test_manifest_must_cover_managed_files(self):
        self.build(manifest=False)
        self.write_manifest(paths=[self.veto])
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("未覆盖受管名单" in f and "cn_ip.txt" in f for f in fails))

    def test_parse_manifest_skips_comments_and_blank(self):
        with io.open(self.manifest, "a", encoding="utf-8") as f:
            f.write("\n# comment\n\n")
        entries = self.mod.parse_manifest(self.manifest)
        self.assertEqual(len(entries), 4)


class ContentGuards(Base):
    def test_veto_below_min_fails(self):
        self.build(veto=["# only", "google.com", "youtube.com"])
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("veto 条目" in f and "下限" in f for f in fails))

    def test_veto_containing_domestic_fails(self):
        self.build(veto=["google.com", "youtube.com", "facebook.com", "qq.com"])
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("veto 含国内关键域" in f and "qq.com" in f for f in fails))

    def test_ip_below_min_fails(self):
        self.build(ip=["1.1.8.0/24"])
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("cn_ip 条目" in f and "下限" in f for f in fails))

    def test_typed_absent_only_warns(self):
        self.build(typed=False, manifest=False)
        self.write_manifest(paths=[self.veto, self.ipf, self.rules])
        fails, warns, detail = self.run_eval()
        self.assertEqual(fails, [])
        self.assertTrue(any("typed 名单不存在" in w for w in warns))
        self.assertIsNone(detail["typed_total"])

    def test_typed_deleted_but_listed_in_manifest_fails(self):
        self.build(typed=False)        # MANIFEST 仍声明 typed 的哈希
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("哈希校验失败" in f and "cn-domains-typed.txt" in f for f in fails))

    def test_typed_too_small_fails(self):
        self.build(typed=["full:only.example"], manifest=False)
        self.write_manifest()
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("typed 名单条目" in f for f in fails))

    def test_rules_missing_key_cn_fails(self):
        self.build(rules=["baidu.com cn", "qq.com cn"], manifest=False)
        self.write_manifest()
        fails, _w, _d = self.run_eval()
        self.assertTrue(any("forwarding-rules 覆盖不足" in f and "taobao.com" in f for f in fails))

    def test_rules_accepts_space_separated_rows(self):
        self.build(rules=["baidu.com\tcn", "qq.com cn", "taobao.com cn",
                          "jd.com cn", "gov.cn cn"], manifest=False)
        self.write_manifest()
        fails, _w, d = self.run_eval()
        self.assertEqual(fails, [])
        self.assertEqual(d["rules_entries"], 5)


class SignatureAndMain(Base):
    def test_signature_required_by_default(self):
        fails, _w, detail = self.run_eval(skip_sig=False)
        self.assertTrue(any("签名校验未过" in f for f in fails))
        self.assertEqual(detail["signature"], "fail")

    def test_main_exit_zero_without_signature_check(self):
        self.assertEqual(self.mod.main(["--no-signature", "--quiet"]), 0)

    def test_main_exit_one_when_content_bad(self):
        self.build(veto=["google.com"])
        self.assertTrue(self.mod.main(["--no-signature", "--quiet"]) == 1)


if __name__ == "__main__":
    unittest.main()
