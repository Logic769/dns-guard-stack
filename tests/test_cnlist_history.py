#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cnlist_history 单测：归档落盘、MANIFEST、保留期清理、签名（有 gpg 时）。

模块级常量在 import 时读环境变量 ⇒ 每个用例先设 env 再 reload。
"""
import glob
import gzip
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

hist = None


def _has_gpg():
    try:
        return subprocess.run(["gpg", "--version"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


class HistBase(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix="cnhist-")
        self.veto = os.path.join(self.td, "cn_veto.txt")
        self.ipf = os.path.join(self.td, "cn_ip.txt")
        self.rules = os.path.join(self.td, "forwarding-rules.txt")
        self.typed = os.path.join(self.td, "cn-domains-typed.txt")
        for p in (self.veto, self.ipf, self.rules, self.typed):
            with io.open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write("# header\nx.example\n")
        os.environ["REFRESH_HIST_DIR"] = os.path.join(self.td, "hist")
        os.environ["REFRESH_MANAGED_FILES"] = os.pathsep.join(
            [self.veto, self.ipf, self.rules, self.typed])
        os.environ["REFRESH_HIST_RETENTION_DAYS"] = "30"
        os.environ["REFRESH_LOG"] = os.path.join(self.td, "log.txt")
        global hist
        import cnlist_history
        hist = importlib.reload(cnlist_history)
        # Windows 绝对路径含驱动器冒号，env 解析不可靠 ⇒ 直接钉住受管文件列表
        hist.MANAGED = [self.veto, self.ipf, self.rules, self.typed]

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)


class RecordArchive(HistBase):
    def test_json_written_with_counts_and_sha(self):
        info = hist.record("veto", {"a.example", "b.example"}, {"b.example", "c.example"}, self.veto)
        self.assertEqual(info["list"], "veto")
        day = os.path.join(self.td, "hist", time.strftime("%Y%m%d"))
        jsons = glob.glob(os.path.join(day, "veto-*.json"))
        self.assertEqual(len(jsons), 1)
        doc = json.loads(io.open(jsons[0], encoding="utf-8").read())
        self.assertEqual(doc["old_count"], 2)
        self.assertEqual(doc["new_count"], 2)
        self.assertEqual(doc["added"], 1)
        self.assertEqual(doc["removed"], 1)
        self.assertEqual(doc["added_sample"], ["c.example"])
        self.assertEqual(doc["removed_sample"], ["a.example"])
        self.assertFalse(doc["unchanged"])
        self.assertEqual(doc["file_sha256"], hist.sha256_file(self.veto))
        self.assertEqual(doc["list"], "veto")

    def test_details_gzipped_with_content(self):
        hist.record("veto", {"a.example"}, {"b.example", "c.example"}, self.veto)
        day = os.path.join(self.td, "hist", time.strftime("%Y%m%d"))
        add = glob.glob(os.path.join(day, "veto-*.added.txt.gz"))
        rem = glob.glob(os.path.join(day, "veto-*.removed.txt.gz"))
        self.assertEqual(len(add), 1)
        self.assertEqual(len(rem), 1)
        with gzip.open(add[0], "rt", encoding="utf-8") as f:
            self.assertEqual(sorted(x.strip() for x in f if x.strip()), ["b.example", "c.example"])
        with gzip.open(rem[0], "rt", encoding="utf-8") as f:
            self.assertEqual([x.strip() for x in f if x.strip()], ["a.example"])

    def test_unchanged_flag_and_no_detail_files(self):
        info = hist.record("ipso", {"a.example"}, {"a.example"}, self.ipf)
        self.assertTrue(info["unchanged"])
        self.assertEqual(info["added"], 0)
        self.assertEqual(info["removed"], 0)
        day = os.path.join(self.td, "hist", time.strftime("%Y%m%d"))
        self.assertEqual(glob.glob(os.path.join(day, "ipso-*.added.txt.gz")), [])
        self.assertEqual(glob.glob(os.path.join(day, "ipso-*.removed.txt.gz")), [])

    def test_upstream_and_extra_merged(self):
        info = hist.record("veto", set(), {"a.example"}, self.veto,
                           upstream={"v2fly_commit": "abc", "pinned": True},
                           gate="force", extra={"conflict_dropped": 7})
        self.assertEqual(info["upstream"]["v2fly_commit"], "abc")
        self.assertEqual(info["gate"], "force")
        self.assertEqual(info["conflict_dropped"], 7)


class ManifestAndCleanup(HistBase):
    def test_manifest_covers_managed_and_archives(self):
        hist.record("veto", {"a.example"}, {"b.example"}, self.veto)
        mp, n = hist.update_manifest()
        self.assertTrue(os.path.exists(mp))
        txt = io.open(mp, encoding="utf-8").read()
        for p in (self.veto, self.ipf, self.rules, self.typed):
            self.assertIn(p, txt)
        self.assertIn(".json", txt)
        self.assertIn(".added.txt.gz", txt)
        self.assertGreaterEqual(n, 5)

    def test_manifest_hashes_match_disk(self):
        hist.record("veto", {"a.example"}, {"b.example"}, self.veto)
        mp, _n = hist.update_manifest()
        for line in io.open(mp, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            want, path = line.split("  ", 1)
            self.assertEqual(want, hist.sha256_file(path), "哈希不一致：%s" % path)

    def test_cleanup_removes_old_days_and_keeps_recent(self):
        hist.record("veto", {"a.example"}, {"b.example"}, self.veto)
        day = os.path.join(self.td, "hist", time.strftime("%Y%m%d"))
        old = os.path.join(self.td, "hist", "20200101")
        os.makedirs(old)
        with io.open(os.path.join(old, "veto-20200101-000000.json"), "w", encoding="utf-8") as f:
            f.write("{}\n")
        stale = time.time() - 400 * 86400      # cleanup 依据目录 mtime，需把老目录的 mtime 调旧
        os.utime(old, (stale, stale))
        removed = hist.cleanup(30)
        self.assertEqual(removed, 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(day))

    def test_cleanup_zero_keeps_everything(self):
        old = os.path.join(self.td, "hist", "20200101")
        os.makedirs(old)
        stale = time.time() - 400 * 86400
        os.utime(old, (stale, stale))
        self.assertEqual(hist.cleanup(0), 0)
        self.assertTrue(os.path.exists(old))

    def test_finalize_returns_summary(self):
        hist.record("veto", {"a.example"}, {"b.example"}, self.veto)
        out = hist.finalize(note="unit")
        self.assertIn("manifest", out)
        self.assertGreaterEqual(out["entries"], 5)
        self.assertEqual(out["cleaned"], 0)


class Signature(HistBase):
    @unittest.skipUnless(_has_gpg(), "本机无 gpg")
    def test_sign_manifest_produces_asc(self):
        hist.record("veto", {"a.example"}, {"b.example"}, self.veto)
        hist.update_manifest()
        asc = hist.sign_manifest()
        if asc is None:
            self.skipTest("密钥库无可用私钥（未生成签名密钥）")
        self.assertTrue(os.path.exists(asc))
        self.assertIn("BEGIN PGP SIGNATURE", io.open(asc, encoding="utf-8").read())

    def test_sign_manifest_without_manifest_returns_none(self):
        self.assertIsNone(hist.sign_manifest())


if __name__ == "__main__":
    unittest.main()
