# -*- coding: utf-8 -*-
"""第三份审计 F4（veto 侧一致性）：guard 的否决名单快照回退顺序。

发布目录里的 `cn-veto.snapshot.txt` 在发布时固定；veto 名单随后演进（本轮 2167 →
25020 条）后，若 live 文件缺失而退回那份**条目更少**的旧快照，否决面会变窄 ⇒ 反而
扩大国内信任（与 F4 的方向要求相反）。因此快照顺序必须是：
    live 目录快照（refresh-cn-veto-ip.py 维护） → 发布目录快照
"""
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import guard  # noqa: E402


class VetoSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vetosnap-")
        self.live = os.path.join(self.tmp, "cn_veto.txt")          # 故意不创建
        self.live_snap = os.path.join(self.tmp, "cn-veto.snapshot.txt")
        self.rel_snap = os.path.join(self.tmp, "release-cn-veto.snapshot.txt")

    def _patch(self, live_snap=None, rel_snap=None):
        for path, content in ((self.live_snap, live_snap), (self.rel_snap, rel_snap)):
            if content is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                with io.open(path, "w", encoding="utf-8") as f:
                    f.write(content)
        state = {"set": set(), "mtime": 0.0, "checked": 0.0}
        return mock.patch.multiple(
            guard, create=True,
            _CN_VETO=state,
            CN_VETO_FILE=self.live,
            CN_VETO_SNAPSHOT=self.live_snap,
            CN_VETO_SNAPSHOT_REL=self.rel_snap,
            # typed 的「最后有效快照」同样钉到临时目录（避免读到生产快照）
            CN_TYPED_SNAPSHOT=os.path.join(self.tmp, "no-typed-snapshot.txt"))

    def test_live_snapshot_preferred(self):
        with self._patch("live-snap.example\n", "release-snap.example\n"):
            doms = guard._load_cn_veto()
            self.assertIn("live-snap.example", doms)
            self.assertNotIn("release-snap.example", doms)

    def test_release_snapshot_is_fallback(self):
        with self._patch(None, "release-snap.example\n"):
            doms = guard._load_cn_veto()
            self.assertIn("release-snap.example", doms)

    def test_live_snapshot_wins_even_when_release_exists(self):
        with self._patch("a.example\nb.example\n", "c.example\n"):
            doms = guard._load_cn_veto()
            self.assertEqual(doms, {"a.example", "b.example"})

    def test_both_absent_means_veto_none(self):
        with self._patch(None, None):
            self.assertIsNone(guard._load_cn_veto())
            # veto 不可用 ⇒ 一律否决 CN 信任（保守方向：不扩大国内信任）
            self.assertTrue(guard._in_cn_veto("anything.example"))
            self.assertFalse(guard.is_cn_domain("anything.example"))

    def test_snapshot_with_bare_label_is_rejected(self):
        with self._patch("barelabel\n", None):
            self.assertIsNone(guard._load_cn_veto())

    def test_snapshot_ignores_comment_lines(self):
        with self._patch("# header\n# snapshot x\nlive-snap.example\n", None):
            doms = guard._load_cn_veto()
            self.assertEqual(doms, {"live-snap.example"})


if __name__ == "__main__":
    unittest.main()
