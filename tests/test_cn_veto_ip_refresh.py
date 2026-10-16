#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_cn_veto_ip_refresh.py —— 离线测试 refresh-cn-veto-ip.py 的纯逻辑。

覆盖：
  VetoExpand        5 项：include 链展开到 depth 上限 / 上限放宽后完整展开 / 上限仍截断 / 跳过 keyword+regexp / 剥 @attr 与大小写
  CnConflictFilter  5 项：国内冲突剔除（国别后缀、父域命中、标签边界、本地名单读取、接线顺序）
  CidrParse         4 项：非法行丢弃 / 前缀下限 / 去重 / 地址总数
  FileGuard         3 项：写入门禁（条目下限、国内反例、幅度）在源码中的接线护栏
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.dirname(HERE)
SCRIPT = os.path.join(REL, "refresh-cn-veto-ip.py")


def load_script():
    os.environ.setdefault("REFRESH_VETO_FILE", os.path.join(tempfile.gettempdir(), "veto-fixture.txt"))
    os.environ.setdefault("REFRESH_CN_IP_FILE", os.path.join(tempfile.gettempdir(), "cnip-fixture.txt"))
    spec = importlib.util.spec_from_file_location("refresh_cn_veto_ip", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = load_script()


class VetoExpand(unittest.TestCase):
    DOCS = {
        "geolocation-!cn": (
            "include:foreign-a\ninclude:foreign-b\ninclude:chain0\n"
            "full:direct.example\n1inch.io\n"
            "keyword:kw.example\nregexp:^re\\.example$\n"
            "nodot\nUPPER.Example @cn\n"
        ),
        "foreign-a": "include:deep-c\na.example\nfull:b.example\n",
        "foreign-b": "c.example @attr\n",
        "deep-c": "include:deep-d\nd.example\n",
        "deep-d": "e.example\n",
    }

    @staticmethod
    def _chain(n):
        """生成 n 层 include 链（chain0 → … → chain{n-1}），每层带一个 lvl{i}.example。"""
        docs = {}
        for i in range(n):
            nxt = "include:chain%d\n" % (i + 1) if i + 1 < n else ""
            docs["chain%d" % i] = nxt + "lvl%d.example\n" % i
        return docs

    def test_include_chain_expands_to_depth_limit(self):
        docs = dict(self.DOCS)
        docs.update(self._chain(9))          # chain0..chain8；深度上限 8
        doms, nfiles, nskip = M.expand_veto(docs)
        for d in ("direct.example", "1inch.io", "upper.example",
                  "a.example", "b.example", "c.example", "d.example", "e.example"):
            self.assertIn(d, doms, d)
        self.assertIn("lvl0.example", doms)
        self.assertIn("lvl7.example", doms, "depth 8 以内的 include 必须展开（放宽后不再截断）")
        self.assertNotIn("lvl8.example", doms, "超出 depth 上限的链不得展开")
        self.assertEqual(nskip, 2, "keyword: 与 regexp: 应被计数并跳过")
        self.assertNotIn("kw.example", doms)
        self.assertNotIn("nodot", doms)
        self.assertTrue(all("(" not in d and "^" not in d for d in doms),
                        "正则条目不得进入域名集合")

    def test_file_cap_allows_full_expansion(self):
        docs = {"geolocation-!cn": "".join("include:f%d\n" % i for i in range(100))}
        for i in range(100):
            docs["f%d" % i] = "n%d.example\n" % i
        doms, nfiles, _ = M.expand_veto(docs)
        self.assertEqual(nfiles, 101, "未触顶时必须完整展开（文件上限已放宽）")
        for i in (0, 58, 59, 99):
            self.assertIn("n%d.example" % i, doms, "放宽后不得再截断 include")
        self.assertGreaterEqual(M.VETO_MAX_FILES, 2000, "文件上限不得回退")
        self.assertGreaterEqual(M.VETO_MAX_DEPTH, 8, "深度上限不得回退")
        self.assertGreaterEqual(M.VETO_MIN_ENTRIES, 12000, "条目下限须随覆盖放宽同步提高")

    def test_file_cap_still_truncates(self):
        docs = {"geolocation-!cn": "".join("include:f%d\n" % i for i in range(5))}
        for i in range(5):
            docs["f%d" % i] = "n%d.example\n" % i
        old = M.VETO_MAX_FILES
        try:
            M.VETO_MAX_FILES = 3
            _doms, nfiles, _ = M.expand_veto(docs)
        finally:
            M.VETO_MAX_FILES = old
        self.assertEqual(nfiles, 3, "达到上限仍必须停止展开")

    def test_attr_and_comment_stripping(self):
        docs = {"geolocation-!cn": ("x.example @cn\ninclude:q # trailing\n"
                                    "# whole-line comment\n\nbroken.example\n"),
                "q": "y.example # inline\n"}
        doms, _, _ = M.expand_veto(docs)
        self.assertEqual(doms, {"x.example", "y.example", "broken.example"})
        self.assertTrue(all(not d.startswith("#") for d in doms),
                        "整行注释不得变成条目")
        self.assertTrue(all(" " not in d for d in doms),
                        "@attr 与行尾注释必须在建集前剥掉")

    def test_missing_include_member_is_tolerated(self):
        docs = {"geolocation-!cn": "include:not-in-tar\nkeep.example\n"}
        doms, nfiles, _ = M.expand_veto(docs)
        self.assertEqual(doms, {"keep.example"})
        self.assertEqual(nfiles, 2)

    def test_seed_uses_geolocation_not_cn(self):
        self.assertEqual(M.VETO_SEED, "geolocation-!cn")


class CnConflictFilter(unittest.TestCase):
    """放宽展开后上游 !cn 与 cn 数据交叉 ⇒ 冲突条目按「国内优先」从 veto 剔除。

    这里钉住剔除判据与「剔除先于国内反例门禁」的接线顺序 —— 后者是放宽覆盖后
    不再误伤国内域名的关键保证。
    """

    def test_cn_like_tld_suffix(self):
        empty = set()
        self.assertTrue(M.is_cn_like("www.qq.cn", empty))
        self.assertTrue(M.is_cn_like("gov.cn", empty))
        self.assertTrue(M.is_cn_like("a.gov.cn", empty))
        self.assertFalse(M.is_cn_like("example.com", empty))
        self.assertFalse(M.is_cn_like("", empty))

    def test_cn_like_parent_in_set(self):
        cnset = set(["aliyun.com"])
        self.assertTrue(M.is_cn_like("aliyun.com", cnset))
        self.assertTrue(M.is_cn_like("ntp.aliyun.com", cnset))
        self.assertTrue(M.is_cn_like("ntp1.aliyun.com", cnset))
        self.assertFalse(M.is_cn_like("evilaliyun.com", cnset),
                         "标签边界：evilaliyun.com 不是 aliyun.com 的子域")
        self.assertFalse(M.is_cn_like("aliyun.com.evil.example", cnset))

    def test_cn_domain_set_reads_local_lists(self):
        d = tempfile.mkdtemp()
        typed = os.path.join(d, "typed.txt")
        rules = os.path.join(d, "rules.txt")
        with io.open(typed, "w", encoding="utf-8") as f:
            f.write("full:exact.example\ndomain:dom.example\nsuffix:sfx.example\n"
                    "nodot\nUPPER.Example @cn\n")
        with io.open(rules, "w", encoding="utf-8") as f:
            f.write("# 注释行\nplain.example\n")
        old_t, old_r = M.CN_LOCAL_TYPED, M.CN_LOCAL_RULES
        try:
            M.CN_LOCAL_TYPED, M.CN_LOCAL_RULES = typed, rules
            s = M.cn_domain_set()
        finally:
            M.CN_LOCAL_TYPED, M.CN_LOCAL_RULES = old_t, old_r
        for x in ("exact.example", "dom.example", "sfx.example", "upper.example", "plain.example"):
            self.assertIn(x, s, x)
        self.assertNotIn("nodot", s)

    def test_conflict_threshold_constant(self):
        self.assertGreater(M.VETO_CONFLICT_MAX_PCT, 0.0)
        self.assertLessEqual(M.VETO_CONFLICT_MAX_PCT, 100.0)
        self.assertTrue(M.CN_LOCAL_TYPED.endswith("cn-domains-typed.txt"))

    def test_conflict_filter_wired_before_gates(self):
        with io.open(SCRIPT, encoding="utf-8") as f:
            src = f.read()
        body = src[src.index("def main("):]
        self.assertIn("is_cn_like(d, cnset)", body)
        self.assertLess(body.index("is_cn_like(d, cnset)"),
                        body.index("VETO_MUST_ABSENT", body.index("is_cn_like(d, cnset)")),
                        "国内冲突剔除必须先于国内反例门禁")
        self.assertIn("VETO_CONFLICT_MAX_PCT", body)


class CidrParse(unittest.TestCase):
    TEXT = ("1.1.8.0/24\n# comment\n0.0.0.0/0\n10.0.0.0/7\n"
            "2.2.2.0/24\n2.2.2.0/24\n\nnot-a-cidr\n2001:db8::/32\n")

    def test_parse_and_filter(self):
        nets, dropped = M.parse_cidrs(self.TEXT)
        got = [str(n) for n in nets]
        self.assertEqual(got, ["1.1.8.0/24", "2.2.2.0/24"], "去重 + 丢弃超短前缀/非法行/IPv6")
        self.assertEqual(dropped, 4, "/0, /7, not-a-cidr, IPv6 各计一次")
        self.assertEqual(nets[0].num_addresses, 256)

    def test_addr_total(self):
        nets, _ = M.parse_cidrs("1.0.0.0/24\n1.0.1.0/24\n")
        self.assertEqual(M.addr_total(nets), 512)

    def test_min_prefix_constant(self):
        self.assertEqual(M.CN_IP_MIN_PREFIX, 8)

    def test_address_guard_threshold(self):
        self.assertEqual(M.CN_IP_MAX_CHANGE_PCT, 5.0)
        self.assertEqual(M.VETO_MAX_CHANGE_PCT, 5.0)


class FileGuard(unittest.TestCase):
    def setUp(self):
        with io.open(SCRIPT, encoding="utf-8") as f:
            self.src = f.read()

    def test_same_origin_source_first(self):
        self.assertLess(self.src.index("ispip.clang.cn/all_cn.txt"),
                        self.src.index("chnroutes2"),
                        "同源(clang.cn)必须排在备源之前")

    def test_must_absent_guard_present(self):
        for d in ("baidu.com", "qq.com", "gov.cn"):
            self.assertIn(d, self.src)

    def test_no_service_restart(self):
        for bad in ("systemctl", "restart", "docker"):
            self.assertNotIn(bad, self.src,
                             "本脚本不应重启任何服务（guard 按 mtime 热重载）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
