"""2026-10-15 审计 F5 门禁（release_consistency.py）的纯函数回归 —— 全离线。

门禁是"发布错配"的唯一事后判据 ⇒ 它自己必须有测试：这里逐项验证它能拦住
release_id / sha / proto / cwd / current / 磁盘哈希 / 死 pid / 元数据不可读 这 8 类错配，
并验证"完全一致时必须放行"（避免把门禁做成永远 FAIL 的摆设）✓。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import release_consistency as rc

REL = "20261015-audit-fixes-01"
SHA = "a" * 64
CWD = "/opt/dnsguard/releases/" + REL
GPROC = (True, CWD, "/usr/bin/python3 /opt/dnsguard/current/guard.py")
VPROC = (True, CWD, "/usr/bin/python3 /opt/dnsguard/current/verifier.py")


def gmeta(**kw):
    d = {"release_id": REL, "guard_sha256": SHA, "verifier_proto": 2, "pid": 111}
    d.update(kw)
    return d


def vmeta(**kw):
    d = {"release_id": REL, "guard_sha256": SHA, "verifier_proto": 2, "pid": 222}
    d.update(kw)
    return d


class ConsistencyGate(unittest.TestCase):
    def _ev(self, gm=None, vm=None, gp=GPROC, vp=VPROC, cur=CWD, dsha=SHA, gage=10, vage=10):
        return rc.evaluate(gm if gm is not None else gmeta(),
                           vm if vm is not None else vmeta(),
                           gp, vp, cur, dsha, gage, vage)

    def test_all_consistent_passes(self):
        fails, warns = self._ev()
        self.assertEqual(fails, [])
        self.assertEqual(warns, [])

    def test_release_id_mismatch_detected(self):
        fails, _ = self._ev(vm=vmeta(release_id="20261012-client-stage-metrics-01"))
        self.assertTrue(any("release_id 不一致" in f for f in fails), fails)

    def test_sha_mismatch_detected(self):
        fails, _ = self._ev(vm=vmeta(guard_sha256="b" * 64))
        self.assertTrue(any("guard_sha256 不一致" in f for f in fails), fails)

    def test_proto_mismatch_detected(self):
        fails, _ = self._ev(vm=vmeta(verifier_proto=1))
        self.assertTrue(any("verifier_proto 不一致" in f for f in fails), fails)

    def test_proto_missing_on_old_meta_is_not_a_fail(self):
        # 旧发布（无 verifier_proto）不该被误判成错配 ⇒ 只在两侧都有值时比较 ✓
        fails, _ = self._ev(gm=gmeta(verifier_proto=None), vm=vmeta(verifier_proto=None))
        self.assertEqual(fails, [])

    def test_cwd_mismatch_detected(self):
        fails, _ = self._ev(vp=(True, "/opt/dnsguard/releases/other", VPROC[2]))
        self.assertTrue(any("两进程 cwd 不同" in f for f in fails), fails)

    def test_current_mismatch_detected(self):
        fails, _ = self._ev(cur="/opt/dnsguard/releases/other")
        self.assertTrue(any("与进程 cwd 不符" in f for f in fails), fails)

    def test_missing_current_detected(self):
        fails, _ = self._ev(cur=None)
        self.assertTrue(any("current 软链缺失" in f for f in fails), fails)

    def test_disk_sha_mismatch_detected(self):
        fails, _ = self._ev(dsha="c" * 64)
        self.assertTrue(any("≠ 元数据" in f for f in fails), fails)

    def test_dead_pids_detected(self):
        fails, _ = self._ev(gp=(False, None, ""), vp=(False, None, ""))
        self.assertTrue(any("guard pid" in f and "不存活" in f for f in fails), fails)
        self.assertTrue(any("verifier pid" in f and "不存活" in f for f in fails), fails)

    def test_unreadable_meta_detected(self):
        fails, _ = self._ev(gm={"__error__": "FileNotFoundError: x"})
        self.assertTrue(any("guard 元数据不可读" in f for f in fails), fails)

    def test_wrong_script_in_cmdline_detected(self):
        fails, _ = self._ev(gp=(True, CWD, "/usr/bin/python3 /opt/dnsguard/current/other.py"))
        self.assertTrue(any("命令行不像 guard.py" in f for f in fails), fails)

    def test_stale_warn_thresholds_differ_by_role(self):
        _, warns = self._ev(gage=300000, vage=10)
        self.assertEqual(warns, [])                      # guard 侧启动写一次 ⇒ 不 WARN
        _, warns = self._ev(gage=10, vage=3600)
        self.assertTrue(any("verifier 元数据已" in w for w in warns), warns)

    def test_empty_meta_fails_without_crash(self):
        # 空 meta ⇒ 无 pid ⇒ 必然报"不存活"；关键是不能抛异常 ✓
        fails, _ = self._ev(gm={}, vm={}, gp=(False, None, ""), vp=(False, None, ""))
        self.assertTrue(fails)


if __name__ == "__main__":
    unittest.main()
