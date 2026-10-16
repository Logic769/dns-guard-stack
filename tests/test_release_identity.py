"""2026-10-15 审计 F5：双进程发布指纹 —— 纯离线回归（不碰生产状态、不联网）。

覆盖：
  · `release_compatible()` 的 ok / unverified / mismatch 三态与各字段判定顺序；
  · IPC meta 确实随身携带本进程指纹（`verifier_payload_identity()`）；
  · 状态字节 0x05（VERSION_MISMATCH）与其它状态映射互不冲突，未知字节仍回落 ERROR；
  · guard 侧收到 0x05 时**折叠为 ERROR**（走保守路径）+ 计数 + 不把载荷当答案 ✓；
  · verifier.py 源码级护栏：握手校验真的接在 run() 主路径上（防"测试过但没接线"）。
"""
import atexit
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="dns-release-identity-")
atexit.register(shutil.rmtree, TMP, True)
os.environ["GUARD_STATE_DIR"] = TMP
os.environ["GUARD_LOG"] = os.path.join(TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
import guard

NAME = "relcheck.example"
HAS_UNIX = hasattr(socket, "AF_UNIX")


def question(name=NAME, qt=1, qc=1, tid=123):
    return (struct.pack("!HHHHHH", tid, 0x100, 1, 0, 0, 0) +
            b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) +
            b"\0" + struct.pack("!HH", qt, qc))


def _recvn(c, n):
    d = b""
    while len(d) < n:
        x = c.recv(n - len(d))
        if not x:
            raise IOError("short")
        d += x
    return d


class CompatVerdicts(unittest.TestCase):
    def test_own_identity_is_ok(self):
        self.assertEqual(guard.release_compatible(guard.verifier_payload_identity()), "ok")

    def test_payload_carries_release_sha_proto(self):
        pl = guard.verifier_payload_identity()
        self.assertEqual(pl["rel"], guard._RELEASE_ID)
        self.assertEqual(pl["sha"], guard._GUARD_SHA256)
        self.assertEqual(pl["proto"], guard.VERIFIER_PROTO)
        self.assertEqual(len(pl["sha"]), 64)
        int(pl["sha"], 16)

    def test_sha_mismatch_is_rejected(self):
        pl = guard.verifier_payload_identity()
        pl["sha"] = "0" * 64
        self.assertEqual(guard.release_compatible(pl), "mismatch")

    def test_release_id_mismatch_is_rejected(self):
        # 这是审计 F5 的真实形态：同一发布家族的两个不同目录（两进程 cwd 不同）✓
        pl = guard.verifier_payload_identity()
        pl["rel"] = "20261012-client-stage-metrics-01"
        self.assertEqual(guard.release_compatible(pl), "mismatch")

    def test_proto_mismatch_is_rejected(self):
        pl = guard.verifier_payload_identity()
        pl["proto"] = guard.VERIFIER_PROTO + 1
        self.assertEqual(guard.release_compatible(pl), "mismatch")

    def test_missing_sha_is_unverified_not_ok(self):
        # 老 guard（无 sha 字段）⇒ 兼容放行，但必须**单独标记**，不能伪装成 ok ✓
        self.assertEqual(guard.release_compatible({"name": NAME}), "unverified")

    def test_non_dict_or_garbage_is_mismatch(self):
        for bad in (None, [], "x", 7):
            self.assertEqual(guard.release_compatible(bad), "mismatch")

    def test_bad_proto_type_is_mismatch(self):
        pl = guard.verifier_payload_identity()
        pl["proto"] = "not-a-number"
        self.assertEqual(guard.release_compatible(pl), "mismatch")


class StatusByteMap(unittest.TestCase):
    def test_version_mismatch_has_own_byte_and_roundtrips(self):
        self.assertEqual(guard._VSTATUS_BYTE[guard.CORROB_VERSION_MISMATCH], b"\x05")
        self.assertEqual(guard._VBYTE_STATUS[b"\x05"], guard.CORROB_VERSION_MISMATCH)

    def test_all_status_bytes_distinct(self):
        vals = list(guard._VSTATUS_BYTE.values())
        self.assertEqual(len(vals), len(set(vals)))

    def test_unknown_byte_falls_back_to_error(self):
        self.assertEqual(guard._VBYTE_STATUS.get(b"\x7f", guard.CORROB_ERROR), guard.CORROB_ERROR)


class GuardSideFold(unittest.TestCase):
    """真实 `_verifier_dot()` 打到一个"拒服务"的对端 ⇒ 必须折叠成 ERROR 且计数 ✓

    AF_UNIX 仅 POSIX ⇒ Windows 上跳过；本类在目标机（Linux/python3.6）上实跑 ✓。
    """

    def _serve(self, reply_byte, meta_box):
        d = tempfile.mkdtemp(prefix="vsock-", dir=TMP)
        p = os.path.join(d, "verifier.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(p)
        srv.listen(1)

        def _run():
            try:
                c, _ = srv.accept()
                try:
                    a, b = struct.unpack("!HH", _recvn(c, 4))
                    meta_box.append(_recvn(c, a).decode())
                    _recvn(c, b)
                    c.sendall(struct.pack("!H", 1) + reply_byte)
                finally:
                    c.close()
            finally:
                srv.close()

        threading.Thread(target=_run).start()
        return p

    @unittest.skipUnless(HAS_UNIX, "AF_UNIX 仅 POSIX 可用")
    def test_version_mismatch_is_folded_to_error_and_counted(self):
        box = []
        p = self._serve(b"\x05", box)
        before = guard._stats.get("verifier_release_mismatch", 0)
        with mock.patch.dict(os.environ, {"GUARD_VERIFIER_SOCKET": p}):
            st, resp = guard._verifier_dot(question(), NAME, 1, 0.5, False, "dot")
        self.assertEqual(st, guard.CORROB_ERROR)      # 折叠 ⇒ 上层走"没查成"的保守路径
        self.assertIsNone(resp)                       # 绝不把状态字节后的载荷当答案 ✗
        self.assertEqual(guard._stats.get("verifier_release_mismatch", 0), before + 1)

    @unittest.skipUnless(HAS_UNIX, "AF_UNIX 仅 POSIX 可用")
    def test_request_carries_identity_on_the_wire(self):
        import json
        box = []
        p = self._serve(b"\x04", box)
        with mock.patch.dict(os.environ, {"GUARD_VERIFIER_SOCKET": p}):
            guard._verifier_dot(question(), NAME, 1, 0.5, False, "corrob", pool="corrob")
        meta = json.loads(box[0])
        self.assertEqual(meta["sha"], guard._GUARD_SHA256)
        self.assertEqual(meta["rel"], guard._RELEASE_ID)
        self.assertEqual(meta["proto"], guard.VERIFIER_PROTO)
        self.assertEqual(guard.release_compatible(meta), "ok")

    @unittest.skipUnless(HAS_UNIX, "AF_UNIX 仅 POSIX 可用")
    def test_error_byte_still_error(self):
        box = []
        p = self._serve(b"\x04", box)
        before = guard._stats.get("verifier_release_mismatch", 0)
        with mock.patch.dict(os.environ, {"GUARD_VERIFIER_SOCKET": p}):
            st, resp = guard._verifier_dot(question(), NAME, 1, 0.5, False, "dot")
        self.assertEqual(st, guard.CORROB_ERROR)
        self.assertIsNone(resp)
        self.assertEqual(guard._stats.get("verifier_release_mismatch", 0), before)


class VerifierSourceGuard(unittest.TestCase):
    """源码级护栏：verifier 的握手校验必须真的在 run() 主路径上 ✓"""

    def test_verifier_wires_handshake_check(self):
        p = os.path.join(ROOT, "verifier.py")
        with open(p, "rb") as f:
            src = f.read().decode("utf-8")
        self.assertIn("guard.release_compatible(meta,_MY_SHA,_MY_REL,_MY_PROTO)", src)
        self.assertIn("_ST[guard.CORROB_VERSION_MISMATCH]", src)
        self.assertIn("_vs('v_release_mismatch')", src)
        # 拒服务必须发生在取槽/查询之前 ⇒ 校验行早于 sem.acquire 行 ✓
        self.assertLess(src.index("release_compatible(meta"),
                        src.index("if not sem.acquire(timeout=_bd)"))
        # meta 身份三件套要从**自身目录导入的 guard**取值（代表"我这份代码"）✓
        self.assertIn("_MY_SHA=getattr(guard,'_GUARD_SHA256'", src)


if __name__ == "__main__":
    unittest.main()
