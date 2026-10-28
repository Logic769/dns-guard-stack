"""Regression tests for audit F1/F4/F6/F7; no production state or network."""
import atexit
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="dns-audit-fixes-")
atexit.register(shutil.rmtree, TMP, True)
os.environ["GUARD_STATE_DIR"] = TMP
os.environ["GUARD_LOG"] = os.path.join(TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
import guard
import alt_adapter as alt
from answer_policy import Verdict, Answer, finalize_answer, POLICY_VERSION

NAME = "audit.example"
def question(name=NAME, qt=1, qc=1, tid=123):
    return (struct.pack("!HHHHHH", tid, 0x100, 1, 0, 0, 0) +
            b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) +
            b"\0" + struct.pack("!HH", qt, qc))

def reply(ttl=300, rc=0, ad=False, name=NAME, qt=1, qc=1, tid=123, ede=None):
    q = question(name, qt, qc, tid)
    n = 1 if rc == 0 else 0
    r = struct.pack("!HHHHHH", tid, 0x8180 | rc | (32 if ad else 0), 1,n,0,int(ede is not None)) + q[12:]
    if n:
        r += b"\xc0\x0c" + struct.pack("!HHIH",qt,qc,ttl,4) + b"\xc0\0\x02\x01"
    if ede is not None:
        r += b"\0" + struct.pack("!HHIH",41,1232,0x8000,6) + struct.pack("!HHH",15,2,ede)
    return r

def ttl_of(w):
    return alt._parse_rrs(w)[2]["an"][0]["ttl"]

class CacheReplay(unittest.TestCase):
    def test_clean_cache_ages_wire(self):
        with mock.patch.object(guard,"_cache",{guard._c_key(NAME,1):(1300,reply())}), \
             mock.patch.object(guard.time,"time",return_value=1299), \
             mock.patch.object(guard,"_strict_any",return_value=False):
            self.assertLessEqual(ttl_of(guard._dot_query_once(question(),NAME,1)),1)

    def test_corrob_cache_ages_wire(self):
        with mock.patch.object(guard,"_corrob",{guard._c_key(NAME,1):(1300,reply(),("192.0.2.1",))}), \
             mock.patch.object(guard.time,"time",return_value=1299):
            self.assertLessEqual(ttl_of(guard.corrob_get(NAME,1)[0]),1)

    def test_negative_cache_ages_wire_before_finalizer(self):
        with mock.patch.object(guard,"_neg_cache",{guard._c_key(NAME,1):(1300,reply())}), \
             mock.patch.object(guard.time,"time",return_value=1299), \
             mock.patch.object(guard,"_strict_entry",return_value=None):
            self.assertLessEqual(ttl_of(guard.handle(question())),1)

    def test_expired_cache_not_served(self):
        with mock.patch.object(guard,"_corrob",{guard._c_key(NAME,1):(1300,reply(),())}), \
             mock.patch.object(guard.time,"time",return_value=1301):
            self.assertIsNone(guard.corrob_get(NAME,1))

class FailureSemantics(unittest.TestCase):
    def test_plain_servfail_is_transport_not_bogus(self):
        self.assertEqual(alt.classify_response(reply(rc=2),"local-a").verdict,Verdict.TRANSPORT)
        self.assertNotEqual(alt.classify_kind(reply(rc=2)),"bogus")
        self.assertNotEqual(alt.rrset_validity(reply(rc=2))[1]["kind"],"bogus")

    def test_ede_dnssec_bogus_is_terminal(self):
        good=alt.classify_response(reply(),"local-alt",ttl=300)
        for code in (6,7,8,9,10,11,12):
            bad=alt.classify_response(reply(rc=2,ede=code),"local-a")
            self.assertEqual(bad.verdict,Verdict.BOGUS)
            self.assertIsNone(finalize_answer(bad,good))
            self.assertIsNone(finalize_answer(good,bad))

    def test_transport_primary_can_use_validating_alt(self):
        good=alt.classify_response(reply(ad=True),"local-alt",ttl=300)
        with mock.patch.object(guard,"_alt_gate",return_value=True), \
             mock.patch.object(guard,"_src_once",return_value=True), \
             mock.patch.object(guard,"_adm_cache_get",return_value=None), \
             mock.patch.object(alt,"query_alt",return_value=good), \
             mock.patch.object(guard,"_retry_authenticated",return_value=None):
            guard._dl_begin()
            out=guard._finalize_return(reply(rc=2),"local-a",NAME,1,123,question())
            self.assertEqual(struct.unpack("!H",out[2:4])[0]&15,0)

    def test_alt_bogus_cannot_be_repaired_by_witness(self):
        bad=alt.classify_response(reply(rc=2,ede=6),"local-alt")
        good=alt.classify_response(reply(),"witness",ttl=300)
        with mock.patch.object(guard,"_alt_gate",return_value=True), \
             mock.patch.object(guard,"_src_once",return_value=True), \
             mock.patch.object(guard,"_adm_cache_get",return_value=None), \
             mock.patch.object(alt,"query_alt",return_value=bad), \
             mock.patch.object(guard,"_retry_authenticated",return_value=good):
            guard._dl_begin()
            out=guard._finalize_return(reply(rc=2),"local-a",NAME,1,123,question())
            self.assertEqual(struct.unpack("!H",out[2:4])[0]&15,2)

    def test_domestic_cannot_override_observed_bogus(self):
        with mock.patch.object(guard,"CN_DOMESTIC_PRIMARY",True), \
             mock.patch.object(guard,"CN_DOMESTIC_TRUST_B",True), \
             mock.patch.object(guard,"is_cn_domain",return_value=True), \
             mock.patch.object(guard,"_adm_cache_answer",return_value=None), \
             mock.patch.object(guard,"_cn_zone_denied",return_value=False), \
             mock.patch.object(guard,"suspicious",return_value=False), \
             mock.patch.object(guard,"_alt_gate",return_value=False), \
             mock.patch.object(guard,"_retry_authenticated",return_value=None):
            guard._dl_begin()
            a=guard._policy_cn_answer(NAME,1,reply(rc=2,ede=6),reply(),query_id=123)
            self.assertTrue(a is None or a.verdict==Verdict.BOGUS)

class ResponseBinding(unittest.TestCase):
    def test_question_identity_and_wire_shape(self):
        match=getattr(alt,"response_matches",None)
        self.assertIsNotNone(match,"shared response identity validator is required")
        self.assertTrue(match(question(),reply(name="AuDiT.ExAmPlE")))
        for bad in (reply(tid=124),reply(name="wrong.example"),reply(qt=28),reply(qc=3),
                    reply()[:2]+b"\x89\x80"+reply()[4:],
                    reply()[:2]+b"\x01\x80"+reply()[4:],
                    reply()[:-1],reply()+b"junk"):
            self.assertFalse(match(question(),bad))
        self.assertFalse(match(question(),reply().replace(b"\x05audit",b"\x06audi\xfft",1)))

    def test_udp_discards_wrong_sender_and_wrong_question(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server.bind(("127.0.0.1",0))
        addr=server.getsockname()
        def worker():
            q,peer=server.recvfrom(4096)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as other:
                other.sendto(reply(tid=999),peer)
            server.sendto(reply(name="wrong.example"),peer)
            server.sendto(reply(),peer)
        t=threading.Thread(target=worker);t.start()
        try:
            self.assertEqual(guard.udp_query(addr,question(),timeout=1),reply())
        finally:
            t.join(2);server.close()

    def test_witness_udp_uses_same_binding(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server.bind(("127.0.0.1",0))
        def worker():
            q,peer=server.recvfrom(4096)
            tid=struct.unpack("!H",q[:2])[0]
            server.sendto(reply(name="wrong.example",tid=tid),peer)
            server.sendto(reply(tid=tid),peer)
        t=threading.Thread(target=worker);t.start()
        try:
            got=guard._veto_udp(NAME,1,"%s:%d"%server.getsockname(),1)
            self.assertEqual(alt._parse_rrs(got["wire"])[1][0],NAME)
        finally:
            t.join(2);server.close()

class ColdRouting(unittest.TestCase):
    def test_missing_live_veto_uses_release_snapshot(self):
        snapshot=os.path.join(TMP,"veto-snapshot.txt")
        with open(snapshot,"w") as f:f.write("tiktokcdn.com\n")
        state={"set":set(),"mtime":0.0,"checked":0.0}
        # 需同时中和 typed 与例外清单：两者若落到真实环境文件（服务器上确实存在），
        # `www.qq.com` 会被 typed 的 domain 语义判成国内，掩盖本用例要验的 F4 行为。
        typed={"data":None,"mtime":0.0,"checked":0.0,"logged_fail":False}
        exc={"set":set(),"mtime":0.0,"checked":0.0,"loaded":False}
        with mock.patch.object(guard,"_CN_VETO",state), \
             mock.patch.object(guard,"_CN_TYPED",typed,create=True), \
             mock.patch.object(guard,"CN_TYPED_FILE",os.path.join(TMP,"no-typed"),create=True), \
             mock.patch.object(guard,"CN_TYPED_SNAPSHOT",os.path.join(TMP,"no-typed-snap"),create=True), \
             mock.patch.object(guard,"_CN_TRUST_EXC",exc,create=True), \
             mock.patch.object(guard,"CN_TRUST_EXC_FILE",os.path.join(TMP,"no-exc"),create=True), \
             mock.patch.object(guard,"CN_VETO_FILE",os.path.join(TMP,"absent")), \
             mock.patch.object(guard,"CN_VETO_SNAPSHOT",snapshot,create=True), \
             mock.patch.object(guard,"_load_cn_domains",return_value={"qq.com","tiktokcdn.com"}):
            self.assertFalse(guard.is_cn_domain("x.tiktokcdn.com"))
            # 第三份审计 F4：typed/快照都不可用时**不再**做宽匹配回退 ⇒ 合并名单不参与判定
            # （typed 可用时 `www.qq.com` 仍判国内，走的是 typed 的 domain 语义）。
            self.assertFalse(guard.is_cn_domain("www.qq.com"))

    def test_no_live_or_snapshot_never_expands_cn(self):
        state={"set":set(),"mtime":0.0,"checked":0.0}
        typed={"data":None,"mtime":0.0,"checked":0.0,"logged_fail":False}
        with mock.patch.object(guard,"_CN_VETO",state), \
             mock.patch.object(guard,"_CN_TYPED",typed,create=True), \
             mock.patch.object(guard,"CN_TYPED_FILE",os.path.join(TMP,"no-typed"),create=True), \
             mock.patch.object(guard,"CN_TYPED_SNAPSHOT",os.path.join(TMP,"no-typed-snap"),create=True), \
             mock.patch.object(guard,"CN_VETO_FILE",os.path.join(TMP,"absent")), \
             mock.patch.object(guard,"CN_VETO_SNAPSHOT",os.path.join(TMP,"also-absent"),create=True), \
             mock.patch.object(guard,"_load_cn_domains",return_value={"tiktokcdn.com"}):
            self.assertFalse(guard.is_cn_domain("x.tiktokcdn.com"))

if __name__=="__main__":
    unittest.main()
