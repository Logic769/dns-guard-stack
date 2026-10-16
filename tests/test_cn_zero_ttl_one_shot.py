# -*- coding: utf-8 -*-
"""Regression for a trusted domestic B negative that is valid but non-cacheable."""
import atexit
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="cn-zero-ttl-one-shot-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)
sys.path.insert(0, RELEASE_DIR)

import guard
import alt_adapter
import inspect
from answer_policy import Verdict

QID = 0x4242

def _name_wire(name):
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.rstrip(".").split(".")) + b"\x00"

def _opt(ede=None):
    options = b""
    if ede is not None:
        options = struct.pack("!HHH", 15, 2, int(ede))
    return b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, len(options)) + options

def _soa(name):
    data = _name_wire("ns." + name) + _name_wire("hostmaster." + name) + struct.pack("!IIIII", 1, 3600, 600, 604800, 30)
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 0, len(data)) + data

def response(name, qtype=1, rcode=3, authority=False, ede=None, question_name=None):
    qname = question_name or name
    flags = 0x8180 | (rcode & 0xF)
    body = _name_wire(qname) + struct.pack("!HH", qtype, 1)
    ns = 0
    if authority:
        body += _soa(qname)
        ns = 1
    body += _opt(ede)
    return struct.pack("!HHHHHH", QID, flags, 1, 0, ns, 1) + body

def query(name, qtype=1):
    return struct.pack("!HHHHHH", QID, 0x0100, 1, 0, 0, 0) + _name_wire(name) + struct.pack("!HH", qtype, 1)

class TrustedCNZeroTTLNegative(unittest.TestCase):
    def setUp(self):
        self.saved = {}
        for key in ("CN_DOMESTIC_PRIMARY", "CN_DOMESTIC_TRUST_B", "CN_DOMESTIC_ZERO_TTL_ONESHOT",
                    "CN_EXIST_MODE", "POLICY_MODE", "is_cn_domain", "is_cn_trusted", "_cn_zone_denied",
                    "_alt_gate", "_retry_authenticated"):
            self.saved[key] = getattr(guard, key, None)
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        guard.CN_DOMESTIC_ZERO_TTL_ONESHOT = True
        guard.CN_EXIST_MODE = "enforce"
        guard.POLICY_MODE = True
        guard.is_cn_domain = lambda name: True
        guard.is_cn_trusted = lambda name: True
        guard._cn_zone_denied = lambda name: False
        guard._alt_gate = lambda: False
        guard._retry_authenticated = lambda *a, **k: None

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None and key == "CN_DOMESTIC_ZERO_TTL_ONESHOT":
                if hasattr(guard, key):
                    delattr(guard, key)
            else:
                setattr(guard, key, value)

    def _run(self, name, wire, one_shot=True, trust=True, is_cn=True):
        guard.CN_DOMESTIC_ZERO_TTL_ONESHOT = one_shot
        guard.CN_DOMESTIC_TRUST_B = trust
        guard.is_cn_domain = lambda q: is_cn
        guard.is_cn_trusted = lambda q: trust
        kwargs = {"deadline": time.time() + 1.0}
        if "query_id" in inspect.signature(guard._policy_cn_answer).parameters:
            kwargs["query_id"] = wire[:2]
        return guard._policy_cn_answer(name, 1, None, wire, **kwargs)

    def test_empty_zero_ttl_nxdomain_is_returned_once_without_cache(self):
        name = "cold-one-shot.qq.com"
        wire = response(name)
        ans = self._run(name, wire)
        self.assertIsNotNone(ans, "trusted CN B NXDOMAIN with no SOA must avoid the 1-2s authenticated retry")
        self.assertEqual(ans.source, "local-cn")
        self.assertEqual(ans.verdict, Verdict.ACCEPTED)
        self.assertLessEqual(ans.valid_until, time.time(), "one-shot return must not invent TTL")
        out = guard._finalize_return(ans.wire, "local-cn", name, 1, QID, query(name))
        self.assertEqual(struct.unpack("!H", out[:2])[0], QID)
        self.assertEqual(guard._adm_cache_get(name, 1), None, "zero-TTL answer must never enter admission cache")

    def test_stale_ede_is_not_returned(self):
        self.assertIsNone(self._run("stale.qq.com", response("stale.qq.com", ede=3)))

    def test_stale_nxdomain_ede_is_not_returned(self):
        self.assertIsNone(self._run("stale-nxdomain.qq.com", response("stale-nxdomain.qq.com", ede=19)))

    def test_nxdomain_with_soa_is_not_this_one_shot_case(self):
        self.assertIsNone(self._run("soa.qq.com", response("soa.qq.com", authority=True)))

    def test_noerror_empty_answer_is_not_returned(self):
        self.assertIsNone(self._run("nodata.qq.com", response("nodata.qq.com", rcode=0)))

    def test_bogus_servfail_is_not_returned(self):
        self.assertIsNone(self._run("bogus.qq.com", response("bogus.qq.com", rcode=2)))

    def test_mismatched_question_is_not_returned(self):
        self.assertIsNone(self._run("expected.qq.com", response("expected.qq.com", question_name="other.qq.com")))

    def test_feature_flag_off_preserves_current_retry_policy(self):
        self.assertIsNone(self._run("disabled.qq.com", response("disabled.qq.com"), one_shot=False))

    def test_untrusted_cn_b_is_not_returned(self):
        self.assertIsNone(self._run("untrusted.qq.com", response("untrusted.qq.com"), trust=False, is_cn=True))

    def test_foreign_b_is_not_returned_even_when_trust_switch_is_on(self):
        self.assertIsNone(self._run("foreign.example", response("foreign.example"), trust=True, is_cn=False))

class EmptyNegativeCandidateWire(unittest.TestCase):
    def _candidate(self, wire, name, qid=QID):
        fn = getattr(alt_adapter, "is_empty_nxdomain_one_shot_candidate", None)
        if not callable(fn):
            return False
        return bool(fn(wire, name, 1, query_id=struct.pack("!H", qid)))

    def test_exact_empty_nxdomain_matches_name_type_and_id(self):
        name = "wire-check.qq.com"
        self.assertTrue(self._candidate(response(name), name))

    def test_wrong_transaction_id_is_rejected(self):
        name = "wire-id.qq.com"
        self.assertFalse(self._candidate(response(name), name, qid=QID + 1))

    def test_stale_ede_is_rejected(self):
        name = "wire-stale.qq.com"
        self.assertFalse(self._candidate(response(name, ede=3), name))

    def test_stale_nxdomain_ede_is_rejected(self):
        name = "wire-stale-nxdomain.qq.com"
        self.assertFalse(self._candidate(response(name, ede=19), name))

    def test_mismatched_question_is_rejected(self):
        name = "wire-question.qq.com"
        self.assertFalse(self._candidate(response(name, question_name="wrong.qq.com"), name))

    def test_trailing_garbage_is_rejected(self):
        name = "wire-tail.qq.com"
        self.assertFalse(self._candidate(response(name) + b"\x00", name))

if __name__ == "__main__":
    unittest.main(verbosity=2)
