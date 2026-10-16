# -*- coding: utf-8 -*-
"""Regression: trusted CN B path still initializes the DNS question type."""
import atexit
import os
import shutil
import struct
import sys
import tempfile
import unittest

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="cn-trust-route-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
os.environ["GUARD_POLICY_MODE"] = "on"
atexit.register(shutil.rmtree, _TMP, True)
sys.path.insert(0, RELEASE_DIR)
import guard

NAME = "www.qq.com"
QID = 0x4242


def mk_query(name=NAME, qtype=1):
    qname = b"".join(struct.pack("!B", len(x)) + x.encode("ascii")
                     for x in name.split(".")) + b"\x00"
    return (struct.pack("!HHHHHH", QID, 0x0100, 1, 0, 0, 0) + qname
            + struct.pack("!HH", qtype, 1))


class TrustedDomesticRoute(unittest.TestCase):
    def setUp(self):
        self.saved = {
            "primary": guard.CN_DOMESTIC_PRIMARY,
            "trust": guard.CN_DOMESTIC_TRUST_B,
            "exist": guard.CN_EXIST_MODE,
            "policy": guard.POLICY_MODE,
            "is_cn": guard.is_cn_domain,
            "zone_denied": guard._cn_zone_denied,
            "resolve_b": guard.resolve_cn_via_unbound_b,
            "policy_cn": guard._policy_cn_answer,
            "pol_label": guard._pol_label,
        }
        guard.CN_DOMESTIC_PRIMARY = True
        guard.CN_DOMESTIC_TRUST_B = True
        guard.CN_EXIST_MODE = "enforce"
        guard.POLICY_MODE = True
        guard.is_cn_domain = lambda name: True
        guard._cn_zone_denied = lambda name: False
        guard.resolve_cn_via_unbound_b = lambda *a, **k: b"trusted domestic answer"
        self.qtypes = []
        class Answer(object):
            wire = b"trusted domestic answer"
        def policy(name, qtype, *args, **kwargs):
            self.qtypes.append(qtype)
            return Answer()
        guard._policy_cn_answer = policy
        guard._pol_label = lambda answer: "POL"

    def tearDown(self):
        guard.CN_DOMESTIC_PRIMARY = self.saved["primary"]
        guard.CN_DOMESTIC_TRUST_B = self.saved["trust"]
        guard.CN_EXIST_MODE = self.saved["exist"]
        guard.POLICY_MODE = self.saved["policy"]
        guard.is_cn_domain = self.saved["is_cn"]
        guard._cn_zone_denied = self.saved["zone_denied"]
        guard.resolve_cn_via_unbound_b = self.saved["resolve_b"]
        guard._policy_cn_answer = self.saved["policy_cn"]
        guard._pol_label = self.saved["pol_label"]

    def test_trust_bypasses_witness_without_losing_qtype(self):
        result = guard.domestic(mk_query(qtype=28), skip_a=True,
                                name=NAME, qtype=28)
        self.assertEqual(self.qtypes, [28])
        self.assertEqual(result[0], b"trusted domestic answer")
        self.assertEqual(result[1], "POL")


if __name__ == "__main__":
    unittest.main()
