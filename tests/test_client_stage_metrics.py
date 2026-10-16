"""Bounded, client-only A/AAAA timing histogram tests."""
import atexit
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

RELEASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RELEASE_DIR)
_TMP = tempfile.mkdtemp(prefix="client-stage-metrics-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
atexit.register(shutil.rmtree, _TMP, True)
import guard


class ClientStageMetrics(unittest.TestCase):
    def setUp(self):
        self.old_bs = guard._BS
        self.old_sample = guard._BASE_SAMPLE
        self.old_hot_note = guard._hot_note
        guard._BS = {"c": {}, "h": {}, "unk": []}
        guard._BASE_SAMPLE = False
        guard._hot_note = lambda *_args: None

    def tearDown(self):
        guard._BS = self.old_bs
        guard._BASE_SAMPLE = self.old_sample
        guard._hot_note = self.old_hot_note
        guard._TR.t = None

    def finish(self, src_cls, qtype, attempts):
        guard._TR.t = {
            "id": 91, "done": False, "mono0": 1.0, "t0": 1.0,
            "qtype": qtype, "cn": True, "entry": "udp",
            "src_cls": src_cls, "src": "192.0.2.91",
            "name": "private-name-marker.invalid", "wait_ms": 7.0,
            "flags": [], "attempts": attempts,
        }
        with mock.patch.object(guard, "_tr_elapsed_ms", return_value=245.0):
            guard._tr_finish(b"\x00\x01\x81\x80", b"\x00\x01\x81\x80")
        return guard._bs_snapshot()

    @staticmethod
    def count(hist):
        return sum(hist)

    def test_client_a_and_aaaa_record_private_and_legacy_histograms(self):
        for qtype, suffix in ((1, "a"), (28, "aaaa")):
            with self.subTest(qtype=qtype):
                guard._BS = {"c": {}, "h": {}, "unk": []}
                snap = self.finish("client", qtype,
                                   [("a", 24.0, "ok"), ("domestic", 78.0, "ok")])
                self.assertEqual(self.count(snap["h"]["client_ms_" + suffix]), 1)
                self.assertEqual(self.count(snap["h"]["client_att_a_" + suffix]), 1)
                self.assertEqual(self.count(snap["h"]["client_att_domestic_" + suffix]), 1)
                self.assertEqual(self.count(snap["h"]["ms_" + suffix]), 1)
                self.assertEqual(self.count(snap["h"]["att_a"]), 1)
                encoded = json.dumps(snap, sort_keys=True)
                self.assertNotIn("private-name-marker", encoded)
                self.assertNotIn("192.0.2.91", encoded)

    def test_nonclient_and_non_address_queries_do_not_enter_client_histograms(self):
        for src_cls, qtype in (("host", 1), ("loopback", 28), ("probe", 1),
                               ("other", 28), ("client", 65)):
            with self.subTest(src_cls=src_cls, qtype=qtype):
                snap = self.finish(src_cls, qtype, [("a", 24.0, "ok")])
                self.assertFalse(any(k.startswith("client_") for k in snap["h"]))
                self.assertFalse(any(k.startswith("client_") for k in snap["c"]))

    def test_unknown_stage_cannot_create_a_dynamic_histogram_key(self):
        snap = self.finish("client", 1,
                           [("unexpected-stage-marker", 24.0, "ok")])
        self.assertNotIn("client_att_unexpected-stage-marker_a", snap["h"])
        self.assertEqual(self.count(snap["h"]["client_ms_a"]), 1)


if __name__ == "__main__":
    unittest.main()
