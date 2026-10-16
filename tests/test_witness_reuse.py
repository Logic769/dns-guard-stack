"""Regression tests for normalizing the CN W1 witness handoff."""
import atexit
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMP = tempfile.mkdtemp(prefix="witness-reuse-test-")
os.environ["GUARD_STATE_DIR"] = _TMP
os.environ["GUARD_LOG"] = os.path.join(_TMP, "guard.log")
atexit.register(shutil.rmtree, _TMP, True)
import guard


class WitnessHandoff(unittest.TestCase):
    def test_completed_veto_hint_is_reused(self):
        hint = guard._VetoHint({"rc": 0, "ips": ["101.159.106.167"],
                                "proof": None, "wire": b"answer"})
        box, thread = guard._witness_box(hint)
        self.assertIs(box.get("v"), hint)
        self.assertFalse(thread.is_alive())

    def test_completed_negative_hint_is_reused_as_negative_evidence(self):
        hint = guard._VetoHint({"rc": 3, "ips": [], "proof": "nsec3",
                                "wire": b"negative"})
        box, thread = guard._witness_box(hint)
        self.assertIs(box.get("v"), hint)
        self.assertFalse(thread.is_alive())

    def test_legacy_async_box_remains_async(self):
        hint = {"v": None, "t": None}
        box, thread = guard._witness_box(hint)
        self.assertIs(box, hint)
        self.assertIsNone(box.get("v"))
        self.assertFalse(thread.is_alive())

    def test_empty_or_missing_hint_is_pending(self):
        box, thread = guard._witness_box(None)
        self.assertIsNone(box.get("v"))
        self.assertFalse(thread.is_alive())

    def test_completed_hint_is_not_replaced_by_new_query(self):
        hint = guard._VetoHint({"rc": 0, "ips": ["101.159.106.167"],
                                "proof": None, "wire": b"answer"})
        box, thread = guard._witness_box(hint)
        self.assertIs(box.get("v"), hint)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
