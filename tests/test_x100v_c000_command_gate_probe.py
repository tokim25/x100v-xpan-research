"""Reference vectors for the command-gated external-record route."""

import unittest
from pathlib import Path

from tools.x100v_c000_command_gate_probe import verify


class C000CommandGateTest(unittest.TestCase):
    def test_command_and_pointer_slices(self):
        stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
        result = verify(stock)
        self.assertEqual(result["command_cases"], {
            "0xd183": "0x1d6a2e4",
            "0xd185": "0x1d6a2bc",
            "0xd187": "0x1d6a35c",
        })
        self.assertEqual(result["source_modes"], {
            "0x8097": "0xd181", "0x8098": "0xd185",
            "0x8099": "0xd187", "0x809a": "0xd189",
            "0x809b": "0x0",
        })
        self.assertEqual(result["pointer_slot"], "0x17385ec")
        self.assertEqual(result["synthetic_pointer_passed_to_wrapper"],
                         "0x33100000")
        self.assertFalse(result["ordinary_still_command_verified"])


if __name__ == "__main__":
    unittest.main()
