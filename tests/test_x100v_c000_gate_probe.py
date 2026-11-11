"""Independent expected vectors for the stock C000 writer gate."""

import unittest
from pathlib import Path

from tools.x100v_c000_gate_probe import verify


class C000GateProbeTest(unittest.TestCase):
    def test_original_arm_gate_truth_table(self):
        stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
        actual = verify(stock)["rows"]
        expected = [
            (0, 0, 2, 0, False),
            (0xEA, 0xEA, 1, 1, False),
            (0x186, 0x186, 1, 1, False),
            (0, 0xEA, 2, 0, True),
            (0x186, 0, 1, 1, False),
        ]
        self.assertEqual(
            [(r["builder_aec"], r["initializer_aec"],
              r["source_record_26d"], r["converted_record_1c"],
              r["initializer_enters_writer_block"]) for r in actual],
            expected,
        )


if __name__ == "__main__":
    unittest.main()
