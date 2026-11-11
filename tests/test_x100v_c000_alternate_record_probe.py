"""Reference vectors for the alternate-record selector and copied flag."""

import unittest
from pathlib import Path

from tools.x100v_c000_alternate_record_probe import SECOND, verify


class C000AlternateRecordTest(unittest.TestCase):
    def test_original_arm_selector_and_copy_boundary(self):
        stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
        rows = verify(stock)["rows"]
        self.assertEqual(
            [(r["record_field_201"], r["external_flag_26d"],
              r["selected_index"], r["selected_flag_26d"],
              r["converted_byte_1c"],
              r["initializer_enters_writer_block"]) for r in rows],
            [(1, 2, 0, 1, 1, False),
             (2, 1, 1, 1, 1, False),
             (2, 2, 1, 2, 0, True)],
        )
        self.assertIsNone(rows[0]["copy_call"])
        self.assertEqual(rows[2]["copy_call"], {
            "destination": SECOND, "source": 0x33100000, "length": 625,
        })
        self.assertEqual(0x26D + 4, 625)


if __name__ == "__main__":
    unittest.main()
