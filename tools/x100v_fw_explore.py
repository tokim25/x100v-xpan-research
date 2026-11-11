"""Read-only helpers for exploring the decoded X100V 3.01 partitions (static only).

Decodes the primary (6) and secondary (7) partitions and the raw overlay (9)
from the official update, caches them under out/fw-cache (git-ignored), and
offers disassembly, word reads, function starts, BL callers and constant
searches. Addresses are RAM addresses at each partition's load address.
Nothing here runs firmware or touches a camera.

    python -m tools.x100v_fw_explore --stock ~/Downloads/FPUPDATE.DAT dis 0x01dffc38 40
    python -m tools.x100v_fw_explore --stock ~/Downloads/FPUPDATE.DAT const 0x1a0002
    python -m tools.x100v_fw_explore --stock ~/Downloads/FPUPDATE.DAT callers 0x0112d96c
"""

from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

LOADS = {6: 0x00F21000, 7: 0x01BA0000, 9: 0x03720000}
CACHE = Path(os.environ.get("X100V_FW_CACHE", "out/fw-cache"))


def movw_imm(word: int) -> int:
    return ((word >> 4) & 0xF000) | (word & 0xFFF)


def mov_imm(word: int) -> int | None:
    """Value of `mov rd, #imm` (any condition), or None."""
    if (word & 0x0FEF0000) != 0x03A00000:
        return None
    rotate, imm = ((word >> 8) & 0xF) * 2, word & 0xFF
    return ((imm >> rotate) | (imm << (32 - rotate))) & 0xFFFFFFFF if rotate else imm


def branch_target(word: int, address: int) -> int | None:
    """Target of an ARM B/BL at `address` (condition not 0xF), or None."""
    if (word & 0x0E000000) != 0x0A000000 or (word >> 28) == 0xF:
        return None
    offset = word & 0xFFFFFF
    if offset & 0x800000:
        offset -= 0x1000000
    return address + 8 + 4 * offset


class Firmware:
    def __init__(self, stock: Path):
        self.stock = stock
        self._parts: dict[int, bytes] = {}

    def part(self, number: int) -> bytes:
        if number not in self._parts:
            cached = CACHE / f"x100v-301-part{number}.bin"
            if not cached.exists():
                CACHE.mkdir(parents=True, exist_ok=True)
                if number == 9:
                    from tools.x100v_exif_buffer_emulator import load_overlay
                    cached.write_bytes(load_overlay(self.stock))
                else:
                    from tools.x100v_16x9_to_65x24 import stock_partitions
                    for key, data in stock_partitions(self.stock.read_bytes()).items():
                        (CACHE / f"x100v-301-part{key}.bin").write_bytes(data)
            self._parts[number] = cached.read_bytes()
        return self._parts[number]

    def locate(self, address: int) -> int:
        for number, load in LOADS.items():
            if load <= address < load + len(self.part(number)):
                return number
        raise ValueError(f"{address:#x} is outside the decoded partitions")

    def read(self, address: int, size: int) -> bytes:
        number = self.locate(address)
        data = self.part(number)[address - LOADS[number]:address - LOADS[number] + size]
        if len(data) != size:
            raise ValueError("read runs past the partition")
        return data

    def word(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def dis(self, address: int, count: int = 40) -> list[str]:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        lines = []
        for i in range(count):
            a = address + 4 * i
            insn = next(md.disasm(self.read(a, 4), a), None)
            lines.append(f"{a:08x}  {insn.mnemonic:8s} {insn.op_str}" if insn else f"{a:08x}  .word    {self.word(a):#010x}")
        return lines

    def func_start(self, address: int, limit: int = 8192) -> int | None:
        a = address & ~3
        for _ in range(limit // 4):
            w = self.word(a)
            if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
                return a
            a -= 4
        return None

    def words(self, number: int):
        data = self.part(number)
        return struct.unpack_from(f"<{len(data) // 4}I", data)

    def callers(self, target: int, parts=(6, 7)) -> list[int]:
        out = []
        for number in parts:
            for i, w in enumerate(self.words(number)):
                if (w & 0x0F000000) == 0x0B000000 and branch_target(w, LOADS[number] + 4 * i) == target:
                    out.append(LOADS[number] + 4 * i)
        return out

    def find_const(self, value: int, parts=(6, 7, 9)) -> list[tuple[int, str]]:
        """Literal-pool words, movw/movt pairs (same register) and mov immediates."""
        lo, hi = value & 0xFFFF, value >> 16
        out = []
        for number in parts:
            ws = self.words(number)
            for i, w in enumerate(ws):
                a = LOADS[number] + 4 * i
                if w == value:
                    out.append((a, "literal"))
                if mov_imm(w) == value:
                    out.append((a, "mov"))
                if (w & 0x0FF00000) == 0x03000000 and movw_imm(w) == lo:
                    rd = (w >> 12) & 0xF
                    for k in range(1, 8):
                        if i + k >= len(ws):
                            break
                        w2 = ws[i + k]
                        if (w2 & 0x0FF00000) == 0x03400000 and ((w2 >> 12) & 0xF) == rd and movw_imm(w2) == hi:
                            out.append((a, "movw/movt"))
                            break
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, default=Path.home() / "Downloads/FPUPDATE.DAT")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("dis")
    d.add_argument("address", type=lambda s: int(s, 0))
    d.add_argument("count", type=int, nargs="?", default=40)
    c = sub.add_parser("const")
    c.add_argument("value", type=lambda s: int(s, 0))
    b = sub.add_parser("callers")
    b.add_argument("address", type=lambda s: int(s, 0))
    args = parser.parse_args()
    fw = Firmware(args.stock)
    if args.command == "dis":
        print("\n".join(fw.dis(args.address, args.count)))
    elif args.command == "const":
        for a, kind in fw.find_const(args.value):
            start = fw.func_start(a) if fw.locate(a) != 9 else None
            print(f"{a:08x} {kind:10s} function {start or 0:#010x}")
    else:
        for a in fw.callers(args.address):
            print(f"{a:08x} in function {fw.func_start(a) or 0:#010x}")


if __name__ == "__main__":
    main()
