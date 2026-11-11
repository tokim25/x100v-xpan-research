// Seed a few established ARM entrypoints in the two stock X100V 3.01 raw partitions.
// This is analysis metadata only; it never writes firmware bytes.
// @category X100V

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class SeedX100V301 extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String name = currentProgram.getName();
        long base;
        long size;
        long[] seeds;
        if (name.equals("x100v-301-part6.bin")) {
            base = 0x00f21000L;
            size = 6304576L;
            seeds = new long[] {0x0113d87cL, 0x0115119cL, 0x0115bdd4L,
                                0x0115c138L, 0x0115c758L,
                                0x0115d530L, 0x0115d614L, 0x0115d6b0L,
                                0x0115d780L, 0x0115f9f4L, 0x0115fabcL,
                                0x01168514L};
        } else if (name.equals("x100v-301-part7.bin")) {
            base = 0x01ba0000L;
            size = 8568832L;
            seeds = new long[] {0x01ea05a0L, 0x01ed3020L, 0x01ed6b78L,
                                0x01f035bcL,
                                0x01f05b88L, 0x01f05c08L,
                                0x01f05ff0L, 0x01f06614L,
                                0x01f070d0L,
                                0x01f07794L, 0x01f077d8L,
                                0x01f077f8L, 0x01f07820L,
                                0x01f07928L, 0x01f10a64L,
                                0x01f1482cL, 0x01f1cd08L,
                                0x01f14f10L, 0x01f242c8L,
                                0x01f250dcL, 0x01f253fcL,
                                0x01f262e8L,
                                0x01f25c74L, 0x01f284b0L,
                                0x01f27f68L, 0x01f28598L,
                                0x01f293b8L, 0x01f294a0L,
                                0x01f29578L,
                                0x01f29718L, 0x01f29734L,
                                0x01f2a134L, 0x01f2a1a4L,
                                0x01f2ad08L, 0x01f2e0d4L,
                                0x01f30694L,
                                0x01f4ab84L, 0x01f4ac74L, 0x01f6b318L,
                                0x01f88ec0L, 0x01f8926cL, 0x01f894ccL};
        } else {
            throw new IllegalArgumentException("Unexpected program: " + name);
        }

        Address first = toAddr(base);
        Address last = toAddr(base + size - 1);
        MemoryBlock block = currentProgram.getMemory().getBlock(first);
        if (block == null || !block.isInitialized() ||
            block.getStart().compareTo(first) != 0 ||
            block.getEnd().compareTo(last) != 0) {
            throw new IllegalStateException("Raw partition base/length mismatch for " + name);
        }
        println("Verified " + name + " at " + first + ".." + last);
        for (long value : seeds) {
            Address address = toAddr(value);
            if (!block.contains(address)) {
                throw new IllegalStateException("Seed outside partition: " + address);
            }
            disassemble(address);
            Function function = getFunctionAt(address);
            if (function == null) {
                function = createFunction(address, "x100v_" + Long.toHexString(value));
            }
            if (function == null) {
                throw new IllegalStateException("Could not seed function at " + address);
            }
            println("Seeded " + function.getName() + " at " + address);
        }
    }
}
