// Read-only smoke test for the two stock X100V 3.01 Ghidra programs.
// @category X100V

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class VerifyX100V301 extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String name = currentProgram.getName();
        long base;
        long size;
        long[] probes;
        if (name.equals("x100v-301-part6.bin")) {
            base = 0x00f21000L;
            size = 6304576L;
            probes = new long[] {0x0113d87cL, 0x0115119cL, 0x0115f9f4L,
                                 0x0115d530L, 0x0115d614L, 0x01168514L};
        } else if (name.equals("x100v-301-part7.bin")) {
            base = 0x01ba0000L;
            size = 8568832L;
            probes = new long[] {0x01f6b318L, 0x01ea05a0L,
                                 0x01ed3020L,
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
                                 0x01f8926cL, 0x01f894ccL};
        } else {
            throw new IllegalArgumentException("Unexpected program: " + name);
        }
        Address first = toAddr(base);
        Address last = toAddr(base + size - 1);
        MemoryBlock block = currentProgram.getMemory().getBlock(first);
        if (block == null || !block.isInitialized() ||
            !block.getStart().equals(first) || !block.getEnd().equals(last)) {
            throw new IllegalStateException("Memory map mismatch: " + name);
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler did not open " + name);
            }
            for (long probe : probes) {
                Function function = getFunctionAt(toAddr(probe));
                if (function == null) {
                    throw new IllegalStateException("Missing seeded function at " + Long.toHexString(probe));
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    throw new IllegalStateException("Decompile failed: " + result.getErrorMessage());
                }
                String c = result.getDecompiledFunction().getC();
                if (c == null || c.isEmpty()) {
                    throw new IllegalStateException("Empty decompilation: " + name);
                }
                println("VERIFIED " + name + " " + first + ".." + last +
                        " function=" + function.getName() + " c_chars=" + c.length());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
