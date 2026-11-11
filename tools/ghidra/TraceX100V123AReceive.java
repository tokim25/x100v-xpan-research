// Read-only focused decompilation of the conditional 0x123a receive path.
// @category X100V

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class TraceX100V123AReceive extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!currentProgram.getName().equals("x100v-301-part7.bin")) {
            throw new IllegalArgumentException("Expected stock secondary partition");
        }
        long[] addresses = {0x01f035bcL, 0x01f293b8L,
                            0x01f1cd08L, 0x01f27f68L,
                            0x01f30694L};
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler did not open program");
            }
            for (long value : addresses) {
                Function function = getFunctionAt(toAddr(value));
                if (function == null) {
                    throw new IllegalStateException("Missing seed at " + Long.toHexString(value));
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    throw new IllegalStateException("Decompile failed at " + Long.toHexString(value));
                }
                println("TRACE_FUNCTION " + function.getName() + " @" + toAddr(value));
                println(result.getDecompiledFunction().getC());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
