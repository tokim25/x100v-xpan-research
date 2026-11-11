// Read-only targeted decompilation of the stock X100V C000 geometry writer.
// @category X100V

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class TraceX100VRawGeometry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!currentProgram.getName().equals("x100v-301-part7.bin")) {
            throw new IllegalArgumentException("Expected stock secondary partition");
        }
        Function function = getFunctionAt(toAddr(0x01ed6b78L));
        if (function == null) {
            throw new IllegalStateException("Missing seeded geometry writer");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler did not open program");
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompile failed: " + result.getErrorMessage());
            }
            println("TRACE_FUNCTION " + function.getName() + " @" + function.getEntryPoint());
            println(result.getDecompiledFunction().getC());
        } finally {
            decompiler.dispose();
        }
    }
}
