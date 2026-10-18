// decompdecomp: lay out a program Ghidra has no loader for (an original Xbox XBE), before its analysis. The program
// was imported as one flat image at its base address (every section's bytes at its address); this script, run by
// analyzeHeadless as a pre-script, cuts that block into the program's sections (name, executable or not) and adds
// the entry points the analysis starts from. Its argument is a text file of lines:
//   block <name> <start> <end> <x|rw>    (addresses in hex, end not included)
//   entry <address>                      (the program's entry point, or a function start found by decompdecomp)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class DecompWtfLayout extends GhidraScript {
    private Address at(String hex) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(hex, 16));
    }

    private void block(Memory mem, String name, Address start, Address end, boolean exec) throws Exception {
        MemoryBlock b = mem.getBlock(start);
        if (b == null) return;
        if (b.getStart().compareTo(start) < 0) {
            mem.split(b, start);
            b = mem.getBlock(start);
        }
        if (b.getEnd().compareTo(end) >= 0 && end.compareTo(b.getStart()) > 0) {
            mem.split(b, end);
            b = mem.getBlock(start);
        }
        b.setName(name);
        b.setExecute(exec);
        b.setWrite(!exec);
        b.setRead(true);
    }

    @Override
    public void run() throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(getScriptArgs()[0]), StandardCharsets.UTF_8);
        Memory mem = currentProgram.getMemory();
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (String line : lines) {
            String[] f = line.trim().split("\\s+");
            try {
                if (f[0].equals("block") && f.length == 5) {
                    block(mem, f[1], at(f[2]), at(f[3]), f[4].equals("x"));
                } else if (f[0].equals("entry") && f.length == 2) {
                    symbols.addExternalEntryPoint(at(f[1]));
                }
            } catch (Exception e) {
                println("decompdecomp: skipped `" + line + "`: " + e.getMessage());
            }
        }
    }
}
