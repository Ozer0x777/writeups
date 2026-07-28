#!/usr/bin/env python3
"""
decompile_by_name.py : decompile une ou plusieurs fonctions Go identifiees par
leur nom de symbole complet (le binaire Go n'est pas strippe, les noms de
package/fonction sont dans la table de symboles COFF), et liste leurs appelants.

Usage : decompile_by_name.py SAMPLE.exe SORTIE.txt NOM1 [NOM2 ...]
"""
import sys
import pyghidra
pyghidra.start(install_dir="/opt/ghidra")

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    sample, outpath, names = sys.argv[1], sys.argv[2], sys.argv[3:]

    with pyghidra.open_program(sample, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        symtab = program.getSymbolTable()
        refmgr = program.getReferenceManager()

        out = open(outpath, "w")
        ifc = DecompInterface()
        ifc.openProgram(program)
        monitor = ConsoleTaskMonitor()

        for name in names:
            syms = [s for s in symtab.getSymbolIterator() if s.getName(True) == name or s.getName() == name]
            if not syms:
                out.write("\n=== %s : SYMBOLE INTROUVABLE ===\n" % name)
                continue
            for sym in syms:
                f = fm.getFunctionContaining(sym.getAddress())
                if f is None:
                    out.write("\n=== %s @ %s : pas dans une fonction ===\n" % (name, sym.getAddress()))
                    continue
                out.write("\n=== %s @ %s (taille %s) ===\n" % (f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses()))
                res = ifc.decompileFunction(f, 60, monitor)
                out.write(res.getDecompiledFunction().getC() if res.decompileCompleted() else "DECOMPILE FAILED\n")
                out.write("\n--- appelants de %s ---\n" % f.getName())
                for ref in refmgr.getReferencesTo(f.getEntryPoint()):
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    out.write("  from %s (func: %s)\n" % (ref.getFromAddress(), caller.getName() if caller else "NONE"))

        out.close()
        print("DONE, voir", outpath)


if __name__ == "__main__":
    main()
