"""Projects for games built with link-time code generation (/GL and /LTCG), such as many original Xbox games.

With /GL the compiler leaves intermediate code in its objects and the linker generates the machine code for the
whole program at once. It gives functions custom register conventions (`this` and arguments in EAX, ESI, EDI or EBX
instead of ECX and the stack, chosen from their callers) and inlines across source files, so a function's bytes
depend on the program around it, and a source file compiled on its own has nothing objdiff can compare.

An LTCG project builds a unit in harness mode (the template's tools/ltcg.py and tools/dll2coff.py): the unit's
source, a driver that calls its functions the way the original's call sites do, and stand-ins for what it uses from
elsewhere, all compiled with /GL and linked into a DLL with /LTCG; its functions are then cut out of the DLL into an
object laid out like the delinked original, and their references are checked for a one-to-one address mapping.
This module makes a project one: the template setting, the default flags and a driver skeleton per unit.

shortcut: nothing detects LTCG yet, so it's an explicit choice (`ltcg=True`, or DECOMP_XBOX_LTCG=1 for Xbox games).
Signs to detect it by: call sites that load EAX, ESI, EDI or EBX right before calling code that reads them before
writing them (and doesn't save them), and no ECX `this` in methods that clearly have one.
"""

from __future__ import annotations

import re
from pathlib import Path

# The Visual C++ 7.1 flags of an XDK release build with link-time code generation, less /GL (configure.py adds it to
# the units built in harness mode; the rest compile without it): /Ob1 is what a real LTCG game's matches needed, and
# NDEBUG keeps the asserts of release builds out.
XBOX_CL_FLAGS = ["/nologo", "/c", "/O2", "/Ob1", "/G6", "/GF", "/Gy", "/arch:SSE", "/W3", "/D_XBOX", "/DNDEBUG"]

DRIVER = """// Harness driver for src/auto/{unit}.cpp. This game was built with link-time code generation (/GL, /LTCG).
//
// Under /LTCG a function's code depends on its callers: the linker passes `this` and arguments in whatever registers
// suit them (EAX, ESI, EDI, EBX...) and inlines across files. So the unit is built with this driver and linked:
// - here, HarnessEntry calls the unit's functions the way the original's call sites do (what each register holds
//   just before the call, which arguments are constants, what the result is used for);
// - harness/{unit}.<name>.cpp hold stand-ins for what the unit calls or reads from the rest of the game, shaped
//   like the real ones (what they read and which registers they preserve); <name>.nogl.cpp compiles without /GL,
//   for middleware or XDK library code the game's link couldn't see into;
// - `// HARNESS-LINK: <flags>` on a line here adds linker flags (d3d8ltcg.lib, /d2:"-inlT56"...).
// The unit is built this way once HarnessEntry is defined (uncomment it); until then it compiles without /GL.
// Functions are found in the link's map by func_<address> in their names, or by an annotation before the
// definition: `// FUNCTION: 0x<address> [map symbol substring]`.
#include "common.h"

// extern "C" __declspec(dllexport) void HarnessEntry(void)
// {{
// }}
"""


def prepare(root: Path, units: list[str]) -> None:
    """Make the freshly written project an LTCG one: the template's LTCG setting and a driver skeleton per unit
    (units of the XDK's own library code, set aside, get none)."""
    cfg = root / "tools" / "configure.py"
    text, count = re.subn(r"^LTCG = False$", "LTCG = True", cfg.read_text(encoding="utf-8"), count=1, flags=re.M)
    if not count:
        raise RuntimeError("the template's configure.py has no LTCG setting")
    cfg.write_text(text, encoding="utf-8")
    harness = root / "harness"
    harness.mkdir(exist_ok=True)
    for unit in units:
        if unit.startswith("xdk_"):
            continue
        (harness / f"{unit}.drv.cpp").write_text(DRIVER.format(unit=unit), encoding="utf-8")
