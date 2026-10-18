"""The original Xbox: x86 programs (XBE) built with Visual C++ from Microsoft's Xbox Development Kit (the XDK),
PROJECT mode. An Xbox game is a Windows-style program in Microsoft's own executable format, so it goes the PC
console's way (consoles/pc/): Ghidra finds the functions, each one is cut out of the program into a COFF object, and
objdiff judges what src/ compiles to.

- scratch.py: reads an XBE (or the default.xbe on a disc image) into the shape consoles/pc/scratch.py reads a
  Windows program into, so the PC path's analysis, source units and delinker take it unchanged.
- xboxkrnl.py: the kernel's exports by ordinal, so a `call [kernel thunk slot]` becomes an import as on Windows.
- xdvdfs.py: default.xbe out of a disc image (XISO, or a full Redump dump).

Its fixture is projects/demo-xbe, an XBE written byte by byte (no compiler, no Microsoft code) for tests/test_xbe.py.
It isn't a conformance demo (tests/test_consoles.py): a real Xbox program links the XDK's libraries, which are
proprietary.
"""

from __future__ import annotations

from pathlib import Path

from .. import BETA, PROJECT, REBUILD_CHECK, Compiler, Console


class Xbox(Console):
    id = "xbox"
    name = "Xbox"
    short = "Xbox"
    status = BETA
    arch = "x86"
    mode = PROJECT
    layout = "Ghidra + objdiff"
    compilers = (Compiler("MSVC/7.1", "Visual C++ 7.1", "games made with the XDK 5849"),)
    # XDK 5849's vc71 tools are the msvc pack's Visual C++ 7.1 (the same files): the XDK gives the headers and libraries
    packs = (("msvc", "Visual C++ 6.0, 7.0 and 7.1, the compilers of PC games (proprietary)"),
             ("xdk", "your own Xbox XDK: the headers and libraries of Xbox games (proprietary, never downloaded)"))
    guides = ("x86", "xbox", "cpp")
    compiler_guide = "xbox"  # given up front; it starts by pointing at the x86 guide, which holds what PC shares
    ram = (0x00010000, 0x80000000)  # an XBE loads at 0x10000; the kernel lives above 0x80000000
    import_options = ("ltcg",)  # built with link-time code generation or not (None: told from the program)
    own_features = frozenset({REBUILD_CHECK})  # `ninja export` relinks the XBE (pc/project_template/tools/export.py)

    def sniff(self, head: bytes, file) -> bool:
        from . import scratch, xdvdfs

        if scratch.is_xbe(head):
            return True
        return xdvdfs.is_xbox_disc(file if isinstance(file, Path) else bytes(file))

    def upload_name(self, data: bytes) -> str:
        from . import scratch

        return "default.xbe" if scratch.is_xbe(bytes(data[:0x1000])) else "game.iso"

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return ""  # the program's library version table says which XDK, so which Visual C++, built it

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, ltcg: bool | None = None,
                       log=print) -> dict:
        """`ltcg`: the user's choice of link-time code generation (None: told from the program)."""
        from . import scratch

        return scratch.create(root, game, compiler=compiler, ltcg=ltcg, log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The program's data isn't in the target objects: it's read from the user's copy, as on PC."""
        from ..pc import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def refresh_project(self, fp, log=print) -> list[str]:
        """The project's tools/ brought up to the PC template it was made from (consoles/pc/scratch.py)."""
        from ..pc import scratch

        return scratch.refresh_tools(fp, log=log)

    def check_rebuild(self, fp, version: str, log=print) -> dict:
        """The project's `ninja export`: the XBE linked again with the XDK's linker and imagebld, compared byte for
        byte (the PC path's, consoles/pc/scratch.py check_program)."""
        from ..pc import scratch

        return scratch.check_program(fp, version, log=log)

    def read_program(self, data: bytes):
        """The program in the shape the PC path reads a Windows one into (consoles/pc/scratch.py read_program)."""
        from . import scratch

        return scratch.read_xbe(data)


XBOX = Xbox()
