"""The original Xbox: x86 programs (XBE) built with Visual C++ 7.1 from Microsoft's Xbox Development Kit (the XDK),
PROJECT mode. An Xbox game is a Windows-style program in Microsoft's own executable format, so its project is the PC
console's (consoles/pc/: the template, the delinker, the analysis), with what's the Xbox's own:

- scratch.py: a project for the user's XBE or disc image: the XBE read into the PC path's shape, Ghidra's analysis
  of its memory image (stock Ghidra has no XBE loader), the XDK's library code set aside, and whether the game was
  built with link-time code generation (convention.detect_functions, or the user's choice: import_options "ltcg").
- ltcg.py: what makes a project an LTCG one (the template setting, the flags, a harness driver per unit).
- xdklib.py: the XDK's own library functions found in the program by the user's XDK libraries, byte for byte.
- xboxkrnl.py: the kernel's exports by ordinal, for the kernel thunk table's `__imp__<Name>` imports.
- xdvdfs.py: default.xbe read off an Xbox disc image (an XISO or a full Redump dump), in place.
- guides/xbox.md: what agents read about the XDK, kernel calls, library code and LTCG.

The XDK is the user's own copy (the `xdk` local toolchain: checked and read where it is, never downloaded); the
compiler is the `msvc` pack's 7.1 (the XDK's vc71 tools are the same files) and the XDK's linker runs through
`wibo-xbox`. Its demo program is projects/demo-xbe (an XBE written byte by byte, no Microsoft code), which tests read
directly: it has no Demo Quest build, as nothing here may link the XDK's libraries.
"""

from __future__ import annotations

from pathlib import Path

from .. import BETA, PROJECT, Compiler
from ..pc import WindowsPC


class OriginalXbox(WindowsPC):
    id = "xbox"
    name = "Original Xbox"
    short = "Xbox"
    aliases = ()
    status = BETA
    layout = "Ghidra + objdiff"
    compilers = (Compiler("MSVC/7.1", "Visual C++ 7.1", "Xbox games (XDK 5849's compiler)"),)
    packs = (("msvc", "Visual C++ 7.1, the compiler of Xbox games (the same files as the XDK's; proprietary)"),
             ("xdk", "your own Xbox XDK: the headers and libraries of Xbox games (proprietary, never downloaded)"),
             ("ghidra", "finds an Xbox game's functions (540 MB, needs Java 21+)"))
    guides = ("xbox", "x86", "cpp")
    compiler_guide = "xbox"  # it says to read the x86 guide first
    ram = (0x00010000, 0x04000000)  # XBEs load at 0x10000; the retail console has 64 MB
    demo = ""  # projects/demo-xbe is read by tests/test_xbe.py: it isn't a Demo Quest build (see the docstring)
    demo_tools = ()
    import_options = ("ltcg",)  # built with link-time code generation: True, False, or found out at import

    def up_front_guides(self, compiler: str) -> tuple[str, ...]:
        return ("x86", "xbox")  # the Xbox guide is what differs from the x86 one

    def sniff(self, head: bytes, file) -> bool:
        from . import scratch, xdvdfs

        if scratch.is_xbe(head):
            return True
        return xdvdfs.is_xbox_disc(Path(file) if isinstance(file, (str, Path)) else file)

    def upload_name(self, data: bytes) -> str:
        from . import scratch

        return "default.xbe" if scratch.is_xbe(bytes(data[:0x1000])) else "game.iso"

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return ""  # the program's library version table says which XDK, so which Visual C++ (scratch.guess_compiler)

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print, **options) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, ltcg=options.get("ltcg"), log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def read_program(self, data: bytes):
        from . import scratch

        return scratch.read_xbe(data)


XBOX = OriginalXbox()
