"""Windows PC games: 32-bit x86 programs (.exe) built with Microsoft Visual C++ 6.0, 7.0 or 7.1, PROJECT mode. Only
the game is a Windows program: decompdecomp runs on Linux, and so do the compilers (through wibo).

- scratch.py: a project for the user's .exe: Ghidra finds its functions, decompdecomp cuts each one out of the
  program into a COFF object of its own (the target objdiff compares with), and which Visual C++ built it comes
  from the program's Rich header. `ninja export` rebuilds the program from it (the Overview's rebuild check).
- project_template/: what that project starts as (tools/configure.py writes its ninja build; tools/ltcg.py and
  tools/dll2coff.py build a unit in harness mode for games built with link-time code generation; tools/export.py
  rebuilds the program).
- convention.py: how each function takes its arguments, read off the original's code (LTCG's register conventions).
- methods.py: structs and classes with member functions, from how functions use `this` (get_class, briefs).
- standins.py: starting points for an LTCG unit's harness (standins_for).
- unresolved.py: which names a unit's harness link left unresolved matter to a function's code.
- guides/x86.md: what agents read about x86 and matching Visual C++'s code.

The original Xbox (consoles/xbox/) reuses all of it: its programs are x86 built with Visual C++ 7.1 too.

Its demo game is projects/demo-pc (the Demo Quest game built with Visual C++ 6.0). Older projects' configs say
"win32" (decomp.dev's id): that's this console too.
"""

from __future__ import annotations

from pathlib import Path

from .. import BETA, PROJECT, REBUILD_CHECK, Compiler, Console

MSVC_VERSIONS = ["MSVC/6.0", "MSVC/7.0", "MSVC/7.1"]  # the `msvc` pack


class WindowsPC(Console):
    id = "pc"
    name = "Windows PC"
    short = "PC"
    aliases = ("win32",)
    status = BETA
    arch = "x86"
    mode = PROJECT
    layout = "Ghidra + objdiff"
    compilers = tuple(Compiler(v, f"Visual C++ {v.removeprefix('MSVC/')}") for v in MSVC_VERSIONS)
    packs = (("msvc", "Visual C++ 6.0, 7.0 and 7.1, the compilers of PC games (proprietary)"),
             ("ghidra", "finds a PC game's functions, and drafts for platforms m2c can't read (540 MB, needs Java 21+)"))
    guides = ("x86", "cpp")
    compiler_guide = "x86"
    ram = (0x00400000, 0x80000000)  # a 32-bit program's address space above its usual image base
    demo = "demo-pc"
    demo_tools = ("msvc", "objdiff-cli", "wibo", "ghidra", "java")  # Ghidra needs Java 21 or newer
    own_features = frozenset({REBUILD_CHECK})  # `ninja export` rebuilds the program from src/ and the user's copy

    def sniff(self, head: bytes, file) -> bool:
        from .scratch import is_pe

        return is_pe(head)

    def upload_name(self, data: bytes) -> str:
        return "game.exe"

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return ""  # the program's Rich header says which Visual C++ built it (scratch.guess_compiler)

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print, **options) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def check_rebuild(self, fp, version: str, log=print) -> dict:
        """The project's `ninja export`: the program rebuilt with the game's own linker, compared byte for byte."""
        from . import scratch

        return scratch.check_program(fp, version, log=log)

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The program's data isn't in the target objects: it's read from the user's copy."""
        from . import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def read_program(self, data: bytes):
        from . import scratch

        return scratch.read_pe(data)

    def made_here(self, fp) -> bool:
        from . import scratch

        return scratch.made_here(fp)

    def refresh_tools(self, fp, log=print, *, force: bool = False) -> list[str]:
        from . import scratch

        return scratch.refresh_tools(fp, log=log, force=force)

    def program(self, fp):
        from . import convention

        if not (fp.manifest or {}).get("version") or not (fp.manifest or {}).get("game"):
            return None
        return convention.load(fp.root, fp.manifest)


PC = WindowsPC()
