"""Start an original Xbox decompilation from scratch: read the game's program (an XBE, or the default.xbe on its
disc image) into the same shape scratch_pe reads a Windows program into, so the PC path's analysis, source units
and delinker work on it unchanged.

An Xbox game is a Windows-style x86 program built with Visual C++ from Microsoft's Xbox Development Kit (the XDK),
packed in Microsoft's own executable format instead of a PE:

- the headers load at the base address (0x10000) and every pointer in them is an address, not a file offset;
- the entry point and the kernel thunk table's address are stored XORed with a key, one pair for retail images and
  another for debug ones (imagebld writes debug keys; Microsoft's certification switches them to retail);
- there's no import directory: the kernel thunk table is a zero-terminated list of `0x80000000 | ordinal` words
  into xboxkrnl.exe (named in xboxkrnl.py), which become `__imp__<Name>` imports here as a PE's imports do;
- there's no Rich header either. The library version table names each XDK library the program linked (XAPILIB,
  D3D8, DSOUND...) and the XDK build it came from, which is what picks the compiler.

The project is the PC path's (scratch_pe.write_project, pc_template): Ghidra finds the functions in the XBE's memory
image (stock Ghidra has no XBE loader), the XDK's own library code is set aside (xdklib), and src/ compiles with
the [msvc] pack's Visual C++ 7.1 (the XDK's own compiler) against the headers of the user's own XDK, set up in Setup.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .. import toolchains
from . import scratch_pe, xboxkrnl, xdklib, xdvdfs
from .project import ForkError
from .scratch_pe import PE, Section

MAGIC = b"XBEH"
# (entry point key, kernel thunk key) by kind of image
KEYS = {"retail": (0xA8FC57AB, 0x5B6D40B6), "debug": (0x94859D4B, 0xEFB1F152)}
IMAGE_HEADER = 0x184  # the header's size since the earliest XDKs; older fields past 0x178 may be missing
SECTION_HEADER = 56
LIBRARY_VERSION = 16
EXECUTABLE, WRITABLE = 0x4, 0x1  # XBE section flags
# Visual C++ by the XDK build that shipped it, for the compiler a game was built with.
# shortcut: only XDK 5849 (December 2003) is verified (its vc71 tools are the same files as Visual C++ 7.1 build
# 3077); add other XDK releases as someone checks their compilers.
XDK_COMPILERS = {5849: "7.1"}
DEFAULT_COMPILER = "7.1"  # for an XDK whose compiler isn't known yet: most Xbox games are from the 7.1 years
# The template's compiler flags for Xbox games: what the XDK's project templates set for a release build (/G6 for the
# Pentium III, /arch:SSE, /Gy for a section per function) plus _XBOX, which the XDK's headers expect.
# shortcut: games built with /GL (link-time code generation: custom register conventions, cross-file inlining) need
# an LTCG mode, still to come; nothing detects them yet, so /GL is never the default.
CL_FLAGS = ["/nologo", "/c", "/O2", "/G6", "/GF", "/Gy", "/arch:SSE", "/W3", "/D_XBOX"]
# Data sections by name. The Xbox linker marks .rdata and .data executable too (and code sections writable), so the
# flags don't tell code from data: Burnout 3's .rdata, .data and .data1 all carry the executable flag.
_DATA_NAME = re.compile(r"(?i)^(\.r?data\w*|\.bss|\.tls|\.xtlid|\$\$x\w*|\w+_RD)$")
REGIONS = {1:"North America", 2: "Japan", 4: "rest of the world", 0x80000000: "manufacturing"}


@dataclass
class Library:
    name: str  # "XAPILIB", "D3D8", "XBOXKRNL"...
    major: int
    minor: int
    build: int  # the XDK build: 5849 for the December 2003 XDK
    flags: int

    @property
    def qfe(self) -> int:
        """The library's hotfix number: a game can carry a newer QFE of one library than the rest of its XDK."""
        return self.flags & 0x1FFF

    @property
    def debug(self) -> bool:
        return bool(self.flags & 0x8000)


@dataclass
class XBE(PE):
    keys: str = "retail"  # which key pair the entry point and kernel thunk address were stored with
    kernel_thunk: int = 0  # the address of the kernel thunk table
    title_id: int = 0
    title: str = ""
    region: int = 0
    libraries: list[Library] = field(default_factory=list)

    @property
    def title_code(self) -> str:
        """The title ID as Xbox people write it: publisher letters and number, 0x4D530004 -> "MS-004"."""
        letters = self.title_id >> 16
        a, b = chr(letters >> 8), chr(letters & 0xFF)
        if not (a.isalnum() and b.isalnum()):
            return f"{self.title_id:08X}"
        return f"{a}{b}-{self.title_id & 0xFFFF:03d}"


def is_xbe(head: bytes) -> bool:
    """An original Xbox program (the first 4 KiB of the file are enough)."""
    return len(head) >= 0x178 and head[:4] == MAGIC and struct.unpack_from("<I", head, 0x104)[0] & 0xFFF == 0


def is_xbox(path: Path) -> bool:
    """An Xbox program or disc image on disk."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x1000)
    except OSError:
        return False
    return is_xbe(head) or xdvdfs.is_xbox_disc(path)


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def _header(data: bytes, base: int, addr: int, n: int, what: str) -> int:
    """The file offset of `n` bytes at a header address: headers load at the base address, so the offset is the
    address less the base. Says which field was out of the file rather than failing on a bad slice."""
    at = addr - base
    if at < 0 or at + n > len(data):
        raise ForkError(f"this XBE is damaged or cut short: its {what} (0x{addr:08X}) isn't in the file")
    return at


def _string(data: bytes, base: int, addr: int, what: str) -> str:
    at = _header(data, base, addr, 1, what)
    end = data.find(b"\0", at, at + 256)
    return data[at:end if end >= 0 else at + 256].decode("latin-1")


def _keys(entry_enc: int, thunk_enc: int, sections: list[Section]) -> tuple[str, int, int]:
    """(kind, entry point, kernel thunk address): the key pair under which the entry point lands in code and the
    thunk table in the image. A wrong key gives an address nowhere near the program, so only one pair fits."""
    for kind, (entry_key, thunk_key) in KEYS.items():
        entry, thunk = entry_enc ^ entry_key, thunk_enc ^ thunk_key
        if any(s.code and s.va <= entry < s.va + max(s.vsize, s.size) for s in sections) and \
                any(s.va <= thunk < s.va + max(s.vsize, s.size) for s in sections):
            return kind, entry, thunk
    raise ForkError("this XBE's entry point doesn't decode with the retail or debug keys: it may be from a "
                    "prototype kit decompdecomp doesn't know, or damaged")


def _kernel_imports(xbe: XBE) -> dict[int, str]:
    """Kernel thunk slot -> the kernel export's name (`NtClose`, or `xboxkrnl_<ordinal>` for an unknown one)."""
    out: dict[int, str] = {}
    for k in range(1024):
        word = xbe.read(xbe.kernel_thunk + 4 * k, 4)
        if len(word) < 4 or not _u32(word, 0):
            break
        value = _u32(word, 0)
        if not value & 0x80000000:  # not an ordinal: the table ended without its zero, or isn't one
            break
        out[xbe.kernel_thunk + 4 * k] = xboxkrnl.name(value & 0x7FFFFFFF)
    return out


def read_xbe(data: bytes) -> XBE:
    """The program's sections, entry point, kernel imports, certificate and library versions."""
    if not is_xbe(data[:0x1000]):
        raise ForkError("this isn't an original Xbox program (XBE): Xbox games start from default.xbe or their disc "
                        "image")
    base, size_headers, image_size, header_size, timestamp, cert = struct.unpack_from("<6I", data, 0x104)
    count, section_headers = struct.unpack_from("<II", data, 0x11C)
    entry_enc, thunk_enc = _u32(data, 0x128), _u32(data, 0x158)
    lib_count, libs_at = struct.unpack_from("<II", data, 0x160)
    if count > 256:
        raise ForkError(f"this XBE says it has {count} sections, more than any real one: it's damaged")

    sections = []
    at = _header(data, base, section_headers, SECTION_HEADER * count, "section headers")
    for i in range(count):
        flags, va, vsize, offset, raw_size, name_at = struct.unpack_from("<6I", data, at + SECTION_HEADER * i)
        name = _string(data, base, name_at, f"section {i}'s name")
        sections.append(Section(name, va, vsize, offset, min(raw_size, max(0, len(data) - offset)),
                                bool(flags & EXECUTABLE) and not _DATA_NAME.match(name)))
    kind, entry, thunk = _keys(entry_enc, thunk_enc, sections)

    c = _header(data, base, cert, 0xB0, "certificate")
    title = data[c + 0x0C:c + 0x5C].decode("utf-16-le", "replace").split("\0", 1)[0].strip()
    libraries = []
    if lib_count and header_size >= 0x168:
        at = _header(data, base, libs_at, LIBRARY_VERSION * lib_count, "library version table")
        for i in range(min(lib_count, 256)):
            raw = data[at + LIBRARY_VERSION * i:at + LIBRARY_VERSION * (i + 1)]
            libraries.append(Library(raw[:8].split(b"\0", 1)[0].decode("latin-1"), *struct.unpack_from("<4H", raw, 8)))

    xbe = XBE(data, base, image_size, entry, timestamp, sections, keys=kind, kernel_thunk=thunk,
              title_id=_u32(data, c + 0x08), title=title, region=_u32(data, c + 0xA0), libraries=libraries)
    xbe.imports = _kernel_imports(xbe)
    return xbe


def xdk_build(xbe: XBE) -> int | None:
    """The XDK build the program was made with: XAPILIB's (every game links it), else the build most of its
    libraries share. A game can carry a hotfix of one library, which shows as its QFE, not as another build."""
    for lib in xbe.libraries:
        if lib.name == "XAPILIB":
            return lib.build
    builds = Counter(lib.build for lib in xbe.libraries if lib.name != "XBOXKRNL")
    return builds.most_common(1)[0][0] if builds else None


def guess_compiler(xbe: XBE) -> tuple[str | None, str]:
    """(Visual C++ version, why): what the XDK build in the library version table says."""
    build = xdk_build(xbe)
    if build is None:
        return None, "the program has no library version table, so it doesn't say which XDK built it"
    if build in XDK_COMPILERS:
        return XDK_COMPILERS[build], f"its libraries come from XDK {build}, which ships Visual C++ {XDK_COMPILERS[build]}"
    return None, f"its libraries come from XDK {build}, whose compiler decompdecomp doesn't know yet"


def program_bytes(path: Path) -> bytes:
    """The XBE's bytes, from the file itself or from default.xbe on a disc image."""
    with open(path, "rb") as f:
        head = f.read(0x1000)
    if is_xbe(head):
        return path.read_bytes()
    if xdvdfs.is_xbox_disc(path):
        return xdvdfs.read_file(path, "default.xbe")
    raise ForkError("this isn't an original Xbox program (XBE) or disc image")


def game_info(path: Path) -> dict:
    data = program_bytes(path)
    xbe = read_xbe(data)
    title = xbe.title or path.stem
    version, why = guess_compiler(xbe)
    regions = [n for bit, n in REGIONS.items() if xbe.region & bit]
    return {"platform": "xbox", "id": re.sub(r"[^a-z0-9]+", "", title.lower()) or "game", "title": title,
            "title_id": xbe.title_code, "region": ", ".join(regions) or "unknown", "sha1": hashlib.sha1(data).hexdigest(),
            "timestamp": xbe.timestamp, "keys": xbe.keys, "xdk": xdk_build(xbe), "compiler": version,
            "compiler_why": why}


# ---------------------------------------------------------------------------------------------------- Ghidra


def memory_image(xbe: XBE) -> bytes:
    """The program as the Xbox loads it, from the base address: the headers, then each section's bytes at its
    address (zeros where a section is longer in memory than in the file). Stock Ghidra has no XBE loader, so this
    is what it imports, as raw code at the base address."""
    size = max([xbe.image_size, *(s.va + max(s.vsize, s.size) - xbe.image_base for s in xbe.sections)])
    image = bytearray(size)
    headers = min(_u32(xbe.data, 0x108), len(xbe.data), size)
    image[:headers] = xbe.data[:headers]
    for s in xbe.sections:
        at = s.va - xbe.image_base
        image[at:at + s.size] = xbe.data[s.offset:s.offset + s.size]
    return bytes(image)


def function_starts(xbe: XBE, skip: frozenset[str] = frozenset()) -> list[int]:
    """Where functions start, as the code itself shows it: the entry point, and every `call rel32` target in a code
    section that sits where a function can start (at the section's start, or after padding or a ret). Ghidra
    follows calls from what it disassembles anyway; these seed the code it wouldn't reach from the entry point
    (functions only reached through vtables or callbacks still call others).

    Virtual methods nobody calls directly are seeded from the vtables: runs of two or more words in a data section
    that each point at such a start (on Burnout 3, hundreds of small methods were reached only that way, and Ghidra
    merged runs of them into one function)."""
    code = [s for s in xbe.sections if s.code and s.name not in skip]

    def plausible(target: int) -> bool:
        t = next((c for c in code if c.va <= target < c.va + c.size), None)
        if t is None:
            return False
        at = target - t.va + t.offset
        before = xbe.data[at - 1] if target > t.va else None
        return (before is None or before in (0xCC, 0x90, 0xC3)) and xbe.data[at] not in (0x00, 0xCC)

    found = {xbe.entry}
    for s in code:
        data = xbe.data[s.offset:s.offset + s.size]
        for op in (b"\xe8", b"\xe9"):  # calls, and jumps: a tail call can be the only way to a function
            i = data.find(op)
            while 0 <= i <= len(data) - 5:
                target = s.va + i + 5 + struct.unpack_from("<i", data, i + 1)[0]
                if target not in found and plausible(target):
                    found.add(target)
                i = data.find(op, i + 1)
    return sorted(found | vtable_targets(xbe, plausible, skip))


def vtable_targets(xbe: XBE, plausible, skip: frozenset[str] = frozenset()) -> set[int]:
    """Code addresses in vtables: runs of at least two aligned words in a data section that all point at plausible
    function starts. A lone pointer can be any number that happens to look like an address; two in a row rarely are."""
    out: set[int] = set()
    for s in xbe.sections:
        if s.code or s.name in skip:
            continue
        data = xbe.data[s.offset:s.offset + s.size]
        run: list[int] = []
        for (word,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4]):
            if plausible(word):
                run.append(word)
                continue
            if len(run) >= 2:
                out.update(run)
            run = []
        if len(run) >= 2:
            out.update(run)
    return out


def ghidra_layout(xbe: XBE, skip: frozenset[str] = frozenset()) -> str:
    """The DecompWtfLayout pre-script's lines: the headers and every section as blocks (sections in `skip`, the
    XDK's own libraries, are left as data so the analysis doesn't spend its time there), and the entry points."""
    lines = [f"block XBE_HEADERS {xbe.image_base:X} {xbe.image_base + _u32(xbe.data, 0x108):X} rw"]
    for s in xbe.sections:
        name = re.sub(r"[^A-Za-z0-9_.$]", "_", s.name) or "section"
        lines.append(f"block {name} {s.va:X} {s.va + max(s.vsize, s.size):X} "
                     f"{'x' if s.code and s.name not in skip else 'rw'}")
    lines += [f"entry {a:X}" for a in function_starts(xbe, skip)]
    return "\n".join(lines) + "\n"


def find_functions(xbe: XBE, name: str, skip: frozenset[str] = frozenset(), timeout: float = 3600) -> list[dict]:
    """Every function Ghidra finds in the XBE (rows as ghidra.functions() gives them), without an XBE loader: the
    memory image imported as raw x86, cut into sections and seeded by ghidra_layout()."""
    from . import ghidra

    return ghidra.functions_in_image(name, memory_image(xbe), xbe.image_base, ghidra_layout(xbe, skip), timeout)


def wibo(log=lambda *_: None) -> Path | None:
    """The wibo that runs the XDK's Windows tools here (None on Windows, which runs them itself).

    Stock wibo 1.2.0 runs CL.Exe, which is all the PC path needs (delink and objdiff, no link step), but the XDK's
    Link.Exe (and /LTCG, and Lib.Exe) need APIs it lacks: `wibo-xbox` is wibo with those added, a superset, so it
    runs every XDK tool. DECOMP_WIBO_XBOX points at a local build of it (for working on wibo itself). Without
    wibo-xbox, plain compiles still work with the stock wibo."""
    if sys.platform == "win32":
        return None
    if (own := os.environ.get("DECOMP_WIBO_XBOX")):
        if not Path(own).is_file():
            raise ForkError(f"DECOMP_WIBO_XBOX points at {own}, which isn't there: build wibo-xbox or unset it")
        return Path(own)
    reg = toolchains.registry()
    if "wibo-xbox" in reg and reg["wibo-xbox"].supported:
        toolchains.ensure("wibo-xbox", log=log)
        return toolchains.binary("wibo-xbox")
    if toolchains.get("wibo").supported:
        log("using the stock wibo: it compiles Xbox code, but linking with the XDK's linker needs wibo-xbox")
        toolchains.ensure("wibo", log=log)
        return toolchains.binary("wibo")
    raise ForkError("no wibo for this computer: Xbox games' Windows compilers run through wibo on Linux and macOS")


def tool_args(log=lambda *_: None) -> list[str]:
    """configure.py arguments: the [msvc] pack's Visual C++ (7.1 is the XDK's own compiler, the same files), the
    user's own XDK for the headers, and wibo."""
    if toolchains.installed("msvc") is None:
        raise ForkError("Xbox games are built with Visual C++ 7.1, which is proprietary: install it in Setup "
                        "(Visual C++) if you accept that, then try again")
    try:
        xdk = toolchains.local_folder("xdk")
    except toolchains.ToolchainError as e:
        raise ForkError(f"Xbox games are built against the XDK's headers and libraries. {e}") from None
    args = ["--msvc", str(toolchains.path("msvc")), "--xdk", str(xdk)]
    if (w := wibo(log)) is not None:
        args += ["--wibo", str(w)]
    return args


def set_aside(xbe: XBE, functions: list[scratch_pe.Function], xdk: Path | None) -> dict[int, str]:
    """Address -> why, for the analysed functions that are the XDK's library code rather than the game's: the ones
    the user's own XDK libraries match byte for byte (xdklib). Nothing without an XDK folder."""
    if xdk is None:
        return {}
    skip = xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries])
    regions = [(s.va, xbe.data[s.offset:s.offset + s.size]) for s in xbe.sections if s.code and s.name not in skip]
    hits = xdklib.match(regions, xdklib.libraries(xdk / "lib", [lib.name for lib in xbe.libraries]))
    return {f.addr: hits[f.addr].reason for f in functions if f.addr in hits}


def create(root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once, as scratch_pe does for a PC game:
    Ghidra finds the functions (from the XBE's memory image, ghidra_layout), the XDK's own code is set aside (its
    sections outright, its functions in .text by matching the user's XDK libraries), and the rest is grouped into
    source files compiled with Visual C++ 7.1 against the XDK's headers. Returns facts about the game."""
    from . import ghidra

    info = game_info(game)
    compiler = (compiler or f"MSVC/{info['compiler'] or DEFAULT_COMPILER}").removeprefix("MSVC/")
    if info["compiler"] is None:
        log(f"{info['compiler_why']}: trying Visual C++ {compiler}")
    args = tool_args(log)
    if not (toolchains.path("msvc") / compiler).is_dir():
        raise ForkError(f"Visual C++ {compiler} isn't in the installed compiler pack")
    if not ghidra.available():
        if toolchains.java_version() < 21:
            raise ForkError("Xbox games are analysed with Ghidra, which needs Java 21 or newer: install it from "
                            "https://adoptium.net, then try again")
        log("installing Ghidra (540 MB, once): it finds the functions in Xbox programs")
        toolchains.ensure("ghidra", log=log)
    data = program_bytes(game)
    xbe = read_xbe(data)
    skip = frozenset(xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries]))
    if skip:
        log(f"the XDK's library sections are set aside: {', '.join(sorted(skip))}")

    log(f"analysing {xbe.title or game.name} with Ghidra (finds every function; a big game takes a few minutes)")
    found = find_functions(xbe, f"{info['id']}.xbe", skip)
    if not found:
        raise ForkError("Ghidra found no functions in this program (did its analysis fail or time out?)")
    found = [r for r in found if (s := xbe.section_at(r["entry"])) is not None and s.name not in skip]
    functions = scratch_pe.analyse(xbe, found, linker_padding=True)
    xdk = Path(args[args.index("--xdk") + 1])
    aside = set_aside(xbe, functions, xdk)
    game_fns = [f for f in functions if f.addr not in aside]
    library = [f for f in functions if f.addr in aside]
    groups = scratch_pe.units(game_fns)
    groups |= {f"xdk_{u.removeprefix('text_')}": fns for u, fns in scratch_pe.units(library).items()}
    log(f"{len(functions)} functions, {len(library)} of them the XDK's library code (set aside); "
        f"{info['compiler_why']}: Visual C++ {compiler}")
    return scratch_pe.write_project(
        root, game if is_xbe_file(game) else data, info=info, compiler=compiler, args=args,
        pe=xbe, groups=groups, platform="xbox", suffix=".xbe", what="your copy of the game's program (default.xbe)",
        cl_flags=CL_FLAGS, set_aside={f.name: aside[f.addr] for f in library}, log=log)


def is_xbe_file(path: Path) -> bool:
    """The file is the XBE itself (not a disc image holding it), so the project can link to it instead of a copy."""
    try:
        with open(path, "rb") as f:
            return is_xbe(f.read(0x1000))
    except OSError:
        return False
