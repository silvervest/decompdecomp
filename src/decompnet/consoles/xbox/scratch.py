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

import bisect
import copy
import dataclasses
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import capstone

from ... import toolchains
from ...forks import convention
from ...forks import ltcg as ltcg_mode
from ...forks.project import GAME, ForkError
from ..pc import scratch as scratch_pe
from ..pc.scratch import PE, Section
from . import xboxkrnl, xdklib, xdvdfs

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
# Games built with /GL (link-time code generation: custom register conventions, cross-file inlining) get the LTCG
# mode and its flags (forks/ltcg.py). shortcut: nothing detects them yet, so it's an explicit choice.
CL_FLAGS = ["/nologo", "/c", "/O2", "/G6", "/GF", "/Gy", "/arch:SSE", "/W3", "/D_XBOX"]
LTCG_CL_FLAGS = ltcg_mode.XBOX_CL_FLAGS
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


def _plausible_start(xbe: XBE, code: list[Section], target: int) -> bool:
    """`target` sits where a function can start in one of the `code` sections: at the section's start, or after
    padding or a ret, and not on padding or zeros itself."""
    t = next((c for c in code if c.va <= target < c.va + c.size), None)
    if t is None:
        return False
    at = target - t.va + t.offset
    before = xbe.data[at - 1] if target > t.va else None
    return (before is None or before in (0xCC, 0x90, 0xC3)) and xbe.data[at] not in (0x00, 0xCC)


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
        return _plausible_start(xbe, code, target)

    # (the entry point only where it's analysed: a new analysis of the library sections alone leaves .text as data)
    found = {xbe.entry} if any(c.va <= xbe.entry < c.va + c.size for c in code) else set()
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
    """The DecompWtfLayout pre-script's lines: the headers and every section as blocks (sections that aren't code,
    and those in `skip`, are left as data so the analysis doesn't spend its time there), and the entry points."""
    lines = [f"block XBE_HEADERS {xbe.image_base:X} {xbe.image_base + _u32(xbe.data, 0x108):X} rw"]
    seen: Counter = Counter()
    for s in xbe.sections:
        name = re.sub(r"[^A-Za-z0-9_.$]", "_", s.name) or "section"
        seen[name] += 1
        if seen[name] > 1:  # a library section's data after its code (analysis_view): a block of its own
            name = f"{name}_{seen[name]}"
        lines.append(f"block {name} {s.va:X} {s.va + max(s.vsize, s.size):X} "
                     f"{'x' if s.code and s.name not in skip else 'rw'}")
    lines += [f"entry {a:X}" for a in function_starts(xbe, skip)]
    return "\n".join(lines) + "\n"


def find_functions(xbe: XBE, name: str, skip: frozenset[str] = frozenset(), timeout: float = 3600) -> list[dict]:
    """Every function Ghidra finds in the XBE (rows as ghidra.functions() gives them), without an XBE loader: the
    memory image imported as raw x86, cut into sections and seeded by ghidra_layout()."""
    from ...forks import ghidra

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


def library_code(xbe: XBE, xdk: Path | None) -> tuple[dict[int, xdklib.LibraryFunction], list[Path]]:
    """(address -> library function, the libraries matched): the XDK's own functions in every code section (.text
    and the library sections), as the user's own XDK libraries match them byte for byte (xdklib). Nothing without an
    XDK folder."""
    if xdk is None:
        return {}, []
    regions = [(s.va, xbe.data[s.offset:s.offset + s.size]) for s in xbe.sections if s.code]
    libs = xdklib.libraries(xdk / "lib", [lib.name for lib in xbe.libraries])
    return xdklib.match(regions, libs), libs


def with_library_code(found: list[dict], hits: dict[int, xdklib.LibraryFunction]) -> list[dict]:
    """Ghidra's rows with every library function found at its exact extent (`exact`, which analyse() keeps): a
    library function Ghidra merged with its neighbour is split at its end, one it missed is added, and Ghidra's
    starts inside one (labels in the C runtime's assembly) are dropped."""
    inside = sorted((a, a + h.size) for a, h in hits.items())
    rows = {}
    for r in found:
        k = bisect.bisect_right(inside, (r["entry"], 1 << 32)) - 1
        if k >= 0 and inside[k][0] < r["entry"] < inside[k][1]:
            continue
        rows[r["entry"]] = r
    for a, h in hits.items():
        base = rows.get(a, {"name": "", "source": "LIBRARY", "convention": "__cdecl", "purge": 0, "params": 0})
        source = base.get("source") if base.get("source") in ("IMPORTED", "USER_DEFINED") else "LIBRARY"
        rows[a] = {**base, "entry": a, "end": a + h.size, "source": source, "exact": True}
    return sorted(rows.values(), key=lambda r: r["entry"])


def set_aside(xbe: XBE, functions: list[scratch_pe.Function], hits: dict[int, xdklib.LibraryFunction],
              libs: list[Path]) -> dict[int, str]:
    """Address -> why, for the analysed functions that are the XDK's library code rather than the game's: the
    library functions found by their bytes (`hits`), and the small ones only their exact bytes and a library
    neighbour place (xdklib.match_small)."""
    small = xdklib.match_small([(f.addr, xbe.read(f.addr, f.size)) for f in functions], libs, hits)
    every = {a: h.reason for a, h in (hits | small).items()}
    for f in functions:
        # `jmp [slot]`: the stub the linker makes for a kernel import (xboxkrnl.lib holds no code to match it by)
        code = xbe.read(f.addr, f.size)
        if f.addr not in every and len(code) == 6 and code[:2] == b"\xff\x25" and \
                (slot := struct.unpack_from("<I", code, 2)[0]) in xbe.imports:
            every[f.addr] = f"XDK library code: the linker's stub for the kernel import {xbe.imports[slot]}"
    return {f.addr: every[f.addr] for f in functions if f.addr in every}


# ---------------------------------------------------------------------------------------------------- library sections
#
# The XDK's big libraries link into sections of their own (xdklib.library_sections: XMV, DSOUND, WMADEC, XONLINE,
# XNET, D3D, XGRPH, XPP, DOLBY...). Every one carries the executable flag (imagebld marks every section so), and their
# flags vary (on a retail game most are 0x7, XONLINE and DOLBY 0x26), so neither the flags nor the names tell what
# they hold. What they hold, on a retail game:
# - x86 code, then the library's constant data (tables, strings, wave formats) after it in the same section: 128 KiB
#   of XMV's 160 KiB, 57 KiB of WMADEC's 104 KiB, the last 7 KiB of DSOUND, a few KiB of D3D, XNET and XGRPH;
# - no x86 at all: DOLBY is the audio processor's program (another instruction set). Its bytes don't even decode as
#   x86 in places, none of the XDK's x86 library functions match in it, and no x86 call reaches into it.
# The rule, by evidence rather than by name: a library section holds x86 code when the user's XDK libraries match one
# of their i386 functions in it byte for byte (xdklib.match), or when at least MIN_CALLED places in it are each called
# (`call rel32`) from two or more sites at a plausible function start (DOLBY: none; the smallest x86 one, XGRPH: 15).
# Its code ends past the last function that evidence vouches for (a matched library function's end, or a called
# start's own flow with its jump and byte tables), then the int3 padding after it; the rest of the section is data.
# Sections without x86 code, and the data after the code, stay data whatever the project's scope: Ghidra gets them
# as data blocks (analysis_view), so no function is made of them, and the export carries their bytes as they are.
# shortcut: a function after the last vouched-for one that only a pointer reaches is left in the data part.
MIN_CALLED = 2


def call_sites(xbe: XBE) -> dict[int, set[int]]:
    """Plausible function start -> the `call rel32` sites in the program's code sections that call it."""
    code = [s for s in xbe.sections if s.code]
    out: dict[int, set[int]] = {}
    for s in code:
        data = xbe.data[s.offset:s.offset + s.size]
        i = data.find(b"\xe8")
        while 0 <= i <= len(data) - 5:
            target = (s.va + i + 5 + struct.unpack_from("<i", data, i + 1)[0]) & 0xFFFFFFFF
            if target in out or _plausible_start(xbe, code, target):
                out.setdefault(target, set()).add(s.va + i)
            i = data.find(b"\xe8", i + 1)
    return out


def _code_end(md, xbe: XBE, start: int, limit: int) -> int:
    """Where the function at `start` ends, by its own flow, with its switch's jump table and the byte table that
    indexes it. (A byte table without a jump table has no end the code shows: the data after the function would
    all be taken for it, so it's left out.)"""
    flow = scratch_pe._flow_end(md, xbe, start, limit)
    _, data_end, entries = scratch_pe._tables(md, xbe, start, flow, limit)
    return max(flow, data_end) if entries else flow


def library_code_ends(xbe: XBE, sections: frozenset[str], hits: dict[int, xdklib.LibraryFunction]) -> dict[str, int]:
    """The library `sections` that hold x86 code -> where their code ends (the rule above); a section left out holds
    none (another processor's program)."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    called = [a for a, sites in call_sites(xbe).items() if len(sites) >= 2]
    out = {}
    for s in xbe.sections:
        if s.name not in sections or not s.code:
            continue
        lo, hi = s.va, s.va + s.size
        matched = [a + h.size for a, h in hits.items() if lo <= a < hi]
        starts = [a for a in called if lo <= a < hi]
        if not matched and len(starts) < MIN_CALLED:
            continue
        ends = matched + [_code_end(md, xbe, a, hi) for a in starts]
        end = min(max(ends), hi)
        while end < hi and xbe.data[s.offset + end - lo] == 0xCC:  # the last function's padding
            end += 1
        out[s.name] = end
    return out


def analysis_view(xbe: XBE, sections: frozenset[str], ends: dict[str, int]) -> XBE:
    """The program as the analysis sees it: each library section holding x86 code cut in two, its code and the data
    after it (a section of the same name, not code), and the library sections holding none marked as data."""
    view = copy.copy(xbe)
    view.sections = []
    for s in xbe.sections:
        if s.name in sections and s.code and s.name not in ends:
            view.sections.append(dataclasses.replace(s, code=False))
        elif s.name in ends and ends[s.name] < s.va + s.size:
            n = ends[s.name] - s.va
            view.sections += [dataclasses.replace(s, vsize=n, size=n),
                              dataclasses.replace(s, va=s.va + n, vsize=max(s.vsize, s.size) - n, offset=s.offset + n,
                                                  size=s.size - n, code=False)]
        else:
            view.sections.append(s)
    return view


def _say_library_sections(sections: frozenset[str], ends: dict[str, int], log) -> None:
    if ends:
        log("the XDK's library sections with x86 code are analysed and their functions set aside as the XDK's (the "
            "project's scope decides whether agents work on them): "
            + ", ".join(f"{n} (code to 0x{e:08X})" for n, e in sorted(ends.items(), key=lambda kv: kv[1])))
    if rest := sorted(sections - set(ends)):
        log(f"no x86 code in {', '.join(rest)} (another processor's program, say): kept as data")


def in_library_sections(xbe: XBE, functions: list[scratch_pe.Function], sections: frozenset[str]) -> dict[int, str]:
    """Address -> why, for the analysed functions in the XDK's library sections (every import analyses those, and
    sets their functions aside like the XDK's other code)."""
    out = {}
    for f in functions:
        if (s := xbe.section_at(f.addr)) is not None and s.name in sections:
            out[f.addr] = f"XDK library code: the {s.name} section"
    return out


def _ensure_ghidra(log) -> None:
    from ...forks import ghidra

    if not ghidra.available():  # as for a PC game: a JDK of decompdecomp's own where the computer has none
        if ghidra.java_home() is not None and toolchains.installed("jdk") is None:
            log("installing a Java development kit for Ghidra (200 MB, once): this computer has none of its own")
            toolchains.ensure("jdk", log=log)
        if toolchains.installed("ghidra") is None:
            log("installing Ghidra (540 MB, once): it finds the functions in Xbox programs")
            toolchains.ensure("ghidra", log=log)


def create(root: Path, game: Path, *, compiler: str | None = None, ltcg: bool | None = None, scope: str = GAME,
           log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once, as scratch_pe does for a PC game:
    Ghidra finds the functions (from the XBE's memory image, ghidra_layout) in .text and in every library section
    holding x86 code, the XDK's own code is set aside (the library sections' functions, and its functions in .text
    by matching the user's XDK libraries), and the rest is grouped into source files compiled with Visual C++ 7.1
    against the XDK's headers. The same is analysed whatever the project's `scope`: it only decides, when the
    project is measured, whether what's set aside is worked on and counted. Returns facts about the game."""
    info = game_info(game)
    compiler = (compiler or f"MSVC/{info['compiler'] or DEFAULT_COMPILER}").removeprefix("MSVC/")
    if info["compiler"] is None:
        log(f"{info['compiler_why']}: trying Visual C++ {compiler}")
    args = tool_args(log)
    if not (toolchains.path("msvc") / compiler).is_dir():
        raise ForkError(f"Visual C++ {compiler} isn't in the installed compiler pack")
    _ensure_ghidra(log)
    data = program_bytes(game)
    xbe = read_xbe(data)
    sections = frozenset(xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries]))
    hits, libs = library_code(xbe, Path(args[args.index("--xdk") + 1]))
    ends = library_code_ends(xbe, sections, hits)
    view = analysis_view(xbe, sections, ends)
    _say_library_sections(sections, ends, log)

    log(f"analysing {xbe.title or game.name} with Ghidra (finds every function; a big game takes a few minutes)")
    found = find_functions(view, f"{info['id']}.xbe")
    if not found:
        raise ForkError("Ghidra found no functions in this program (did its analysis fail or time out?)")
    found = [r for r in found if (s := view.section_at(r["entry"])) is not None and s.code]
    functions = scratch_pe.analyse(view, with_library_code(found, hits), linker_padding=True)
    aside = in_library_sections(view, functions, frozenset(ends)) | set_aside(view, functions, hits, libs)
    game_fns = [f for f in functions if f.addr not in aside]
    library = [f for f in functions if f.addr in aside]
    groups = scratch_pe.units(game_fns)
    groups |= {f"xdk_{u.removeprefix('text_')}": fns for u, fns in scratch_pe.units(library).items()}
    log(f"{len(functions)} functions, {len(library)} of them the XDK's library code (set aside); "
        f"{info['compiler_why']}: Visual C++ {compiler}")
    # link-time code generation (forks/ltcg.py): the user's choice (the import's switch, or DECOMP_XBOX_LTCG), else
    # what the program's call sites say (forks/convention.py)
    if ltcg is None and os.environ.get("DECOMP_XBOX_LTCG", "") != "":
        ltcg = os.environ["DECOMP_XBOX_LTCG"] != "0"
    found_ltcg = None
    if ltcg is None:
        found_ltcg = convention.detect_functions(xbe, game_fns)
        ltcg = found_ltcg["ltcg"]
        log(f"link-time code generation? {found_ltcg['why']}"
            + "".join(f"\n  e.g. {e}" for e in found_ltcg["examples"][:2]))
    evidence = {"ltcg_detected": found_ltcg} if found_ltcg else {}
    lt = {"cl_flags": LTCG_CL_FLAGS, "prepare": ltcg_mode.prepare, "manifest": {"ltcg": True, **evidence}} if ltcg \
        else {"cl_flags": CL_FLAGS, "manifest": evidence}
    if ltcg:
        log("link-time code generation: units are built in harness mode once their driver (harness/) calls them")
    lt["manifest"]["library_sections"] = sorted(ends)  # analysed (a project made before lacks it: Console.unanalysed)
    return scratch_pe.write_project(
        root, game if is_xbe_file(game) else data, info=info, compiler=compiler, args=args,
        pe=xbe, groups=groups, platform="xbox", suffix=".xbe", what="your copy of the game's program (default.xbe)",
        set_aside={f.name: aside[f.addr] for f in library}, log=log, **lt)


# ---------------------------------------------------------------------------------------------------- older projects
#
# Imports before every one analysed the library sections left them out of a project covering the game's own code
# (their manifests may say so as `set_aside_unimported`). A new analysis of those sections alone brings them in
# (Xbox.analyse_unanalysed, through forkengine.reanalyse): the project's existing functions and source files stay as
# they are, and the new functions get source files of their own, set aside like the XDK's other code.

_UNANALYSED: dict[tuple, list[str]] = {}  # (program, its mtime, functions.json's mtime) -> unanalysed_sections()


def _functions_json(root: Path, manifest: dict) -> Path:
    return root / "config" / manifest["version"] / "functions.json"


def unanalysed_sections(root: Path, manifest: dict) -> list[str]:
    """The XDK's library sections holding x86 code that a project made before they were always analysed has no
    functions in ([]: none, or a project whose import analysed them: its manifest lists `library_sections`). Quick
    (Settings asks): x86 code is told by its calls alone here, without matching the XDK's libraries; cached."""
    if manifest.get("platform") != "xbox" or manifest.get("created") != "from scratch" or \
            "library_sections" in manifest or "version" not in manifest:
        return []
    program, functions = root / manifest["game"]["path"], _functions_json(root, manifest)
    key = (str(program), program.stat().st_mtime_ns, functions.stat().st_mtime_ns)
    if key not in _UNANALYSED:
        xbe = read_xbe(program.read_bytes())
        sections = frozenset(xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries]))
        have = {s.name for fns in json.loads(functions.read_text(encoding="utf-8"))["units"].values() for f in fns
                if (s := xbe.section_at(f["addr"])) is not None}
        _UNANALYSED.clear()
        _UNANALYSED[key] = sorted(set(library_code_ends(xbe, sections, {})) - have,
                                  key=lambda n: next(s.va for s in xbe.sections if s.name == n))
    return list(_UNANALYSED[key])


def _xdk_folder(manifest: dict) -> Path | None:
    """The user's XDK, for matching its libraries: the one the project is configured with, else Setup's."""
    for cmd in manifest.get("setup", [])[:1]:
        if "--xdk" in cmd[:-1] and Path(cmd[cmd.index("--xdk") + 1]).is_dir():
            return Path(cmd[cmd.index("--xdk") + 1])
    try:
        return toolchains.local_folder("xdk")
    except toolchains.ToolchainError:
        return None


def analyse_library_sections(root: Path, log=print) -> tuple[str | None, list[str]]:
    """Bring the library sections holding x86 code that the project has no functions in into it: Ghidra analyses
    those sections alone (.text and the rest stay data blocks, so it's quick), their functions get source files of
    their own (xdk_<address>) and are set aside as the XDK's library code; references to the project's existing
    functions name them (scratch_pe.analyse's `known`). Changes config/ and src/auto/ only. Returns (what it did, as a
    sentence, None when there was nothing to do; the library sections with x86 code, all analysed now)."""
    manifest = json.loads((root / ".decomp.wtf.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    xbe = read_xbe((root / manifest["game"]["path"]).read_bytes())
    path = _functions_json(root, manifest)
    info = json.loads(path.read_text(encoding="utf-8"))
    known = {f["addr"]: f["name"] for fns in info["units"].values() for f in fns}
    sections = frozenset(xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries]))
    hits, libs = library_code(xbe, _xdk_folder(manifest))
    ends = library_code_ends(xbe, sections, hits)
    view = analysis_view(xbe, sections, ends)
    have = {s.name for a in known if (s := view.section_at(a)) is not None}
    todo = frozenset(ends) - have
    if not todo:
        return None, sorted(ends)
    _say_library_sections(sections, {n: e for n, e in ends.items() if n in todo}, log)
    _ensure_ghidra(log)
    log(f"analysing the library sections {', '.join(sorted(todo))} with Ghidra (the rest of the program stays as it is)")
    skip = frozenset(s.name for s in view.sections if s.code and s.name not in todo)  # (data sections: seeds)

    def new(a: int) -> bool:
        return a not in known and (s := view.section_at(a)) is not None and s.code and s.name in todo
    found = [r for r in find_functions(view, f"{version}.xbe", skip) if new(r["entry"])]
    if not found:
        raise ForkError("Ghidra found no functions in the library sections (did its analysis fail or time out?)")
    mine = {a: h for a, h in hits.items() if new(a)}
    functions = [f for f in scratch_pe.analyse(view, with_library_code(found, mine), linker_padding=True, known=known)
                 if new(f.addr)]
    aside = in_library_sections(view, functions, todo) | set_aside(view, functions, mine, libs)
    groups = {f"xdk_{u.removeprefix('text_')}": fns for u, fns in scratch_pe.units(functions).items()}
    if clash := set(groups) & set(info["units"]):
        raise ForkError(f"the project already has units named {', '.join(sorted(clash))}")
    info["units"].update({u: [scratch_pe.function_entry(view, f) for f in fns] for u, fns in groups.items()})
    path.write_text(json.dumps(info, indent=1), encoding="utf-8")
    listed = root / manifest.get("set_aside", f"config/{version}/set_aside.json")
    old = json.loads(listed.read_text(encoding="utf-8")) if listed.exists() else {}
    listed.write_text(json.dumps(old | {f.name: aside[f.addr] for f in functions}, indent=1), encoding="utf-8")
    for u, fns in groups.items():
        src = root / "src" / "auto" / f"{u}.cpp"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(scratch_pe.source_stub(fns), encoding="utf-8")
    matched = sum(1 for f in functions if f.addr in mine)
    return (f"{len(functions)} functions in the XDK's library sections {', '.join(sorted(todo))} are in "
            f"{len(groups)} new source file{'s' if len(groups) != 1 else ''}, set aside as the XDK's library code "
            f"({matched} of them matched to its libraries by their bytes)"), sorted(ends)


def is_xbe_file(path: Path) -> bool:
    """The file is the XBE itself (not a disc image holding it), so the project can link to it instead of a copy."""
    try:
        with open(path, "rb") as f:
            return is_xbe(f.read(0x1000))
    except OSError:
        return False
