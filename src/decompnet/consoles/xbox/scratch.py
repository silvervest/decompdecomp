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

What's here so far reads an XBE and its disc. Making the project (the XDK as a toolchain in Setup, Ghidra loading
an XBE, setting the XDK's own library code aside) is the next step, so create() refuses with a clear message.
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

from ... import toolchains
from ...forks.project import ForkError
from ..pc.scratch import PE, Section
from . import xboxkrnl, xdvdfs

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
REGIONS = {1: "North America", 2: "Japan", 4: "rest of the world", 0x80000000: "manufacturing"}


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
                                bool(flags & EXECUTABLE)))
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


NOT_YET = ("Xbox projects aren't finished yet: decompdecomp reads this game's program, but making its project needs "
           "the XDK as a toolchain and Ghidra's XBE loading, which are still being built. Use a PC, GameCube, Wii or "
           "DS game for now")


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


def create(root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root`. Not yet: the game is read (so a bad file still gets its own message), then this
    refuses, until the XDK toolchain and Ghidra's XBE loading are in."""
    read_xbe(program_bytes(game))
    raise ForkError(NOT_YET)
