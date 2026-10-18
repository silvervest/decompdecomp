"""The XDK's own library code in an Xbox game, found so it can be set aside: it's Microsoft's, not the game's, and
agents shouldn't spend time decompiling it.

Two kinds:

- Whole sections. The XDK's big libraries link into sections of their own, named after them (D3D, DSOUND, XNET,
  XONLINE, ...). Their code is set aside without looking at it.
- Functions in .text: the C runtime (libcmt), XAPI (xapilib) and the smaller libraries link next to the game's code.
  They're found by matching the user's own XDK libraries against the program: every function in a library member
  (with /Gy, one code section per function) becomes a byte pattern in which the fields relocations fill in are
  wildcards, and each place the pattern fits in a code section is that library function.

LTCG libraries (`d3d8ltcg.lib` and the like) hold the compiler's intermediate code, not machine code, so there's
nothing to match in them; their members are skipped (an object whose machine isn't i386).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

# Sections the XDK's libraries link their code into (the Xbox linker groups them by these names). Any section named
# after a library in the program's library version table counts too.
SECTIONS = frozenset({"XMV", "DSOUND", "WMADEC", "XONLINE", "XNET", "D3D", "D3DX", "XGRPH", "XPP", "DOLBY"})
I386 = 0x14C
CODE = 0x20  # section characteristics: holds code
RELOC_BYTES = {0x01: 2, 0x02: 2, 0x06: 4, 0x07: 4, 0x0A: 2, 0x0B: 4, 0x14: 4}  # i386 relocation -> bytes it fills
MIN_BYTES = 16  # shorter functions (a ret, a jmp) fit in too many places to say anything
ANCHOR = 6  # the fixed run a pattern is searched by
# libraries every game links, matched even when the version table doesn't name them (the C and C++ runtimes)
ALWAYS = ("libcmt.lib", "libcpmt.lib", "libc.lib", "libcp.lib")


@dataclass
class LibraryFunction:
    addr: int
    size: int
    symbol: str  # the library's name for it: `_memcpy`, `_XapiInitProcess@0`
    library: str  # `xapilib.lib`
    member: str  # the object it came from

    @property
    def reason(self) -> str:
        """Why it's set aside, as agents and the GUI read it."""
        return f"XDK library code: {self.symbol} from {self.library} ({self.member})"


def library_sections(section_names: list[str], library_names: list[str]) -> set[str]:
    """The program's sections that are XDK libraries outright: the known ones, and any named after a library in
    its version table (`XGRPH` is xgraphics, `D3D` is d3d8: the table and the section can differ, hence the list)."""
    libs = {n.upper() for n in library_names}
    return {s for s in section_names if s.upper() in SECTIONS or s.upper() in libs}


def members(data: bytes):
    """(name, bytes) of every object in a COFF archive (.lib)."""
    if data[:8] != b"!<arch>\n":
        return
    at, longnames = 8, b""
    while at + 60 <= len(data):
        head = data[at:at + 60]
        name = head[:16].decode("latin-1").strip()
        try:
            size = int(head[48:58].decode("latin-1").strip())
        except ValueError:
            return
        body = data[at + 60:at + 60 + size]
        if name == "//":
            longnames = body
        elif name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"\0", off)
            yield longnames[off:end if end >= 0 else None].decode("latin-1").split("\n")[0].rstrip("/"), body
        elif name not in ("/", "//"):
            yield name.rstrip("/"), body
        at += 60 + size + (size & 1)


def code_sections(obj: bytes):
    """(symbol, bytes, wildcard mask) of every code section of a COFF object; nothing for an LTCG object (compiler
    intermediate code) or an import stub."""
    if len(obj) < 20:
        return
    machine, count, _, symbols_at, n_symbols, opt_size, _ = struct.unpack_from("<HHIIIHH", obj, 0)
    if machine != I386:
        return
    strings = symbols_at + 18 * n_symbols
    names: dict[int, str] = {}
    i = 0
    while i < n_symbols and symbols_at + 18 * (i + 1) <= len(obj):
        at = symbols_at + 18 * i
        raw = obj[at:at + 8]
        if raw[:4] == b"\0\0\0\0":
            off = strings + struct.unpack_from("<I", raw, 4)[0]
            name = obj[off:obj.find(b"\0", off)].decode("latin-1")
        else:
            name = raw.rstrip(b"\0").decode("latin-1")
        value, section, typ, cls, aux = struct.unpack_from("<IhHBB", obj, at + 8)
        if section > 0 and value == 0 and cls in (2, 3) and (typ & 0x20 or cls == 2):
            names.setdefault(section, name)  # the function the section holds (the first symbol at its start)
        i += 1 + aux
    for k in range(count):
        at = 20 + opt_size + 40 * k
        size, raw_at, relocs_at, _, n_relocs, _, flags = struct.unpack_from("<IIIIHHI", obj, at + 16)
        if not flags & CODE or not raw_at or not size:
            continue
        body = obj[raw_at:raw_at + size]
        mask = bytearray(size)
        for r in range(n_relocs):
            va, _, typ = struct.unpack_from("<IIH", obj, relocs_at + 10 * r)
            for b in range(RELOC_BYTES.get(typ, 4)):
                if va + b < size:
                    mask[va + b] = 1
        yield names.get(k + 1, f"{obj[at:at + 8].rstrip(b'\0').decode('latin-1')}#{k + 1}"), body, bytes(mask)


def _pattern(body: bytes, mask: bytes) -> tuple[re.Pattern, bytes, int]:
    """The body as a regular expression (relocated bytes match anything), its longest fixed run and where that is."""
    parts, best, run = [], (0, 0), None
    for i in range(len(body) + 1):
        fixed = i < len(body) and not mask[i]
        if fixed and run is None:
            run = i
        elif not fixed and run is not None:
            if i - run > best[1] - best[0]:
                best = (run, i)
            run = None
    i = 0
    while i < len(body):
        if mask[i]:
            j = i
            while j < len(body) and mask[j]:
                j += 1
            parts.append(b".{%d}" % (j - i))
            i = j
        else:
            parts.append(re.escape(body[i:i + 1]))
            i += 1
    return re.compile(b"".join(parts), re.S), body[best[0]:best[1]], best[0]


def libraries(lib_dir: Path, library_names: list[str]) -> list[Path]:
    """The user's XDK libraries to match: the ones the program's version table names, and the C runtimes. LTCG
    libraries are left out (nothing in them to match); case is ignored, as on Windows."""
    present = {p.name.lower(): p for p in lib_dir.iterdir() if p.suffix.lower() == ".lib"} if lib_dir.is_dir() else {}
    wanted = [f"{n.lower()}.lib" for n in library_names] + list(ALWAYS)
    out = []
    for name in wanted:
        if name in present and present[name] not in out and not name.endswith("ltcg.lib"):
            out.append(present[name])
    return out


def match(regions: list[tuple[int, bytes]], libs: list[Path], min_bytes: int = MIN_BYTES) -> dict[int, LibraryFunction]:
    """Address -> the library function found there, in `regions` ((address, bytes) of the code to search). The
    first library to claim an address keeps it; a function that fits in several places is each of them (a game
    can link two copies)."""
    found: dict[int, LibraryFunction] = {}
    seen: set[tuple[bytes, bytes]] = set()
    for lib in libs:
        for member, obj in members(lib.read_bytes()):
            for symbol, body, mask in code_sections(obj):
                if len(body) < min_bytes or (body, mask) in seen:
                    continue
                seen.add((body, mask))
                rx, anchor, anchor_at = _pattern(body, mask)
                if len(anchor) < ANCHOR:
                    continue
                for base, data in regions:
                    p = data.find(anchor)
                    while p >= 0:
                        start = p - anchor_at
                        if start >= 0 and base + start not in found and rx.fullmatch(data, start, start + len(body)):
                            found[base + start] = LibraryFunction(base + start, len(body), symbol, lib.name,
                                                                  Path(member).name)
                        p = data.find(anchor, p + 1)
    return found
