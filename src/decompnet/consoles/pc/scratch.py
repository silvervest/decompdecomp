"""Start a PC (Windows) decompilation from scratch: a project made for the user's own copy of a 32-bit x86 program
(.exe), built with the game's Visual C++ and judged by objdiff, worked on like any community project.

There's no community toolkit for this as there is for GameCube (decomp-toolkit) or DS (ds-decomp), so decompdecomp
does the delinking itself:

- Ghidra's analysis finds the functions (and reads the program's imports and exports);
- each function's extent is its code plus what MSVC puts after it (jump tables, byte index tables) and the nop
  padding Visual C++ 6 ends functions with; code Ghidra didn't see in between becomes functions of its own;
- capstone reads every instruction for the addresses it holds: calls and jumps to other functions, and data
  addresses, become relocations (functions by their decorated names, `_func_00401000`, `_func_00401020@8` for
  __stdcall, `@func_00401040@8` for __fastcall; data as `_D_00402034`; imports as `__imp__Name@4`), so each function
  matches whatever names the C uses, under objdiff's usual rules.

The project (tools/configure.py, tools/delink.py) cuts the functions out of the user's copy into COFF objects at
build time, one per source file (src/auto/text_<address>.cpp, about 4 KiB of functions each), and compiles src/ with
MSVC through wibo. A program built without relocations (most games before 2005) has every address fixed, which is
what this reads; there's no relink of the whole .exe yet, so files aren't linked into the game as on GameCube.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import capstone
from capstone import x86

from decompnet.hostenv import NO_WINDOW

from ... import toolchains
from ...forks.project import ForkError, ForkProject

UNIT_BYTES = 0x1000
TEMPLATE = Path(__file__).with_name("project_template")
MSVC_DEFAULT = "6.0"
DIR32, REL32 = 0x06, 0x14
PAD = 0x90  # what Visual C++ 6 pads a function's section with (the linker pads between objects with 0xCC or zeros)
# Visual C++ versions by the build number its tools leave in the program's Rich header, for the C/C++ compiler
RICH_BUILDS = {8168: "6.0", 8447: "6.0", 8799: "6.0", 8966: "6.0", 9044: "6.0", 9782: "6.0", 9466: "7.0", 9955: "7.0",
               3052: "7.1", 3077: "7.1", 4035: "7.1", 6030: "7.1"}
# Rich header product ids from Visual C++ 2005 on (its C compiler is 0x6D; 7.1 and older use lower ids): a program
# built with them is newer than the compiler pack (GitHub #12: a 2010 game only said "Ghidra found no functions")
NEWER_TOOLS_FIRST_PRODUCT = 0x6D
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_FN = 0x40000  # the most of a function's surroundings analyse() reads at once: bigger than any function
_PADDING = re.compile(rb"\x90*[\xcc\x00]*")  # between functions: Visual C++ 6's nops, then the linker's int3 or zeros
_NOT_PADDING = re.compile(rb"[^\x90\xcc\x00]")
_NOPS = re.compile(rb"\x90*")
_INT3S = re.compile(rb"\xcc*")


@dataclass
class Section:
    name: str
    va: int  # absolute address
    vsize: int
    offset: int  # in the file
    size: int  # bytes in the file
    code: bool


@dataclass
class PE:
    data: bytes
    image_base: int
    image_size: int
    entry: int
    timestamp: int
    sections: list[Section]
    imports: dict[int, str] = field(default_factory=dict)  # import address table slot -> "Sleep"

    def section_at(self, addr: int) -> Section | None:
        return next((s for s in self.sections if s.va <= addr < s.va + max(s.vsize, s.size)), None)

    def offset(self, addr: int) -> int | None:
        s = self.section_at(addr)
        return None if s is None or addr - s.va >= s.size else s.offset + addr - s.va

    def read(self, addr: int, n: int) -> bytes:
        off = self.offset(addr)
        return b"" if off is None else self.data[off:off + n]

    def contains(self, addr: int) -> bool:
        return self.image_base <= addr < self.image_base + self.image_size


# a Windows program: the DOS header ("MZ") says where the PE header is; after it the COFF header, then the optional
# header (PE32's: a 32-bit program), then the section table
DOS_HEADER_BYTES, PE_OFFSET_AT = 0x40, 0x3C
PE_HEADER_BYTES = 0x18  # "PE\0\0" and the COFF header
MACHINE_AT, SECTION_COUNT_AT, TIMESTAMP_AT = 4, 6, 8  # in the COFF header, from "PE\0\0"
OPTIONAL_HEADER_AT = PE_HEADER_BYTES
MACHINE_I386, PE32_MAGIC = 0x14C, 0x10B
ENTRY_AT, IMAGE_BASE_AT, IMAGE_SIZE_AT, IMPORTS_AT = 16, 28, 56, 104  # in the optional header
SECTION_HEADER_BYTES, SECTION_FLAGS_AT = 40, 36
CODE_AND_EXECUTABLE = 0x20000020  # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
PE_PROBE_BYTES, PE_HEADERS_BYTES = 0x1000, 0x200  # is_pe reads this much of a file, or the PE header and this much more
# the import directory: 20-byte descriptors, each with a table of 4-byte entries (a name's address, or an ordinal)
IMPORT_DESCRIPTOR_BYTES = 20
MAX_IMPORT_DLLS, MAX_IMPORTS_PER_DLL = 4096, 65536  # a broken table stops here
BY_ORDINAL, ORDINAL_BITS = 0x80000000, 0xFFFF
DLL_NAME_BYTES, IMPORT_NAME_BYTES = 64, 256
IMPORT_HINT_BYTES = 2  # an import's name follows its 2-byte hint
# the Rich header: the tools that built the program, XORed with a key, between the DOS stub and "Rich"
RICH_START = 0x80
RICH_ENTRIES_AT, RICH_ENTRY_BYTES = 16, 8  # after "DanS" and its padding: (product << 16 | build, count)
# read_data
READ_DEFAULT_BYTES, READ_MIN_BYTES, READ_MAX_BYTES = 64, 4, 512
HEX_ROW_BYTES = 16
POINTERS_SHOWN, FLOATS_SHOWN = 24, 8
PLAUSIBLE_FLOAT = (1e-6, 1e7)  # magnitudes a float in game data has; other words aren't floats
MIN_STRING_CHARS = 3
PRINTABLE = range(32, 127)
TOOL_SECONDS = 3600  # Ghidra on a big game, the project's build
ERROR_TAIL = 1500  # how much of a tool's output an error shows


def _pe_header(head: bytes) -> int | None:
    if len(head) < DOS_HEADER_BYTES or head[:2] != b"MZ":
        return None
    at = struct.unpack_from("<I", head, PE_OFFSET_AT)[0]
    if at + PE_HEADER_BYTES > len(head) or head[at:at + 4] != b"PE\0\0":
        return None
    return at


def is_pe(head: bytes) -> bool:
    """A 32-bit x86 Windows program (the first 4 KiB of the file are enough)."""
    at = _pe_header(head)
    return at is not None and struct.unpack_from("<H", head, at + MACHINE_AT)[0] == MACHINE_I386 and \
        struct.unpack_from("<H", head, at + OPTIONAL_HEADER_AT)[0] == PE32_MAGIC


def read_pe(data: bytes) -> PE:
    at = _pe_header(data)
    if at is None or not is_pe(data[:max(PE_PROBE_BYTES, at + PE_HEADERS_BYTES)]):
        raise ForkError("this isn't a 32-bit Windows program (.exe): PC games start from their x86 .exe")
    count, _, _, _, opt_size = struct.unpack_from("<HIIIH", data, at + SECTION_COUNT_AT)
    timestamp = struct.unpack_from("<I", data, at + TIMESTAMP_AT)[0]
    opt = at + OPTIONAL_HEADER_AT
    entry_rva, base, image_size = (struct.unpack_from("<I", data, opt + field)[0]
                                   for field in (ENTRY_AT, IMAGE_BASE_AT, IMAGE_SIZE_AT))
    sections = []
    for number in range(count):
        header = opt + opt_size + SECTION_HEADER_BYTES * number
        name, vsize, va, size, offset = struct.unpack_from("<8sIIII", data, header)
        flags = struct.unpack_from("<I", data, header + SECTION_FLAGS_AT)[0]
        sections.append(Section(name.rstrip(b"\0").decode("latin-1"), base + va, vsize, offset,
                                min(size, max(0, len(data) - offset)), bool(flags & CODE_AND_EXECUTABLE)))
    pe = PE(data, base, image_size, base + entry_rva, timestamp, sections)
    pe.imports = _imports(pe, opt)
    return pe


def _imports(pe: PE, opt: int) -> dict[int, str]:
    """Import address table slot -> the function's name (or DLL ordinal), from the import directory."""
    rva = struct.unpack_from("<I", pe.data, opt + IMPORTS_AT)[0]
    out: dict[int, str] = {}
    if not rva:
        return out
    at = pe.image_base + rva
    for _ in range(MAX_IMPORT_DLLS):
        desc = pe.read(at, IMPORT_DESCRIPTOR_BYTES)
        if len(desc) < IMPORT_DESCRIPTOR_BYTES or desc == bytes(IMPORT_DESCRIPTOR_BYTES):
            break
        lookup, _, _, name_rva, iat = struct.unpack("<IIIII", desc)
        dll = pe.read(pe.image_base + name_rva, DLL_NAME_BYTES).split(b"\0", 1)[0].decode("latin-1")
        lookup = lookup or iat
        for k in range(MAX_IMPORTS_PER_DLL):
            entry = pe.read(pe.image_base + lookup + 4 * k, 4)
            if len(entry) < 4 or not struct.unpack("<I", entry)[0]:
                break
            value = struct.unpack("<I", entry)[0]
            if value & BY_ORDINAL:
                name = f"{Path(dll).stem}_{value & ORDINAL_BITS}"
            else:
                address = pe.image_base + value + IMPORT_HINT_BYTES
                name = pe.read(address, IMPORT_NAME_BYTES).split(b"\0", 1)[0].decode("latin-1")
            out[pe.image_base + iat + 4 * k] = name if _IDENT.fullmatch(name) else f"{Path(dll).stem}_{k}"
        at += IMPORT_DESCRIPTOR_BYTES
    return out


def rich_builds(data: bytes) -> list[tuple[int, int, int]]:
    """(product id, build number, count) of every tool the Rich header says built a part of the program."""
    at = _pe_header(data)
    end = data.find(b"Rich", RICH_START, at)
    if end < 0:
        return []
    key = data[end + 4:end + 8]
    plain = bytes(byte ^ key[i % 4] for i, byte in enumerate(data[RICH_START:end]))
    if not plain.startswith(b"DanS"):
        return []
    out = []
    for entry in range(RICH_ENTRIES_AT, len(plain) - RICH_ENTRY_BYTES + 1, RICH_ENTRY_BYTES):
        comp, count = struct.unpack_from("<II", plain, entry)
        out.append((comp >> 16, comp & 0xFFFF, count))
    return out


def guess_compiler(data: bytes) -> tuple[str, str]:
    """(Visual C++ version, why): what the Rich header's build numbers say, or the default."""
    seen: dict[str, int] = {}
    for _, build, count in rich_builds(data):
        if build in RICH_BUILDS:
            seen[RICH_BUILDS[build]] = seen.get(RICH_BUILDS[build], 0) + count
    if not seen:
        return MSVC_DEFAULT, "the program doesn't say which Visual C++ built it; 6.0 built most games of its time"
    version = max(seen, key=seen.get)
    return version, f"the program's Rich header names Visual C++ {version}'s tools"


def newer_tools(builds: list[tuple[int, int, int]]) -> bool:
    """Whether the Rich header's tools are Visual C++ 2005 or newer: none of the compiler pack's builds, and newer ids."""
    known = any(build in RICH_BUILDS for _, build, _ in builds)
    return not known and any(product >= NEWER_TOOLS_FIRST_PRODUCT for product, _, _ in builds)


def game_info(path: Path) -> dict:
    data = path.read_bytes()
    pe = read_pe(data)
    stem = re.sub(r"[^a-z0-9]+", "", path.stem.lower()) or "game"
    version, why = guess_compiler(data)
    return {"platform": "pc", "id": stem, "title": path.stem, "region": "PC", "sha1": hashlib.sha1(data).hexdigest(),
            "timestamp": pe.timestamp, "compiler": version, "compiler_why": why}


# ---------------------------------------------------------------------------------------------------- analysis


@dataclass
class Function:
    addr: int
    size: int
    name: str  # the symbol, decorated as MSVC decorates the C name
    relocs: list[tuple[int, int, str | None, int]] = field(default_factory=list)  # (offset, type, symbol, addend)
    pad: int = 0  # int3 bytes the linker put after it (Visual C++ 7): not in its section, but no gap between files


def decorate(name: str, convention: str, purge: int, params: int) -> str:
    """The symbol MSVC makes for a C function: _f (__cdecl), _f@8 (__stdcall), @f@8 (__fastcall). __thiscall
    functions (C++ methods, `this` in ecx) are written in C as __fastcall with an unused second argument (edx).
    A purge Ghidra couldn't work out comes as 2147483647 (it made `_func_0001190E@2147483647` on an Xbox program):
    no function pops that many bytes, so it counts as none."""
    if not 0 <= purge <= 0xFFFF:
        purge = 0
    if convention == "__thiscall":
        return f"@{name}@{purge + 8}"
    if convention == "__fastcall":
        return f"@{name}@{purge + 4 * min(max(params, 1), 2)}"
    if purge > 0:
        return f"_{name}@{purge}"
    return f"_{name}"


def _disasm(md, code: bytes, addr: int):
    """Instructions, stopping at bytes that don't decode."""
    return md.disasm(code, addr)


def _tables(md, pe: PE, start: int, code_end: int, limit: int) -> tuple[int, int, list[int]]:
    """(where the function's code ends, where its data ends, the jump table entries' offsets): MSVC puts a switch's
    jump table (and its byte index table) right after the function's code."""
    tables, bytes_at = [], []
    for ins in _disasm(md, pe.read(start, code_end - start), start):
        for op in ins.operands:
            if op.type != x86.X86_OP_MEM or ins.disp_size != 4:
                continue
            disp = op.mem.disp & 0xFFFFFFFF
            if not start < disp < limit or disp <= ins.address:
                continue
            if op.mem.scale == 4 and ins.id == x86.X86_INS_JMP:
                tables.append(disp)
            elif op.size == 1:
                bytes_at.append(disp)
    code_end = min([code_end, *tables, *bytes_at])
    data_end, entries = code_end, []
    for t in sorted(set(tables)):
        at = t
        while at + 4 <= limit:
            value = struct.unpack("<I", pe.read(at, 4).ljust(4, b"\0"))[0]
            if not start <= value < code_end:
                break
            entries.append(at - start)
            at += 4
        data_end = max(data_end, at)
    for b in sorted(set(bytes_at)):
        tail = pe.read(b, limit - b).rstrip(b"\x90\xcc")
        if entries:
            # a byte table indexes the jump table, so every byte is below its entry count: the first one that isn't
            # is past the table (Burnout 3: code that only a vtable reaches followed a byte table and was swallowed)
            n = len(entries)
            stop = next((k for k, v in enumerate(tail) if v >= n), len(tail))
            tail = tail[:stop]
        data_end = max(data_end, b + len(tail))
    return code_end, data_end, entries


def flow_end(md, pe: PE, start: int, limit: int) -> int:
    """Where a function's code ends, by following it: linear disassembly up to a ret, or an unconditional jump, that
    no earlier branch jumps past. A jump out of [start, limit) is a tail call and doesn't extend it, a switch's jump
    table extends it to its furthest case and ends the code (MSVC puts the tables after the code), and an int3 or
    bytes that don't decode end it too. Ghidra's own extent stops short when a function returns in the middle and
    goes on after it (code reached by an earlier jump): taken as the end, the rest became a false start."""
    code = pe.read(start, limit - start)
    reach, table_at, end = start, None, start
    for ins in _disasm(md, code, start):
        if (table_at is not None and ins.address >= table_at) or ins.id == x86.X86_INS_INT3:
            break
        end = ins.address + ins.size
        ops = ins.operands
        imm = bool(ops) and ops[0].type == x86.X86_OP_IMM
        if ins.id == x86.X86_INS_JMP and ops and ops[0].type == x86.X86_OP_MEM and ops[0].mem.scale == 4 \
                and ops[0].mem.base == 0 and start < (ops[0].mem.disp & 0xFFFFFFFF) < limit:
            table = ops[0].mem.disp & 0xFFFFFFFF
            table_at = table if table_at is None else min(table_at, table)
            at = table
            while at + 4 <= limit:
                value = struct.unpack("<I", pe.read(at, 4).ljust(4, b"\0"))[0]
                if not start <= value < table:
                    break
                reach, at = max(reach, value), at + 4
        if imm and x86.X86_GRP_JUMP in ins.groups:
            target = ops[0].imm & 0xFFFFFFFF
            if start < target < limit:
                reach = max(reach, target)
            elif ins.id == x86.X86_INS_JMP and ins.address >= reach:
                break  # a tail call
        if ins.address >= reach and (ins.id in (x86.X86_INS_RET, x86.X86_INS_RETF) or (
                ins.id == x86.X86_INS_JMP and (not imm or ops[0].imm & 0xFFFFFFFF <= ins.address))):
            break  # nothing falls through: a ret, an indirect jump, or a jump back (a loop's or a shared tail)
    return end


def _flow_end(md, pe: PE, start: int, limit: int) -> int:
    """flow_end, reading a small window first and a bigger one only when the code reaches its end: a function's
    surroundings run to the section's end after the last start, and reading all of that for each function found
    there was quadratic."""
    size = 0x1000
    while True:
        stop = min(limit, start + size)
        end = flow_end(md, pe, start, stop)
        if stop >= limit or end < stop - 16:
            return end
        size *= 8


def referenced(pe: PE) -> frozenset[int]:
    """Code addresses something points at the way only function starts are pointed at: `call rel32` targets, and
    words in data sections (vtables, callback tables) or pushed as immediates (callbacks). Jump tables are left out
    on purpose: they sit in the code sections and point at a switch's cases, inside their function.

    It scans the whole image, so it's worked out once per program object (analyse() is called per unit by tools
    that re-analyse a few functions at a time: every call scanned the image again)."""
    key = (id(pe.data), tuple((s.va, s.size, s.offset, s.code) for s in pe.sections))
    cached = pe.__dict__.get("_referenced")
    if cached is not None and cached[0] == key and cached[1] is pe.data:
        return cached[2]
    code = [(s.va, s.va + s.size) for s in pe.sections if s.code]

    def in_code(a: int) -> bool:
        return any(lo <= a < hi for lo, hi in code)

    out: set[int] = set()
    for s in pe.sections:
        data = pe.data[s.offset:s.offset + s.size]
        if s.code:
            for op in (b"\xe8", b"\x68"):
                i = data.find(op)
                while 0 <= i <= len(data) - 5:
                    value = struct.unpack_from("<I", data, i + 1)[0]
                    a = (s.va + i + 5 + value) & 0xFFFFFFFF if op == b"\xe8" else value
                    if in_code(a):
                        out.add(a)
                    i = data.find(op, i + 1)
        else:
            out.update(a for (a,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4]) if in_code(a))
    pe.__dict__["_referenced"] = (key, pe.data, frozenset(out))  # (the data itself: an id can be reused)
    return pe.__dict__["_referenced"][2]


def _whole_instructions(md, pe: PE, start: int, code_end: int, limit: int) -> int:
    """`code_end` moved past the instruction it cuts, if any: Ghidra's body for a function ending in a tail call
    (`jmp` to another function) can stop a byte short of the jmp's end, and the cut byte then decodes as garbage
    on the original's side only (seen in a real Xbox game, against an LTCG harness that matched it)."""
    at = code_end
    for ins in _disasm(md, pe.read(start, limit - start), start):
        if ins.address >= code_end:
            break
        at = ins.address + ins.size
    return max(code_end, min(at, limit))


def _mid_code(pe: PE, value: int, starts, start: int, end: int) -> bool:
    """An immediate that lands inside another function's code: a constant, not an address. Xbox programs load at
    0x10000, so flag masks like `and edx, 0x70000` fall inside .text (seen in a real Xbox game; the LTCG harness,
    comparing numbers, matched where objdiff saw a relocation on one side). A real code address in an immediate is
    a function (a callback) or a label of the function itself."""
    sec = pe.section_at(value)
    return sec is not None and sec.code and value not in starts and not start <= value < end


def analyse(pe: PE, found: list[dict], *, linker_padding: bool = False, sweep: bool = True) -> list[Function]:
    """Every function's extent, name and relocations, from Ghidra's function list.

    A row with `exact` (library code matched byte for byte, scratch_xbe) keeps its extent as given.

    `sweep` (an import's full function list): code after the last row, to its section's end, is looked for missed
    functions too. A caller re-analysing a few functions passes False: the last row then ends with its own code
    and padding (else one call analysed all of a big game's .text after it, function after function).

    Visual C++ 6 pads a function's own section with nops (0x90), so they're part of the function. From Visual C++ 7
    on (Xbox games, PC games of 2002 on) the compiler pads nothing and the linker fills the space up to the next
    function's 16-byte boundary with int3 (0xCC). `linker_padding` (for those programs) records that run as the
    function's `pad`: the compiled section doesn't hold it, so it isn't delinked, but units() doesn't take it for
    the gap between two object files either (with /Gy every function has one). Multi-byte nops inside a function
    (`lea ecx, [ecx]` before a loop) are code, and Ghidra's extent already covers them."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rows: dict[int, dict] = {}
    for r in found:
        s = pe.section_at(r["entry"])
        if r.get("thunk") or s is None or not s.code or pe.offset(r["entry"]) is None:
            continue
        rows[r["entry"]] = r
    starts = sorted(rows)
    refs = referenced(pe)

    def doubtful(addr: int) -> bool:
        """A start nothing vouches for: not the entry point, not named, no call or pointer to it, and not after
        padding (padding only ever comes between functions)."""
        r, sec = rows[addr], pe.section_at(addr)
        return addr != pe.entry and r.get("source") not in ("IMPORTED", "USER_DEFINED", "LIBRARY") and \
            addr not in refs and \
            addr > sec.va and pe.read(addr - 1, 1) not in (b"\xcc", b"\x90")

    i = 0
    extents: dict[int, tuple[int, int, list[int], int]] = {}  # start -> (code end, end, jump table entries, pad)
    while i < len(starts):
        start = starts[i]
        sec = pe.section_at(start)
        # Ghidra makes functions of switch cases it couldn't tie to their switch (Burnout 3: dozens): a doubtful
        # start that this function's own flow runs past is part of it
        while i + 1 < len(starts) and doubtful(starts[i + 1]):
            far = next((s for s in starts[i + 2:] if not doubtful(s)), sec.va + sec.size)
            if _flow_end(md, pe, start, min(far, sec.va + sec.size)) <= starts[i + 1]:
                break
            del rows[starts.pop(i + 1)]
        limit = min(starts[i + 1] if i + 1 < len(starts) else sec.va + sec.size, sec.va + sec.size)
        if not sweep and i + 1 == len(starts):  # a few functions re-analysed: the last one's code and padding, not
            ends = max(_flow_end(md, pe, start, limit), min(rows[start].get("end", start + 1), limit))  # all after it
            at = pe.offset(ends)
            limit = min(limit, ends + (_PADDING.match(pe.data, at, at + 0x100).end() - at if at is not None else 0))
        window = min(limit, start + MAX_FN)  # what's read of the code after it (the last start: not all the rest)
        if rows[start].get("exact"):  # a library function: its size is the library object's, not a guess
            code_end, end, entries = _tables(md, pe, start, min(rows[start]["end"], limit), window)
            end = min(rows[start]["end"], limit)
            code_end = min(code_end, end)
        else:
            code_end = max(start + 1, min(rows[start].get("end", limit), limit), _flow_end(md, pe, start, window))
            code_end = _whole_instructions(md, pe, start, code_end, window)
            if linker_padding:  # Ghidra's body can run over the linker's int3s into a function it missed
                code_end = start + max(1, len(pe.read(start, code_end - start).rstrip(b"\xcc")))
            code_end, end, entries = _tables(md, pe, start, code_end, window)
        # what follows, up to the next start: padding, or code Ghidra missed (found without copying the gap, which
        # runs to the section's end after the last start: copied for every function found in it, that was quadratic)
        off = pe.offset(end) if end < limit else None
        stop = off + min(limit - end, max(0, sec.offset + sec.size - off)) if off is not None else 0
        skip = _PADDING.match(pe.data, off, stop).end() if off is not None else 0
        if off is not None and skip < stop and _NOT_PADDING.search(pe.data, skip, stop):
            # code nobody calls directly (callbacks, vtables) that Ghidra didn't make a function: one of its own,
            # as far as its own flow goes; what follows it (a run of small vtable methods) is looked at in turn
            missed = end + skip - off
            flow = _flow_end(md, pe, missed, min(limit, missed + MAX_FN))
            rows[missed] = {"entry": missed, "end": max(missed + 1, flow), "name": "", "source": "DEFAULT", "purge": 0,
                            "convention": "__cdecl"}
            starts.insert(i + 1, missed)
            limit = missed
            stop = off + (limit - end)
        pad = 0
        if off is not None and stop > off and _NOPS.fullmatch(pe.data, off, stop):
            end = limit  # Visual C++ 6's own padding: part of the compiled function's section too
        elif off is not None and stop > off and linker_padding and _INT3S.fullmatch(pe.data, off, stop):
            pad = stop - off
        extents[start] = (code_end, end, entries, pad)
        i += 1

    names = {}
    for start, r in rows.items():
        base = r.get("name", "")
        named = r.get("source") in ("IMPORTED", "USER_DEFINED") and _IDENT.fullmatch(base) and base != "entry"
        names[start] = decorate(base if named else f"func_{start:08X}", r.get("convention", ""),
                                int(r.get("purge") or 0), int(r.get("params") or 0))

    out = []
    for start in starts:
        code_end, end, entries, pad = extents[start]
        fn = Function(start, end - start, names[start], pad=pad)

        def symbol(addr: int) -> tuple[str | None, int]:
            if start <= addr < end:  # noqa: B023  called within this pass of the loop
                return None, addr - start  # noqa: B023  called within this pass of the loop
            if addr in names:
                return names[addr], 0
            if addr in pe.imports:
                return f"__imp__{pe.imports[addr]}", 0
            return f"_D_{addr:08X}", 0

        for ins in _disasm(md, pe.read(start, code_end - start), start):
            at = ins.address - start
            if ins.size >= 5 and (x86.X86_GRP_JUMP in ins.groups or x86.X86_GRP_CALL in ins.groups) \
                    and ins.operands and ins.operands[0].type == x86.X86_OP_IMM:  # rel32, not a short jump
                target = ins.operands[0].imm & 0xFFFFFFFF
                if not start <= target < end:  # calls, and jumps to other functions (tail calls)
                    name, _ = symbol(target)
                    fn.relocs.append((at + ins.size - 4, REL32, name, 0))
                continue
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and ins.disp_size == 4 and pe.contains(op.mem.disp & 0xFFFFFFFF):
                    name, addend = symbol(op.mem.disp & 0xFFFFFFFF)
                    fn.relocs.append((at + ins.disp_offset, DIR32, name, addend))
                elif op.type == x86.X86_OP_IMM and ins.imm_size == 4 and pe.contains(op.imm & 0xFFFFFFFF) \
                        and not _mid_code(pe, op.imm & 0xFFFFFFFF, names, start, end):
                    name, addend = symbol(op.imm & 0xFFFFFFFF)
                    fn.relocs.append((at + ins.imm_offset, DIR32, name, addend))
        for off in sorted(set(entries)):  # a table two jumps go through is found twice (Burnout 3 has such switches)
            fn.relocs.append((off, DIR32, None, struct.unpack("<I", pe.read(start + off, 4))[0] - start))
        fn.relocs.sort()
        out.append(fn)
    return out


def units(functions: list[Function]) -> dict[str, list[Function]]:
    """Source files: runs of neighbouring functions of about UNIT_BYTES each. A gap between two functions (other
    than the linker's padding, `pad`) is where one object file ended, so a source file never spans one."""
    out: dict[str, list[Function]] = {}
    cur: list[Function] = []
    for fn in functions:
        if cur and (fn.addr + fn.size - cur[0].addr > UNIT_BYTES or fn.addr != cur[-1].addr + cur[-1].size + cur[-1].pad):
            out[f"text_{cur[0].addr:08X}"] = cur
            cur = []
        cur.append(fn)
    if cur:
        out[f"text_{cur[0].addr:08X}"] = cur
    return out


# ---------------------------------------------------------------------------------------------------- the project


def tool_args() -> list[str]:
    """configure.py arguments pointing at decompdecomp's pinned tools."""
    if toolchains.installed("msvc") is None:
        raise ForkError("PC games are built with Microsoft Visual C++, which is proprietary: install it in Setup "
                        "(Visual C++) if you accept that, then try again")
    args = ["--msvc", str(toolchains.path("msvc"))]
    if toolchains.get("wibo").supported and sys.platform != "win32":
        toolchains.ensure("wibo", log=lambda *_: None)
        args += ["--wibo", str(toolchains.binary("wibo"))]
    return args


TYPES_H = """/* Basic types for this decompilation (32-bit x86, Visual C++, written in C++). Agents add structs, classes and
 * prototypes here or in new headers next to it.
 *
 * The game's functions are func_<address> and its data D_<address>: write them as free functions or as a class's
 * methods (`void Town::func_0041B470(int id)`), with the original's calling convention (methods: this in ecx; free
 * functions: __cdecl, __stdcall or __fastcall, as the code shows). The build gives what they compile to the
 * original's symbol names, so any C++ name mangling pairs with the game's code. Data: `extern int D_00402034;`. */
#ifndef COMMON_H
#define COMMON_H

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef __int64 s64;
typedef unsigned __int64 u64;
typedef float f32;
typedef double f64;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#ifndef NULL
#define NULL 0
#endif

#endif
"""


_PROGRAMS: dict[tuple[str, int], object] = {}  # (path, mtime) -> its parsed program, for data_bytes


def _program(root: Path, manifest: dict):
    """The user's copy, parsed once per change of the file (a diff reads several constants from it)."""
    path = root / manifest["game"]["path"]
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _PROGRAMS:
        _PROGRAMS.clear()
        _PROGRAMS[key] = read_program(path.read_bytes(), manifest.get("platform", "pc"))
    return _PROGRAMS[key]


def data_bytes(root: Path, manifest: dict, addr: int, length: int) -> bytes | None:
    """The bytes at an address of the user's copy, or None (not in it, uninitialized, no copy)."""
    try:
        pe = _program(root, manifest)
    except Exception:  # no copy, or one that doesn't parse: the diff goes without values
        return None
    if pe.section_at(addr) is None:
        return None
    data = pe.read(addr, length)
    return data if data and len(data) == length else None


def _named_data(root: Path, manifest: dict, name: str) -> str | None:
    """The D_<address> a real name stands for (functions.json's "names", kept by rename_symbol), or None: a helper
    that renamed a global could no longer read_data it by its name."""
    try:
        info = json.loads((root / "config" / manifest["version"] / "functions.json").read_text(encoding="utf-8"))
    except (OSError, KeyError, ValueError):
        return None
    return next((key for key, real in (info.get("names") or {}).items() if real == name and key.startswith("D_")), None)


def read_program(data: bytes, platform: str) -> PE:
    """The program of a project made here, read by its console's reader: a console whose programs aren't PE files
    reads them into the same shape (`read_program` on the console: the Xbox's XBE)."""
    from .. import get

    reader = getattr(get(platform), "read_program", None)
    return reader(data) if reader is not None else read_pe(data)


def read_data(root: Path, manifest: dict, name: str, length: int = READ_DEFAULT_BYTES) -> str:
    """What read_data shows on a PC or Xbox project: the bytes at a D_<address> (or any address) in the user's copy, the
    addresses its words point to, and a string or floats when it reads as one."""
    m = re.fullmatch(r"_?D_([0-9A-Fa-f]{8})|(?:0x)?([0-9A-Fa-f]{6,8})", name)
    real = None
    if m is None and (key := _named_data(root, manifest, name)) is not None:  # a real name given since
        real, m = name, re.fullmatch(r"D_([0-9A-F]{8})()", key)
    if m is None:
        raise ForkError(f"`{name}` isn't data by address or a real name of data: PC data is named D_<address> "
                        "(D_00402034) until rename_symbol names it")
    addr = int(m.group(1) or m.group(2), 16)
    pe = read_program((root / manifest["game"]["path"]).read_bytes(), manifest.get("platform", "pc"))
    sec = pe.section_at(addr)
    if sec is None:
        raise ForkError(f"0x{addr:08X} isn't in the game's program (it spans 0x{pe.image_base:08X}-"
                        f"0x{pe.image_base + pe.image_size:08X})")
    n = max(READ_MIN_BYTES, min(int(length or READ_DEFAULT_BYTES), READ_MAX_BYTES))
    data = pe.read(addr, n)
    out = [f"{real + ' = ' if real else ''}D_{addr:08X} ({sec.name}+0x{addr - sec.va:X}, {n} bytes)"]
    if not data:
        return out[0] + f": uninitialized data ({sec.name}), zeros at start-up."
    for i in range(0, len(data), HEX_ROW_BYTES):
        chunk = data[i:i + HEX_ROW_BYTES]
        out.append(f"  +0x{i:03X}: {chunk.hex(' '):<47}  {''.join(chr(c) if c in PRINTABLE else '.' for c in chunk)}")
    words = [w for (w,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4])]
    ptrs = [(4 * i, w) for i, w in enumerate(words) if pe.contains(w)]
    if ptrs:
        out.append("pointers in it: " + ", ".join(f"+0x{at:X} -> 0x{w:08X}" for at, w in ptrs[:POINTERS_SHOWN]))
    floats = [struct.unpack("<f", struct.pack("<I", w))[0] for w in words[:FLOATS_SHOWN]]
    smallest, biggest = PLAUSIBLE_FLOAT
    if words and any(smallest < abs(x) < biggest for x in floats):
        out.append("as f32: " + ", ".join(f"{x:g}" for x in floats))
    text = data.split(b"\0", 1)[0]
    if len(text) >= MIN_STRING_CHARS and all(c in PRINTABLE or c in b"\t\n" for c in text) and not (ptrs and ptrs[0][0] == 0):
        out.append(f"as a string: {json.dumps(text.decode('latin-1'))}")
    return "\n".join(out)


def _run(cmd: list[str], root: Path, what: str, log) -> None:
    ok, tail = ForkProject(root).run(cmd, log=log, timeout=TOOL_SECONDS)
    if not ok:
        raise ForkError(f"{what} failed:\n{tail[-ERROR_TAIL:]}")


def check_program(fp: ForkProject, version: str, log=print) -> dict:
    """The project's export (`ninja export`, the template's tools/export.py): the game's program rebuilt with its own
    linker from the matched functions and the rest of the user's copy, compared byte for byte. {"identical",
    "detail", "compiled", "functions"}; a project made before the export existed gets the template's tool first."""
    tool = fp.root / "tools" / "export.py"
    if not tool.exists():  # made by an older decompdecomp: the template's export and its ninja rule
        shutil.copyfile(TEMPLATE / "tools" / "export.py", tool)
        cfg = fp.root / "tools" / "configure.py"
        new = (TEMPLATE / "tools" / "configure.py").read_text(encoding="utf-8")
        old = cfg.read_text(encoding="utf-8")
        if "def linker()" not in old:  # its settings (compiler, flags, LTCG) kept, the rest the template's
            keep = {k: m.group(0) for k in ("MSVC_VERSION", "CL_FLAGS", "LTCG")
                    if (m := re.search(rf"^{k} = .*$", old, re.M))}
            for k, line in keep.items():
                new = re.sub(rf"^{k} = .*$", lambda _, line=line: line, new, count=1, flags=re.M)
            cfg.write_text(new, encoding="utf-8")
        for cmd in (fp.manifest or {}).get("setup", [])[:1]:  # configure again, for the export rule
            fp.run([sys.executable if cmd[0] == "python" else cmd[0], *cmd[1:]], log=log)
    ok, tail = fp.run(["ninja", "export"], log=log, timeout=3600)
    report = fp.root / "build" / version / "export" / "export.json"
    try:
        rep = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"identical": False, "detail": (tail.strip().splitlines() or ["the export failed"])[-1][-300:]}
    detail = f"{rep['compiled_count']} of {rep['functions']} functions from src/; " + \
        ("identical to your copy" if rep["identical"] else "; ".join(rep["differences"][:3]) or "differs")
    return {"identical": bool(rep["identical"] and ok), "detail": detail, "compiled": rep["compiled_count"],
            "functions": rep["functions"]}


def create(root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once. Returns facts about the game."""
    from ...forks import ghidra

    info = game_info(game)
    compiler = (compiler or f"MSVC/{info['compiler']}").removeprefix("MSVC/")
    args = tool_args()
    if not (toolchains.path("msvc") / compiler).is_dir():
        raise ForkError(f"Visual C++ {compiler} isn't in the installed compiler pack")
    if not ghidra.available():
        if ghidra.java_home() is not None and toolchains.installed("jdk") is None:
            log("installing a Java development kit for Ghidra (200 MB, once): this computer has none of its own")
            toolchains.ensure("jdk", log=log)
        if toolchains.installed("ghidra") is None:
            log("installing Ghidra (540 MB, once): it finds the functions in PC programs")
            toolchains.ensure("ghidra", log=log)
    data = game.read_bytes()
    pe = read_pe(data)
    newer = newer_tools(rich_builds(data))
    if newer:
        log("its Rich header names Visual C++ 2005 or newer: decompdecomp builds with 6.0 to 7.1 for now, so expect "
            "little to match")
    log(f"analysing {game.name} with Ghidra (finds every function; a big game takes a few minutes)")
    found = ghidra.functions(game)
    if not found:
        why = ("it was built with Visual C++ 2005 or newer (its Rich header says so), and decompdecomp supports 6.0 "
               "to 7.1 for now" if newer else "a program that is packed or protected (some games' DRM wraps their code) "
               "shows none until it's unpacked")
        raise ForkError(f"Ghidra found no functions in this program: {why}.")
    functions = analyse(pe, found, linker_padding=compiler != "6.0")
    groups = units(functions)
    log(f"{len(functions)} functions; {info['compiler_why']}: Visual C++ {compiler}")
    return write_project(root, game, info=info, compiler=compiler, args=args, pe=pe, groups=groups, log=log)


def write_project(root: Path, game: Path | bytes, *, info: dict, compiler: str, args: list[str], pe: PE,
                  groups: dict[str, list[Function]], platform: str = "pc", suffix: str = ".exe",
                  what: str = "your copy of the game's program (.exe)", cl_flags: list[str] | None = None,
                  set_aside: dict[str, str] | None = None, prepare=None, manifest: dict | None = None,
                  log=print) -> dict:
    """Write the project for analysed functions (the template, the user's program in orig/, functions.json, a source
    file per unit, the manifest) and build it once. Shared by PC and Xbox (scratch_xbe), which differ in the
    program's format, not in the project. `game`: the program's file, or its bytes (an XBE read off a disc image);
    `cl_flags` replace the template's compiler flags; `set_aside`: symbol -> why agents don't get it (library
    code), kept in config/<version>/set_aside.json and read when the project is measured; `prepare(root, units)`
    adds a mode's files and settings before the first build and `manifest` its keys (an Xbox LTCG project, ltcg.py)."""
    version = info["id"]
    shutil.copytree(TEMPLATE, root)
    (root / "orig").mkdir()
    exe = root / "orig" / f"{version}{suffix}"
    if isinstance(game, (bytes, bytearray)):
        exe.write_bytes(game)
    else:
        try:
            exe.hardlink_to(game)
        except OSError:
            shutil.copyfile(game, exe)
    (root / "include").mkdir()
    (root / "include" / "common.h").write_text(TYPES_H, encoding="utf-8")
    cfg = root / "tools" / "configure.py"
    text = cfg.read_text(encoding="utf-8").replace(f'MSVC_VERSION = "{MSVC_DEFAULT}"', f'MSVC_VERSION = "{compiler}"')
    if cl_flags is not None:
        text = re.sub(r"^CL_FLAGS = .*$", lambda _: f"CL_FLAGS = {json.dumps(cl_flags)}", text, count=1, flags=re.M)
    cfg.write_text(text, encoding="utf-8")
    conf = root / "config" / version
    conf.mkdir(parents=True)
    if set_aside:
        (conf / "set_aside.json").write_text(json.dumps(set_aside, indent=1), encoding="utf-8")
    (conf / "functions.json").write_text(json.dumps({
        "exe": f"orig/{version}{suffix}", "sha1": info["sha1"], "image_base": pe.image_base,
        "units": {u: [{"name": f.name, "addr": f.addr, "offset": pe.offset(f.addr), "size": f.size,
                       "relocs": [list(r) for r in f.relocs]} for f in fns] for u, fns in groups.items()},
    }, indent=1), encoding="utf-8")
    for u, fns in groups.items():
        src = root / "src" / "auto" / f"{u}.cpp"  # C++, as PC games of the time were written (C compiles too)
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(f"/* {len(fns)} function{'s' if len(fns) != 1 else ''} from 0x{fns[0].addr:08X} to "
                       f"0x{fns[-1].addr + fns[-1].size:08X}, found by Ghidra. */\n#include \"common.h\"\n",
                       encoding="utf-8")
    log(f"{len(groups)} source files for agents to write into")
    if prepare is not None:  # a mode's own files and settings before the first build (forks/ltcg.py)
        prepare(root, list(groups))

    setup = [[sys.executable, "tools/configure.py", version, *args], ["ninja", "prepare"]]
    for cmd in setup:
        _run(cmd, root, "the first build", log)
    if not (root / "objdiff.json").exists():
        raise ForkError("the first build finished without writing objdiff.json")

    (root / ".decomp.wtf.json").write_text(json.dumps({
        "created": "from scratch", "platform": platform, "version": version, "compiler": f"MSVC/{compiler}",
        "game": {"what": what, "path": f"orig/{version}{suffix}", "sha1": info["sha1"]},
        "setup": [["python", "tools/configure.py", version, *args], ["ninja", "prepare"]],
        **({"set_aside": f"config/{version}/set_aside.json"} if set_aside else {}), **(manifest or {}),
    }, indent=2), encoding="utf-8")
    (root / ".gitignore").write_text("# made from your copy of the game, or by the build\norig/\nbuild/\nbuild.ninja\n"
                                     ".ninja_*\nobjdiff.json\n__pycache__/\n.decomp-wtf/\n", encoding="utf-8")
    (root / "README.md").write_text(f"""# {info['title']} decompilation

Started from scratch with [decompdecomp](https://github.com/n-delic/decompdecomp): the game's functions, found by Ghidra, are cut out of your
copy of its program and compared with what `src/` compiles to, function by function, with objdiff.

1. Put your own copy of the game's program here as `orig/{version}{suffix}` (never commit it).
2. `python tools/configure.py {version} --msvc <Visual C++ folder> [--wibo <wibo>]{" --xdk <your XDK's xbox folder>" if platform == "xbox" else ""}`, then `ninja`.
3. Decompiled code goes in `src/`; `objdiff.json` shows each function's progress in [objdiff](https://github.com/encounter/objdiff).
4. `ninja export` rebuilds the game's program from the matched functions and the rest of your copy, with the game's
   own linker{" (and the XDK's imagebld)" if platform == "xbox" else ""}, and checks it byte for byte:
   `build/{version}/export/export.json` says what came from `src/` and what differs.

Compiler: Visual C++ {compiler} (change `MSVC_VERSION` and `CL_FLAGS` in tools/configure.py if the game was built
with another version or other flags). `config/{version}/functions.json` holds what the analysis found: every
function's address, size, symbol and relocations.
""", encoding="utf-8")
    if shutil.which("git"):
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=decompdecomp", "-c", "user.email=noreply@decompdecomp.invalid", "commit", "-q", "-m",
                     f"Start the {info['title']} decompilation (decompdecomp, Ghidra)"]):
            subprocess.run(cmd, cwd=root, capture_output=True, creationflags=NO_WINDOW)
    return {"platform": platform, "id": version, "title": info["title"], "compiler": f"MSVC/{compiler}",
            "sources": len(groups), "sha1": info["sha1"]}
