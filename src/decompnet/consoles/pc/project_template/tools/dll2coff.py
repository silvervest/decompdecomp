#!/usr/bin/env python3
"""Cut a unit's functions out of its LTCG harness DLL into the object objdiff compares with the original's
(tools/ltcg.py says why a game built with /GL and /LTCG needs that), and check that the code refers to the same
things the original refers to.

    python tools/dll2coff.py config/<version>/functions.json UNIT DLL MAP OUT.obj SOURCE...

Which functions: the unit's (config/<version>/functions.json). Each is found in the linker's map by name, as the
annotations in the sources say (`// FUNCTION: 0x<address> [map symbol substring]` before a definition, or
`// TARGET 0x<address> <map symbol substring>` anywhere), else by a func_<address> in its name.

The object is laid out the way tools/delink.py lays out the original's functions, so the two sides follow the same
rules: one section per function, from its first byte to where the next symbol starts, less the linker's int3
padding (MSVC puts a switch's jump table after the function's code, inside it); DIR32 relocations where the DLL's
base relocation table has them (an address inside the function, a jump table and its entries, becomes a label);
REL32 for every call or jump with a 32-bit offset that leaves the function. Functions are named with the original's
symbols, references by the map (func_<address> and D_<address> names as tools/names.py gives them).

objdiff, as decompdecomp runs it, doesn't compare what relocations point at. So this also writes OUT.ltcg.json, an
address mapping check per function: relocation by relocation, the original's target address and ours are paired,
and the pairs must form a one-to-one mapping. A function whose code reads one global where the original reads two
(or swaps two callees used twice each) is 100% in objdiff but fails here, and isn't a match.
It also checks what each reference stands for (`data` in OUT.ltcg.json): a D_<address> or func_<address> name, or a
global annotated `// GLOBAL: 0x<address> [map symbol]` before its declaration, says which original address it means,
and must be the address the original refers to there; floats and strings the compiler made are compared by value.
That catches two globals used once each and swapped, which keeps the mapping one to one.
Needs capstone (decompdecomp's Python has it). Made by decompdecomp.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import delink  # noqa: E402  the original's side: the same object layout
import names  # noqa: E402  func_<address> / D_<address> -> the original's symbols

try:
    import capstone
    from capstone import x86
except ImportError:  # pragma: no cover
    sys.exit("tools/dll2coff.py needs capstone (pip install capstone): decompdecomp's own Python has it")

DIR32, REL32 = delink.DIR32, delink.REL32
# "// FUNCTION: 0x<va> [symbol substring]" then the definition's first line; the symbol never starts with "(".
FUNCTION = re.compile(r"//[ \t]*FUNCTION:[ \t]*(0x[0-9a-fA-F]+)(?:[ \t]+(?!\(|NONMATCHING\b)(\S+))?[^\n]*\n"
                      r"((?:[ \t]*//[^\n]*\n|[ \t]*\n)*)([^\n{;]*\()")
TARGET = re.compile(r"//[ \t]*TARGET[ \t]+(0x[0-9a-fA-F]+)[ \t]+(\S+)")
# "// GLOBAL: 0x<va> [map symbol]" then a declaration or definition of the global at that original address
GLOBAL = re.compile(r"//[ \t]*GLOBAL:[ \t]*(0x[0-9a-fA-F]+)(?:[ \t]+(\S+))?[^\n]*\n"
                    r"((?:[ \t]*//(?![ \t]*GLOBAL:)[^\n]*\n|[ \t]*\n)*)((?![ \t]*//)[^\n;={(\[]*)?")
LITERAL = re.compile(r"__real@([0-9a-fA-F]{8}|[0-9a-fA-F]{16})$")
MAP_LINE = re.compile(r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+(\S+)\s+([0-9a-fA-F]{8})\s")


class Image:
    """The harness DLL: sections, image range and base relocation sites."""

    def __init__(self, data: bytes):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        count, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        self.base, self.size = struct.unpack_from("<I", data, opt + 28)[0], struct.unpack_from("<I", data, opt + 56)[0]
        reloc_rva, reloc_size = struct.unpack_from("<II", data, opt + 96 + 5 * 8)
        self.sections = []  # (name, va, virtual size, file offset, raw size)
        for i in range(count):
            at = opt + opt_size + 40 * i
            name = data[at:at + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, raw_size, raw = struct.unpack_from("<4I", data, at + 8)
            self.sections.append((name, self.base + va, vsize, raw, raw_size))
        self.relocs: set[int] = set()
        if reloc_rva:
            table, o = self.read(self.base + reloc_rva, reloc_size), 0
            while o + 8 <= len(table):
                page, size = struct.unpack_from("<II", table, o)
                if size < 8:
                    break
                for k in range(8, size, 2):
                    e = struct.unpack_from("<H", table, o + k)[0]
                    if e >> 12 == 3:  # IMAGE_REL_BASED_HIGHLOW
                        self.relocs.add(self.base + page + (e & 0xFFF))
                o += size

    def section(self, va: int):
        return next((s for s in self.sections if s[1] <= va < s[1] + max(s[2], s[4])), None)

    def offset(self, va: int) -> int | None:
        s = self.section(va)
        return None if s is None or va - s[1] >= s[4] else s[3] + va - s[1]

    def read(self, va: int, n: int) -> bytes:
        s = self.section(va)
        if s is None:
            return b"\0" * n
        off = va - s[1]
        b = self.data[s[3] + off:s[3] + min(off + n, s[4])]
        return b + b"\0" * (n - len(b))

    def contains(self, va: int) -> bool:
        return self.base <= va < self.base + self.size


class Program:
    """The original program (a PE .exe or an Xbox XBE): its bytes at an address, for comparing literal values."""

    def __init__(self, data: bytes):
        self.data, self.sections = data, []  # (va, size in the file, file offset)
        if data[:4] == b"XBEH":
            base, count, at = struct.unpack_from("<I", data, 0x104)[0], *struct.unpack_from("<II", data, 0x11C)
            for i in range(min(count, 256)):
                _, va, _, offset, raw = struct.unpack_from("<5I", data, at - base + 56 * i)
                self.sections.append((va, raw, offset))
        elif data[:2] == b"MZ":
            img = Image(data)
            self.sections = [(va, raw_size, raw) for _, va, _, raw, raw_size in img.sections]

    def read(self, va: int, n: int) -> bytes | None:
        for start, size, offset in self.sections:
            if start <= va and va + n <= start + size:
                return self.data[offset + va - start:offset + va - start + n]
        return None


def map_symbols(path: Path) -> dict[str, int]:
    """Every symbol of the linker's map (public and static) -> its address."""
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = MAP_LINE.match(line)
        if m and int(m.group(1), 16):
            out.setdefault(m.group(3), int(m.group(4), 16))
    return out


def symbol_hint(decl: str) -> str | None:
    """The map symbol substring for a definition line: `bool Car::IsFast(` -> `?IsFast@Car@@` (MSVC mangles A::B::f
    as ?f@B@A@@ and a free function f as ?f@@). Operators, constructors and destructors need an explicit one."""
    head = decl[:decl.rindex("(")].strip()
    name = re.split(r"[\s*&]+", head)[-1]
    parts = name.split("::")
    last = parts[-1]
    if not last or last.startswith("operator") or last.startswith("~") or (len(parts) > 1 and last == parts[-2]):
        return None
    if re.search(r'extern\s+"C"', decl):
        return None
    return "?" + "@".join([last] + parts[-2::-1]) + "@@"


def annotations(paths: list[Path]) -> tuple[dict[int, str], list[str]]:
    """original address -> map symbol substring, from the sources' FUNCTION and TARGET annotations; and problems."""
    out, problems = {}, []
    for p in paths:
        text = p.read_text(encoding="utf-8", errors="replace")
        for va, sym in TARGET.findall(text):
            out[int(va, 16)] = sym
        for va, sym, _, decl in FUNCTION.findall(text):
            sym = sym or symbol_hint(decl)
            if sym is None:
                problems.append(f"{p}: FUNCTION {va}: give the map symbol after the address (an operator, "
                                "constructor, destructor or extern \"C\" function)")
                continue
            out.setdefault(int(va, 16), sym)
    return out, problems


def global_annotations(paths: list[Path]) -> dict[str, int]:
    """Map symbol (or the declared name) -> original address, from `// GLOBAL: 0x<address> [symbol]` before a
    global's declaration: for globals with real names, which (unlike D_<address>) don't say where they are."""
    out = {}
    for p in paths:
        for va, sym, _, decl in GLOBAL.findall(p.read_text(encoding="utf-8", errors="replace")):
            names_in = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", decl)
            if sym or names_in:
                out.setdefault(sym or names_in[-1], int(va, 16))
    return out


def global_symbol(syms: dict[str, int], name: str) -> str | None:
    """The map symbol of a global declared as `name`: `name` itself, its C name `_name` or its C++ name `?name@...`."""
    if name in syms:
        return name
    cand = [s for s in syms if s == f"_{name}" or s.startswith(f"?{name}@")]
    return cand[0] if len(cand) == 1 else None


def _show(data: bytes, name: str) -> str:
    if name.startswith("__real@") and len(data) == 4:
        return f"{struct.unpack('<f', data)[0]!r}f"
    if name.startswith("__real@") and len(data) == 8:
        return f"{struct.unpack('<d', data)[0]!r}"
    if name.startswith("??_C@_1"):
        return "L" + json.dumps(data.decode("utf-16-le", "replace").rstrip("\0"))
    return json.dumps(data.rstrip(b"\0").decode("latin-1"))


def data_check(fn: dict, exe: bytes, program: Program, ours: list[tuple[int, int, int]], lo: int, hi: int,
               claim, literal) -> dict:
    """What each reference stands for, against what the original's reference at the same place is. objdiff
    passes a function that reads one global where the original reads another (each used once, so the address
    mapping stays one to one), but our references often say which original address they mean: a D_<address> or
    func_<address> name, a `// GLOBAL:` annotation, one of the unit's own functions. Compiler literals (floats,
    strings) are compared by value. `claim(our address)` -> (name, the original address it stands for) or None;
    `literal(our address)` -> (name, its bytes) or None. References that say neither aren't checked."""
    orig = original_targets(fn, exe)
    checked, wrong = 0, []
    for off, _, value in ours:
        theirs = orig.get(off)
        if theirs is None or theirs[1] is None or lo <= value < hi:
            continue
        a = theirs[1]
        if (c := claim(value)) is not None:
            checked += 1
            if c[1] != a:
                wrong.append(f"+0x{off:X}: yours refers to {c[0]} (0x{c[1]:X}) where the original refers to 0x{a:X}")
        elif (lit := literal(value)) is not None:
            checked += 1
            got = program.read(a, len(lit[1]))
            if got != lit[1]:
                was = _show(got, lit[0]) if got is not None else "nothing it can read"
                wrong.append(f"+0x{off:X}: yours loads {_show(lit[1], lit[0])} ({lit[0]}) where the original loads {was} "
                             f"(0x{a:X})")
    return {"data_checked": checked, "data": wrong}


def find_symbol(syms: dict[str, int], want: str) -> tuple[str | None, str]:
    cand = [s for s in syms if want in s]
    if len(cand) > 1 and want in syms:  # an exact name wins over longer names that contain it
        cand = [want]
    if len(cand) == 1:
        return cand[0], ""
    return None, "isn't in the map (not called from the driver, or inlined everywhere)" if not cand else \
        f"is ambiguous in the map: {', '.join(sorted(cand)[:4])}"


def extent(img: Image, start: int, starts: list[int]) -> int:
    """Where the function at `start` ends: the next symbol (or its section's end), less the linker's int3 padding."""
    sec = img.section(start)
    limit = sec[1] + sec[2]
    i = bisect.bisect_right(starts, start)
    if i < len(starts):
        limit = min(limit, starts[i])
    code = img.read(start, limit - start).rstrip(b"\xcc")
    return start + max(1, len(code))


def code_end(md, img: Image, start: int, end: int) -> int:
    """Where the instructions end: the first jump table (`jmp [reg*4 + table]`) or byte index table inside the
    function, as scratch_pe reads the original's (MSVC puts both after the code)."""
    ends = [end]
    for ins in md.disasm(img.read(start, end - start), start):
        for op in ins.operands:
            if op.type != x86.X86_OP_MEM or ins.disp_size != 4:
                continue
            disp = op.mem.disp & 0xFFFFFFFF
            if not start < disp < end or disp <= ins.address:
                continue
            if (op.mem.scale == 4 and ins.id == x86.X86_INS_JMP) or op.size == 1:
                ends.append(disp)
    return min(ends)


def cut(md, img: Image, start: int, end: int, name_of) -> tuple[list, list[str], list[tuple[int, int, int]]]:
    """(relocations in delink.py's form, notes, (offset, type, our target address) for the mapping check)."""
    relocs, notes, targets, seen = [], [], [], set()
    stop = code_end(md, img, start, end)
    for ins in md.disasm(img.read(start, stop - start), start):
        at = ins.address - start
        if (x86.X86_GRP_JUMP in ins.groups or x86.X86_GRP_CALL in ins.groups) and ins.operands \
                and ins.operands[0].type == x86.X86_OP_IMM:
            target = ins.operands[0].imm & 0xFFFFFFFF
            if start <= target < end:
                continue
            if ins.size < 5:
                notes.append(f"+0x{at:X}: a short jump leaves the function (to 0x{target:X}): no relocation can "
                             "say where")
                continue
            off = at + ins.size - 4
            name, addend = name_of(target)
            relocs.append((off, REL32, name, addend))
            targets.append((off, REL32, target))
            seen.add(start + off)
            continue
        for field, size in ((ins.disp_offset, ins.disp_size), (ins.imm_offset, ins.imm_size)):
            if size == 4 and field and img.contains(struct.unpack_from("<I", bytes(ins.bytes), field)[0]) \
                    and ins.address + field not in img.relocs:
                notes.append(f"+0x{at + field:X}: an address-like constant without a base relocation")
    for site in sorted(r for r in img.relocs if start <= r < end - 3):
        if site in seen:
            continue
        off = site - start
        value = struct.unpack("<I", img.read(site, 4))[0]
        if start <= value < end:
            relocs.append((off, DIR32, None, value - start))  # a label: a jump table, its entries
        else:
            name, addend = name_of(value)
            relocs.append((off, DIR32, name, addend))
        targets.append((off, DIR32, value))
    relocs.sort()
    targets.sort()
    return relocs, notes, targets


def original_targets(fn: dict, exe: bytes) -> dict[int, tuple[int, int | None]]:
    """offset -> (type, the original's target address; None inside the function) of its relocations."""
    out = {}
    for off, rtype, name, _ in fn["relocs"]:
        raw = struct.unpack_from("<I", exe, fn["offset"] + off)[0]
        addr = raw if rtype == DIR32 else (fn["addr"] + off + 4 + raw) & 0xFFFFFFFF
        out[off] = (rtype, None if name is None else addr)
    return out


def mapping(fn: dict, exe: bytes, ours: list[tuple[int, int, int]], lo: int, hi: int) -> dict:
    """The harness's address check: relocation by relocation the original's target and ours make a pair; one
    original address must always pair with the same one of ours and the other way round. References inside the
    function (jump tables) are compared by offset."""
    orig = original_targets(fn, exe)
    fwd: dict[int, int] = {}
    back: dict[int, int] = {}
    conflicts, unpaired, pairs = [], [], 0
    for off, rtype, value in ours:
        theirs = orig.pop(off, None)
        if theirs is None:
            unpaired.append(f"+0x{off:X}: a relocation in yours only")
            continue
        a, b = theirs[1], (None if lo <= value < hi else value)
        if (a is None) != (b is None):
            conflicts.append(f"+0x{off:X}: {'inside' if a is None else 'outside'} the function in the original, "
                             f"{'inside' if b is None else 'outside'} it in yours")
            continue
        if a is None:
            continue
        pairs += 1
        if fwd.setdefault(a, b) != b:
            conflicts.append(f"orig 0x{a:X} -> yours 0x{fwd[a]:X} and 0x{b:X}")
        if back.setdefault(b, a) != a:
            conflicts.append(f"yours 0x{b:X} <- orig 0x{back[b]:X} and 0x{a:X}")
    unpaired += [f"+0x{off:X}: a relocation in the original only" for off in sorted(orig)]
    return {"pairs": pairs, "conflicts": sorted(set(conflicts)), "unpaired": unpaired}


def main() -> None:
    config, unit, dll, mapf, out = sys.argv[1:6]
    sources = [Path(p) for p in sys.argv[6:]]
    info = json.loads(Path(config).read_text(encoding="utf-8"))
    exe = Path(info["exe"]).read_bytes()
    if hashlib.sha1(exe).hexdigest() != info["sha1"]:
        sys.exit(f"{info['exe']} isn't the copy this project was made from (its SHA-1 should be {info['sha1']})")
    functions = {fn["addr"]: fn for fn in info["units"][unit]}
    unit_of = {fn["addr"]: u for u, fns in info["units"].items() for fn in fns}
    img = Image(Path(dll).read_bytes())
    syms = map_symbols(Path(mapf))
    wanted = names.wanted(info)
    starts = sorted({a for a in syms.values() if img.section(a) is not None})
    by_addr = sorted((a, s) for s, a in syms.items())
    addrs = [a for a, _ in by_addr]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    hints, problems = annotations(sources)
    for va in sorted(hints):
        if va not in functions:
            where = f"it is in unit {unit_of[va]}" if va in unit_of else "no function starts there"
            problems.append(f"0x{va:08X} ({hints[va]}) isn't one of {unit}'s functions: {where}")
    found: dict[int, tuple[str, int]] = {}  # original address -> (map symbol, our address)
    for addr, fn in functions.items():
        want = hints.get(addr)
        if want is None:
            m = [s for s in syms if re.search(f"func_{addr:08X}(?![0-9A-Fa-f])", s, re.I)]
            if len(m) == 1:
                found[addr] = (m[0], syms[m[0]])
            continue
        sym, why = find_symbol(syms, want)
        if sym is None:
            problems.append(f"0x{addr:08X} {want} {why}")
        else:
            found[addr] = (sym, syms[sym])
    ours_name = {sva: functions[a]["name"] for a, (_, sva) in found.items()}

    def name_of(va: int) -> tuple[str, int]:
        if va in ours_name:
            return ours_name[va], 0
        i = bisect.bisect_right(addrs, va) - 1
        if i < 0:
            return f"$A{va:08X}", 0
        a, s = by_addr[i]
        m = names.REF.search(s.encode())
        if m:
            s = wanted.get(m.group(1) + b"_" + m.group(2).upper(), s.encode()).decode()
        return s, va - a

    program = Program(exe)
    orig_of = {sva: a for a, (_, sva) in found.items()}  # our copy of a unit function -> its original address
    annotated = {}
    for name, va in global_annotations(sources).items():
        if (sym := global_symbol(syms, name)) is not None:
            annotated[sym] = va

    def claim(va: int) -> tuple[str, int] | None:
        if va in orig_of:
            return functions[orig_of[va]]["name"], orig_of[va]
        i = bisect.bisect_right(addrs, va) - 1
        if i < 0:
            return None
        a, s = by_addr[i]
        delta = va - a
        if delta >= 0x1000 or img.section(a) is not img.section(va):
            return None
        shown = s if not delta else f"{s}+0x{delta:X}"
        if s in annotated:
            return shown, annotated[s] + delta
        m = names.REF.search(s.encode())
        return (shown, int(m.group(2), 16) + delta) if m else None

    def literal(va: int) -> tuple[str, bytes] | None:
        i = bisect.bisect_right(addrs, va) - 1
        if i < 0 or by_addr[i][0] != va:
            return None
        s = by_addr[i][1]
        if (m := LITERAL.match(s)) is not None:
            return s, bytes.fromhex(m.group(1))[::-1]
        if s.startswith("??_C@_0") or s.startswith("??_C@_1"):
            raw, wide = img.read(va, 512), s.startswith("??_C@_1")
            step = 2 if wide else 1
            end = next((k for k in range(0, len(raw) - step + 1, step) if raw[k:k + step] == b"\0" * step), None)
            return None if end is None else (s, raw[:end + step])
        return None

    cuts, report = [], {"unit": unit, "dll": dll, "functions": {}, "problems": problems}
    for addr in sorted(found):
        sym, start = found[addr]
        end = extent(img, start, starts)
        relocs, notes, targets = cut(md, img, start, end, name_of)
        fn = functions[addr]
        cuts.append({"name": fn["name"], "addr": addr, "offset": img.offset(start), "size": end - start,
                     "relocs": relocs})
        check = mapping(fn, exe, targets, start, end)
        check |= data_check(fn, exe, program, targets, start, end, claim, literal)
        report["functions"][fn["name"]] = {"orig": f"0x{addr:08X}", "ours": f"0x{start:08X}", "symbol": sym,
                                           "size": end - start, "orig_size": fn["size"], "notes": notes, **check}
    data = delink.coff(cuts, img.data)
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.with_suffix(".ltcg.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    bad = {n: f["conflicts"] for n, f in report["functions"].items() if f["conflicts"]}
    for p in problems:
        print(f"{unit}: {p}")
    for n, c in bad.items():
        print(f"{unit}: {n}: addresses map inconsistently: {'; '.join(c[:4])}")
    for n, f in report["functions"].items():
        if f["data"]:
            print(f"{unit}: {n}: refers to other data than the original: {'; '.join(f['data'][:4])}")


if __name__ == "__main__":
    main()
