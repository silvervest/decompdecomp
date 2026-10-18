"""Build Demo Xbox, a tiny original Xbox program (XBE) written byte by byte here, and Xbox disc images holding it: the
fixture that decompdecomp's Xbox support is tested on without any game or any of Microsoft's code.

Anything linked with the XDK's libraries is Microsoft's, so nothing here is compiled. The program has the shapes a
real XBE has and nothing more:

- the image header, a certificate (title ID DQ-001, "Demo Xbox") and a library version table naming XAPILIB and
  XBOXKRNL from XDK 5849 (names and numbers only: no library code);
- .text with three hand-assembled functions that call each other (call rel32, a tail jmp rel32), read and write a
  global in .data, and call two kernel functions through the kernel thunk table (`call [slot]`);
- .rdata holding the kernel thunk table: KeQueryPerformanceCounter (ordinal 126) and NtClose (187);
- .data with one word.

The entry point and kernel thunk address are stored with the retail keys, or the debug ones (`--debug`), as imagebld
and Microsoft's certification write them. The disc images are XDVDFS: an XISO (filesystem at byte 0) and, with
`--redump`, the layout of a full Redump dump (filesystem at 0x18300000: a 388 MB file, sparse where the filesystem
allows it).

    uv run python projects/demo-xbe/build.py [--debug] [--redump]
        ->  build/demo.xbe, build/demo.iso (XISO) [, build/demo-redump.iso]
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"

BASE = 0x10000
TEXT, RDATA, DATA = 0x11000, 0x12000, 0x13000  # each section's address; its file offset is the address less BASE
KEYS = {"retail": (0xA8FC57AB, 0x5B6D40B6), "debug": (0x94859D4B, 0xEFB1F152)}
KERNEL = [126, 187]  # KeQueryPerformanceCounter, NtClose: the thunk table's slots, in order
TITLE_ID = 0x44510001  # "DQ-001"
REDUMP = 0x18300000
SECTOR = 0x800

# Where each function starts, and the symbols the tests expect decompdecomp to give the code's references.
FUNCTIONS = {"entry": TEXT, "helper": TEXT + 0x20, "pushes_global": TEXT + 0x30}
GLOBAL = DATA
SLOTS = {RDATA: "KeQueryPerformanceCounter", RDATA + 4: "NtClose"}


def _rel32(at: int, size: int, target: int) -> bytes:
    """The rel32 of an instruction `size` bytes long at `at` that branches to `target`."""
    return struct.pack("<i", target - (at + size))


def text() -> bytes:
    """Three functions, padded with int3 to 16 bytes as Visual C++ pads them."""
    entry, helper, pushes = FUNCTIONS["entry"], FUNCTIONS["helper"], FUNCTIONS["pushes_global"]
    code = bytearray()
    code += b"\x55"                                                     # push ebp
    code += b"\x8b\xec"                                                 # mov ebp, esp
    code += b"\xe8" + _rel32(entry + 3, 5, helper)                      # call helper
    code += b"\xa3" + struct.pack("<I", GLOBAL)                         # mov [global], eax
    code += b"\x50"                                                     # push eax
    code += b"\xff\x15" + struct.pack("<I", RDATA + 4)                  # call [NtClose]
    code += b"\x5d"                                                     # pop ebp
    code += b"\xc3"                                                     # ret
    code = code.ljust(helper - TEXT, b"\xcc")
    code += b"\xff\x15" + struct.pack("<I", RDATA)                      # call [KeQueryPerformanceCounter]
    code += b"\x03\x05" + struct.pack("<I", GLOBAL)                     # add eax, [global]
    code += b"\xc3"                                                     # ret
    code = code.ljust(pushes - TEXT, b"\xcc")
    code += b"\x68" + struct.pack("<I", GLOBAL)                         # push offset global
    code += b"\xe8" + _rel32(pushes + 5, 5, helper)                     # call helper
    code += b"\x59"                                                     # pop ecx
    code += b"\xe9" + _rel32(pushes + 11, 5, entry)                     # jmp entry (a tail call)
    return bytes(code.ljust(0x40, b"\xcc"))


def xbe(keys: str = "retail") -> bytes:
    """The program: headers in the first 0x1000 bytes, then one 0x1000-byte page per section."""
    entry_key, thunk_key = KEYS[keys]
    head = bytearray(0x1000)
    cert, sections_at, names_at, libs_at, strings_at = 0x184, 0x360, 0x400, 0x440, 0x480
    sections = [(".text", 0x6, TEXT, text()),                                                   # executable, preload
                (".rdata", 0x2, RDATA, b"".join(struct.pack("<I", 0x80000000 | o) for o in KERNEL) + bytes(4)),
                (".data", 0x3, DATA, struct.pack("<I", 0x12345678))]                            # writable, preload
    head[0:4] = b"XBEH"
    struct.pack_into("<6I", head, 0x104, BASE, 0x1000, DATA + 0x1000 - BASE, 0x184, 0x41000000, BASE + cert)
    struct.pack_into("<3I", head, 0x11C, len(sections), BASE + sections_at, 0x5)  # count, headers, init flags
    struct.pack_into("<I", head, 0x128, FUNCTIONS["entry"] ^ entry_key)
    struct.pack_into("<I", head, 0x130, 0x10000)  # stack commit
    struct.pack_into("<3I", head, 0x14C, BASE + strings_at, BASE + strings_at + 12, BASE + strings_at + 24)
    struct.pack_into("<I", head, 0x158, RDATA ^ thunk_key)
    struct.pack_into("<4I", head, 0x160, 2, BASE + libs_at, BASE + libs_at + 16, BASE + libs_at)
    struct.pack_into("<2I", head, 0x170, BASE + strings_at + 64, 0)  # logo: none
    head[strings_at:strings_at + 11] = b"D:\\demo.exe"
    head[strings_at + 12:strings_at + 20] = b"demo.exe"
    head[strings_at + 24:strings_at + 40] = "demo.exe".encode("utf-16-le")

    struct.pack_into("<3I", head, cert, 0x1D0, 0x41000000, TITLE_ID)
    title = "Demo Xbox".encode("utf-16-le")
    head[cert + 0x0C:cert + 0x0C + len(title)] = title
    struct.pack_into("<4I", head, cert + 0x9C, 0x80000002, 0x7, 0, 0)  # media types, regions (all three), ratings
    struct.pack_into("<I", head, cert + 0xAC, 1)  # version

    name_at = names_at
    for i, (name, flags, va, raw) in enumerate(sections):
        struct.pack_into("<6I", head, sections_at + 56 * i, flags, va, len(raw), va - BASE, len(raw), BASE + name_at)
        head[name_at:name_at + len(name)] = name.encode("ascii")
        name_at += len(name) + 1
    for i, (lib, flags) in enumerate((("XAPILIB", 0x4001), ("XBOXKRNL", 0x4000))):
        at = libs_at + 16 * i
        head[at:at + len(lib)] = lib.encode("ascii")
        struct.pack_into("<4H", head, at + 8, 1, 0, 5849, flags)

    out = bytearray(head)
    for _, _, va, raw in sections:
        out = out.ljust(va - BASE, b"\0") + raw
    return bytes(out)


def _entry(name: str, sector: int, size: int, attrs: int, right: int) -> bytes:
    raw = struct.pack("<HHIIBB", 0, right, sector, size, attrs, len(name)) + name.encode("latin-1")
    return raw.ljust((len(raw) + 3) & ~3, b"\xff")


def _directory(files: list[tuple[str, int, int, int]]) -> bytes:
    """A directory's sector: its entries chained through their right children in uppercase-name order (a valid,
    if lopsided, binary tree), the rest padded with 0xFF as mastering tools pad it."""
    out = bytearray()
    files = sorted(files, key=lambda f: f[0].upper())
    sizes = [len(_entry(n, 0, 0, 0, 0)) for n, *_ in files]
    for i, (name, sector, size, attrs) in enumerate(files):
        right = (len(out) + sizes[i]) // 4 if i + 1 < len(files) else 0
        out += _entry(name, sector, size, attrs, right)
    return bytes(out.ljust(SECTOR, b"\xff"))


def xiso(program: bytes) -> bytes:
    """An XISO: the volume descriptor at 0x10000, the root directory (default.xbe and a media folder holding a
    readme) and the files after it."""
    root, media, readme_at, xbe_at = 33, 34, 35, 36
    readme = b"Demo Xbox: decompdecomp's homemade Xbox fixture.\n"
    out = bytearray(xbe_at * SECTOR)
    desc = 32 * SECTOR
    out[desc:desc + 20] = b"MICROSOFT*XBOX*MEDIA"
    struct.pack_into("<II", out, desc + 0x14, root, SECTOR)
    out[desc + 0x7EC:desc + 0x800] = b"MICROSOFT*XBOX*MEDIA"
    out[root * SECTOR:(root + 1) * SECTOR] = _directory([("default.xbe", xbe_at, len(program), 0x20),
                                                         ("media", media, SECTOR, 0x10)])
    out[media * SECTOR:(media + 1) * SECTOR] = _directory([("readme.txt", readme_at, len(readme), 0x20)])
    out[readme_at * SECTOR:readme_at * SECTOR + len(readme)] = readme
    out += program
    return bytes(out.ljust((len(out) + SECTOR - 1) // SECTOR * SECTOR, b"\0"))


def write_redump(path: Path, image: bytes) -> None:
    """The XISO's filesystem placed where a full Redump dump has it, after a video partition left as zeros (seeking
    past them keeps the file sparse where the filesystem allows it)."""
    with open(path, "wb") as f:
        f.seek(REDUMP)
        f.write(image)


def main() -> None:
    keys = "debug" if "--debug" in sys.argv else "retail"
    BUILD.mkdir(exist_ok=True)
    program = xbe(keys)
    (BUILD / "demo.xbe").write_bytes(program)
    image = xiso(program)
    (BUILD / "demo.iso").write_bytes(image)
    print(f"built build/demo.xbe ({len(program)} bytes, {keys} keys) and build/demo.iso ({len(image)} bytes, XISO)")
    if "--redump" in sys.argv:
        write_redump(BUILD / "demo-redump.iso", image)
        print("built build/demo-redump.iso (Redump layout)")


if __name__ == "__main__":
    main()
