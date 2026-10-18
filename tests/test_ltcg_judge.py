"""The LTCG judge on what a whole existing decompilation brought out (an Xbox game's 4,250 harness-matched functions
judged again here): the original's in-image constants, two relocations in one instruction, vtables the game's link
folded, and a callback that names the wrong function. Each runs tools/dll2coff.py on a hand-made DLL and map
against a hand-made original, as test_ltcg.py does."""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

from decompnet.forks import scratch_pe
from decompnet.forks.scratch_pe import DIR32

from .test_ltcg import BASE, TOOLS, _coff, _pe, _tool

dll2coff = _tool("dll2coff")


def _judge(tmp_path: Path, orig: bytes, relocs: list, ours: bytes, sites: list[int], map_lines: list[str],
           data: bytes = bytes(16), extra: dict | None = None) -> tuple[list[tuple[int, str, int, int]], dict]:
    """One function G at 0x11000 in the original (`orig`, with functions.json's `relocs`) and at 0x10001000 in our
    DLL (`ours`, base relocations at `sites`, relative to BASE). Returns our object's relocations (offset, symbol,
    type, inline addend) and G's .ltcg.json entry."""
    exe = orig.ljust(0x40, b"\xcc") + data
    (tmp_path / "game.bin").write_bytes(exe)
    units = {"u": [{"name": "?G@@YAXXZ", "addr": 0x11000, "offset": 0, "size": len(orig), "relocs": relocs}]}
    units.update(extra or {})
    (tmp_path / "functions.json").write_text(json.dumps({"exe": str(tmp_path / "game.bin"),
                                                         "sha1": hashlib.sha1(exe).hexdigest(), "units": units}))
    (tmp_path / "u.dll").write_bytes(_pe([(".text", 0x1000, ours + b"\xcc" * 4), (".data", 0x2000, data)], sites))
    (tmp_path / "u.map").write_text(" Address         Publics by Value              Rva+Base       Lib:Object\n\n"
                                    " 0001:00000000       ?G@@YAXXZ                  10001000 f   a.obj\n"
                                    + "".join(line + "\n" for line in map_lines))
    src = tmp_path / "u.cpp"
    src.write_text("// FUNCTION: 0x11000\nvoid G()\n{\n}\n")
    out = tmp_path / "u.obj"
    subprocess.run([sys.executable, str(TOOLS / "dll2coff.py"), str(tmp_path / "functions.json"), "u",
                    str(tmp_path / "u.dll"), str(tmp_path / "u.map"), str(out), str(src)], check=True, cwd=tmp_path)
    obj = out.read_bytes()
    sections, names = _coff(obj)
    raw_at = struct.unpack_from("<I", obj, 20 + 20)[0]  # the first section's bytes
    got = [(off, names[i], t, struct.unpack_from("<i", obj, raw_at + off)[0]) for off, i, t in sections[0][1]]
    return got, json.loads(out.with_suffix(".ltcg.json").read_text())["functions"]["?G@@YAXXZ"]


def test_a_constant_the_original_relocates_gets_the_same_relocation_on_our_side(tmp_path):
    # cmp eax, [ecx+0xE6C80] (a struct offset); mov dword ptr [g_state], 0x10101 (a flag word): in a program loaded
    # at 0x10000 both numbers fall in the image, so the original's delinker relocated them; ours are plain numbers
    orig = bytes.fromhex("3b81806c0e00" "c705acd57500 01010100" "c3")
    ours = bytes.fromhex("3b81806c0e00" "c70500200010 01010100" "c3")
    relocs = [[2, DIR32, "_D_000E6C80", 0], [8, DIR32, "_D_0075D5AC", 0], [12, DIR32, "_D_00010101", 0]]
    got, side = _judge(tmp_path, orig, relocs, ours, [0x1008], [" 0002:00000000       _g_state                   "
                                                                "10002000     a.obj"])
    assert got == [(2, "_D_000E6C80", DIR32, 0), (8, "_g_state", DIR32, 0), (12, "_D_00010101", DIR32, 0)]
    assert side["constants"] == ["+0x2", "+0xC"] and side["unpaired"] == [] and side["conflicts"] == []
    # a field whose number differs from the original's is left alone: a real difference objdiff shows
    got, side = _judge(tmp_path, orig, relocs, ours.replace(bytes.fromhex("806c0e00"), bytes.fromhex("846c0e00")),
                       [0x1008], [" 0002:00000000       _g_state                   10002000     a.obj"])
    assert [r[0] for r in got] == [8, 12] and side["constants"] == ["+0xC"]
    assert side["unpaired"] == ["+0x2: a relocation in the original only"]


def test_a_second_relocation_in_an_instruction_is_written_as_the_originals(tmp_path):
    # mov dword ptr [g_w+0x28], offset g_x+0x4C: objdiff relates the first relocation and compares the second
    # field's bytes, the addend (0x4C in ours, 0 in the original's D_0073A1D0)
    orig = bytes.fromhex("c705e0e43f00 d0a17300" "c3")
    ours = bytes.fromhex("c70528200010 4c200010" "c3")
    relocs = [[2, DIR32, "_D_003FE4E0", 0], [6, DIR32, "_D_0073A1D0", 0]]
    lines = [" 0002:00000000       ?g_w@@3UW@@A               10002000     a.obj"]
    got, side = _judge(tmp_path, orig, relocs, ours, [0x1002, 0x1006], lines)
    assert got == [(2, "?g_w@@3UW@@A", DIR32, 0x28), (6, "_D_0073A1D0", DIR32, 0)]
    assert side["conflicts"] == [] and side["pairs"] == 2
    # a name that says another original address keeps it, so the data check (and the export) still see it
    lines.append(" 0002:00000040       _D_0073A1D8                10002040     a.obj")
    got, side = _judge(tmp_path, orig, relocs, bytes.fromhex("c70528200010 40200010" "c3"), [0x1002, 0x1006], lines)
    assert got[1] == (6, "_D_0073A1D8", DIR32, 0)
    assert side["data"] == ["+0x6: yours refers to _D_0073A1D8 (0x73A1D8) where the original refers to 0x73A1D0"]


def test_one_original_vtable_folded_where_ours_has_two_is_a_note(tmp_path):
    # mov [esi], offset ??_7A@@6B@; mov [edi], offset ??_7B@@6B@: the game's link folded A's and B's identical
    # vtables into one (0x3B11A0), our harness link keeps two
    orig = bytes.fromhex("c706a0113b00" "c707a0113b00" "c3")
    ours = bytes.fromhex("c70600200010" "c70710200010" "c3")
    relocs = [[2, DIR32, "_D_003B11A0", 0], [8, DIR32, "_D_003B11A0", 0]]
    lines = [" 0002:00000000       ??_7A@@6B@                 10002000     a.obj",
             " 0002:00000010       ??_7B@@6B@                 10002010     a.obj"]
    # an original address the project doesn't list as a vtable (and, here, can't be read as one): a conflict
    _, side = _judge(tmp_path, orig, relocs, ours, [0x1002, 0x1008], lines)
    assert side["folded"] == [] and side["conflicts"] == ["orig 0x3B11A0 -> yours 0x10002000 and 0x10002010"]
    # listed in config/<version>/vtables.csv (or vtables.json): a note, as the LTCG harness has it
    (tmp_path / "vtables.csv").write_text("vtable_va,n_slots\n0x003b11a0,6\n")
    _, side = _judge(tmp_path, orig, relocs, ours, [0x1002, 0x1008], lines)
    assert side["conflicts"] == [] and side["folded"] == ["orig 0x3B11A0 -> yours 0x10002000 and 0x10002010"]
    assert dll2coff.original_vtables(tmp_path / "functions.json") == {0x3B11A0}
    # without vtable names on our side it is the split global the mapping check is for
    plain = [x.replace("??_7A@@6B@", "_g_a      ").replace("??_7B@@6B@", "_g_b      ") for x in lines]
    _, side = _judge(tmp_path, orig, relocs, ours, [0x1002, 0x1008], plain)
    assert side["conflicts"] == ["orig 0x3B11A0 -> yours 0x10002000 and 0x10002010"]
    # unlisted, the original's address counts as a vtable when its first word is one of the game's functions
    names = {0x10002000: ("??_7A@@6B@", 0), 0x10002010: ("??_7B@@6B@", 0), 0x10002020: ("_g_c", 0)}
    fold = dll2coff.vtable_fold(set(), {0x18C470}, {0x3B11A0: 0x18C470, 0x3B2000: 0x3F800000}.get, names.get)
    assert fold(0x3B11A0, 0x10002000, 0x10002010)
    assert not fold(0x3B2000, 0x10002000, 0x10002010) and not fold(0x3B11A0, 0x10002000, 0x10002020)


def test_a_callback_naming_the_function_itself_says_so(tmp_path):
    # push offset G where the original pushes another function (0x11100): a real difference, worded as one
    orig = bytes.fromhex("6800110100" "c3")
    ours = bytes.fromhex("6800100010" "c3")
    _, side = _judge(tmp_path, orig, [[1, DIR32, "_func_00011100", 0]], ours, [0x1001], [])
    assert side["conflicts"] == ["+0x1: yours refers to this function itself, the original to 0x11100"]


def test_two_jump_tables_and_a_byte_table_relocate_each_entry_once():
    # jmp [eax*4+T1] (3 cases), movzx eax, byte [ecx+B]; jmp [eax*4+T2] (2 cases): T1's scan runs on into T2,
    # whose entries are code addresses too; listed twice, objdiff decoded the byte table after them as code
    code = bytes.fromhex("ff2485 1a100010" "0fb681 2e100010" "ff2485 26100010" "c3c3c3c3c3")
    t1 = struct.pack("<3I", BASE + 0x1015, BASE + 0x1016, BASE + 0x1017)
    t2 = struct.pack("<2I", BASE + 0x1018, BASE + 0x1019)
    data = code + t1 + t2 + bytes([0, 1, 1, 0]) + b"\xcc" * 4
    pe = scratch_pe.PE(data, BASE, 0x2000, BASE + 0x1000, 0,
                       [scratch_pe.Section(".text", BASE + 0x1000, len(data), 0, len(data), True)])
    fn = scratch_pe.analyse(pe, [{"entry": BASE + 0x1000, "end": BASE + 0x1032, "name": "", "source": "DEFAULT"}],
                            linker_padding=True, sweep=False)[0]
    offs = [o for o, *_ in fn.relocs]
    assert offs == [3, 10, 17, 0x1A, 0x1E, 0x22, 0x26, 0x2A]  # the tables' addresses, then each entry once
    assert (fn.size, fn.pad) == (0x32, 4)  # the byte table is the function's, the int3s after it aren't
