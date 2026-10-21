"""Original Xbox: reading a game's program (XBE) and disc image into the shape the PC path works on.

projects/demo-xbe builds Demo Xbox byte by byte (no compiler, no Microsoft code): three hand-assembled functions that
call each other and two kernel functions through the kernel thunk table, with a certificate and a library version
table, plus XDVDFS disc images holding it. Making an Xbox project isn't finished yet, so the importer reads the game
and then refuses with a message saying so.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from decompnet import consoles, toolchains
from decompnet.app.engine import RomNetwork
from decompnet.consoles.pc import scratch as scratch_pe
from decompnet.consoles.pc.scratch import DIR32, REL32
from decompnet.consoles.xbox import scratch as scratch_xbe
from decompnet.consoles.xbox import xboxkrnl, xdklib, xdvdfs
from decompnet.forks import ghidra
from decompnet.forks.project import ForkError

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("demo_xbe_build", ROOT / "projects" / "demo-xbe" / "build.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

ENTRY, HELPER, PUSHES = (demo.FUNCTIONS[k] for k in ("entry", "helper", "pushes_global"))


def _ghidra_rows(*starts: int) -> list[dict]:
    """What Ghidra's function list says about the demo (where each function's last instruction ends)."""
    ends = {ENTRY: ENTRY + 0x16, HELPER: HELPER + 0x0D, PUSHES: PUSHES + 0x10}
    return [{"entry": s, "end": ends.get(s, s + 1), "name": f"FUN_{s:08x}", "source": "DEFAULT", "convention": "__cdecl",
             "purge": 0, "params": 0} for s in starts]


def test_an_xbe_is_told_apart_from_a_windows_program():
    data = demo.xbe()
    assert scratch_xbe.is_xbe(data[:0x1000]) and not scratch_pe.is_pe(data[:0x1000])
    assert not scratch_xbe.is_xbe(b"MZ" + bytes(0x1000)) and not scratch_xbe.is_xbe(b"XBEH" + bytes(8))
    with pytest.raises(ForkError, match="isn't an original Xbox program"):
        scratch_xbe.read_xbe(b"MZ" + bytes(0x1000))


@pytest.mark.parametrize("keys", ["retail", "debug"])
def test_the_header_sections_and_entry_point_are_read_with_either_key_pair(keys):
    xbe = scratch_xbe.read_xbe(demo.xbe(keys))
    assert xbe.keys == keys
    assert xbe.image_base == 0x10000 and xbe.entry == ENTRY and xbe.kernel_thunk == demo.RDATA
    assert xbe.image_size == demo.DATA + 0x1000 - demo.BASE and xbe.timestamp == 0x41000000
    assert [(s.name, s.va, s.offset, s.code) for s in xbe.sections] == [
        (".text", demo.TEXT, demo.TEXT - demo.BASE, True), (".rdata", demo.RDATA, demo.RDATA - demo.BASE, False),
        (".data", demo.DATA, demo.DATA - demo.BASE, False)]
    assert xbe.read(demo.TEXT, 3) == b"\x55\x8b\xec" and xbe.read(demo.DATA, 4) == b"\x78\x56\x34\x12"
    assert xbe.title == "Demo Xbox" and xbe.title_id == demo.TITLE_ID and xbe.title_code == "DQ-001"


def test_an_entry_point_no_key_decodes_is_refused():
    data = bytearray(demo.xbe())
    data[0x128:0x12C] = (0x00ABCDEF).to_bytes(4, "little")
    with pytest.raises(ForkError, match="retail or debug keys"):
        scratch_xbe.read_xbe(bytes(data))


def test_a_header_pointing_outside_the_file_says_which_field():
    data = bytearray(demo.xbe())
    data[0x120:0x124] = (0x7FFF0000).to_bytes(4, "little")
    with pytest.raises(ForkError, match="section headers"):
        scratch_xbe.read_xbe(bytes(data))


def test_the_library_versions_name_the_xdk_and_its_compiler():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    assert [(lib.name, lib.build, lib.qfe) for lib in xbe.libraries] == [("XAPILIB", 5849, 1), ("XBOXKRNL", 5849, 0)]
    assert scratch_xbe.xdk_build(xbe) == 5849
    assert scratch_xbe.guess_compiler(xbe) == ("7.1", "its libraries come from XDK 5849, which ships Visual C++ 7.1")
    xbe.libraries[0].build = 4627
    version, why = scratch_xbe.guess_compiler(xbe)
    assert version is None and "XDK 4627" in why


def test_kernel_thunk_slots_become_named_imports():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    assert xbe.imports == demo.SLOTS
    assert xboxkrnl.name(187) == "NtClose" and xboxkrnl.name(160) == "KfRaiseIrql" and xboxkrnl.name(370) == "xboxkrnl_370"
    assert xboxkrnl.import_symbol(187) == "__imp__NtClose@4" and xboxkrnl.import_symbol(160) == "__imp_@KfRaiseIrql@4"
    assert xboxkrnl.import_symbol(156) == "__imp__KeTickCount" and xboxkrnl.import_symbol(8) == "__imp__DbgPrint"
    assert len(xboxkrnl.EXPORTS) == 371 and max(xboxkrnl.EXPORTS) == 378 and xboxkrnl.EXPORTS[156] == ("KeTickCount", True)


def test_the_pc_analysis_finds_the_functions_and_their_relocations():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    fns = {f.addr: f for f in scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER, PUSHES))}
    helper, data = f"_func_{HELPER:08X}", f"_D_{demo.GLOBAL:08X}"
    assert fns[ENTRY].relocs == [(4, REL32, helper, 0), (9, DIR32, data, 0), (16, DIR32, "__imp__NtClose", 0)]
    assert fns[HELPER].relocs == [(2, DIR32, "__imp__KeQueryPerformanceCounter", 0), (8, DIR32, data, 0)]
    assert fns[PUSHES].relocs == [(1, DIR32, data, 0), (6, REL32, helper, 0), (12, REL32, f"_func_{ENTRY:08X}", 0)]
    assert fns[PUSHES].size == 0x10


def test_visual_cpp_7_int3_padding_keeps_neighbours_in_one_source_file():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    fns = scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER, PUSHES), linker_padding=True)
    # the int3 run is the linker's, so it isn't in the function's section (nor delinked), only its pad
    assert [(f.addr, f.size, f.pad) for f in fns] == [(ENTRY, 0x16, 0x0A), (HELPER, 0x0D, 0x03), (PUSHES, 0x10, 0)]
    assert list(scratch_pe.units(fns)) == [f"text_{ENTRY:08X}"]


def test_visual_cpp_6_keeps_its_nop_padding_and_splits_at_int3_gaps():
    data = bytearray(demo.xbe())
    at = demo.TEXT - demo.BASE
    data[at + 0x16:at + 0x20] = b"\x90" * 0x0A  # the compiler's nops after entry; helper keeps the linker's int3s
    xbe = scratch_xbe.read_xbe(bytes(data))
    fns = scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER, PUSHES))
    assert [(f.addr, f.size, f.pad) for f in fns] == [(ENTRY, 0x20, 0), (HELPER, 0x0D, 0), (PUSHES, 0x10, 0)]
    # without linker padding an int3 gap is where one object file ended: a new source file starts after it
    assert list(scratch_pe.units(fns)) == [f"text_{ENTRY:08X}", f"text_{PUSHES:08X}"]


def test_code_ghidra_missed_becomes_a_function_of_its_own():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    fns = scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER))
    assert [f.addr for f in fns] == [ENTRY, HELPER, PUSHES]


def test_default_xbe_comes_out_of_an_xiso():
    image, program = demo.xiso(demo.xbe()), demo.xbe()
    assert xdvdfs.layout(image) == "xiso"
    assert {(e.path, e.directory) for e in xdvdfs.entries(image)} == {
        ("default.xbe", False), ("media", True), ("media/readme.txt", False)}
    assert xdvdfs.read_file(image, "DEFAULT.XBE") == program
    assert xdvdfs.read_file(image, "media/readme.txt").startswith(b"Demo Xbox")
    with pytest.raises(ForkError, match="no update.xbe"):
        xdvdfs.read_file(image, "update.xbe")
    with pytest.raises(ForkError, match="isn't an original Xbox disc image"):
        xdvdfs.entries(bytes(0x20000))


def test_default_xbe_comes_out_of_a_redump_image(tmp_path):
    disc = tmp_path / "demo-redump.iso"
    demo.write_redump(disc, demo.xiso(demo.xbe("debug")))
    assert xdvdfs.layout(disc) == "redump" and scratch_xbe.is_xbox(disc)
    info = scratch_xbe.game_info(disc)
    assert (info["platform"], info["title"], info["title_id"], info["keys"], info["xdk"]) == \
        ("xbox", "Demo Xbox", "DQ-001", "debug", 5849)
    assert info["region"] == "North America, Japan, rest of the world"


def test_importing_an_xbox_game_without_its_tools_says_what_to_install(tmp_path, monkeypatch):
    monkeypatch.setenv("DECOMPNET_TOOLCHAINS", str(tmp_path / "none"))
    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    (tmp_path / "ws").mkdir()
    for data, name in ((demo.xbe(), "default.xbe"), (demo.xiso(demo.xbe()), "demo.iso")):
        assert consoles.identify(data) is consoles.get("xbox")
        with pytest.raises(ForkError, match="Visual C\\+\\+ 7.1.*Setup"):
            net.import_rom(data, name=name, confirmed=True, log=lambda *_: None)
    assert not any(p.name != ".decomp" for p in (tmp_path / "ws").iterdir())
    assert consoles.get("xbox").status == consoles.BETA


needs_xbox_tools = pytest.mark.skipif(
    any(toolchains.installed(t) is None for t in ("msvc", "objdiff-cli", "xdk")) or not ghidra.available()
    or (sys.platform != "win32" and not toolchains.installed("wibo") and not toolchains.installed("wibo-xbox")),
    reason="needs Visual C++ (msvc, proprietary), your own XDK set up in Setup, Ghidra, objdiff and wibo")


@needs_xbox_tools
def test_an_xbox_game_becomes_a_project_agents_can_match_in(tmp_path):
    import json
    import subprocess

    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    (tmp_path / "ws").mkdir()
    slug = net.import_rom(demo.xiso(demo.xbe()), name="demo.iso", confirmed=True, log=lambda *_: None)
    ov = net.overview(slug)
    assert ov["kind"] == "fork" and ov["origin"] == "scratch" and ov["platform"] == "xbox" and ov["ready"]
    root = Path(net.project_row(slug)["root"])
    manifest = json.loads((root / ".decomp.wtf.json").read_text())
    assert manifest["platform"] == "xbox" and manifest["game"]["path"] == "orig/demoxbox.xbe"
    assert "--xdk" in manifest["setup"][0]
    config = json.loads((root / "config" / "demoxbox" / "functions.json").read_text())
    # the int3 padding doesn't split them: one source file, functions at their XBE file offsets
    assert list(config["units"]) == [f"text_{ENTRY:08X}"]
    assert [(f["addr"], f["offset"]) for f in config["units"][f"text_{ENTRY:08X}"]] == [
        (a, a - demo.BASE) for a in (ENTRY, HELPER, PUSHES)]
    assert '"/arch:SSE"' in (root / "tools" / "configure.py").read_text()
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
    assert files and not [f for f in files if f.startswith(("orig/", "build/"))]
    # data reads from the XBE
    assert "78 56 34 12" in net.forks.read_data(None, slug, f"D_{demo.GLOBAL:08X}")
    # helper, written in C against the XDK's own kernel declaration, is judged by objdiff
    agent, _ = net.local_agent("xbox-agent")
    helper = f"func_{HELPER:08X}"
    decl = (f'extern "C" __declspec(dllimport) int KeQueryPerformanceCounter(void);\n'
            f'extern "C" int D_{demo.GLOBAL:08X};\n')
    assert net.forks.edit_file(agent, slug, "include/common.h", "", decl, "kernel").startswith("✅")
    res = net.attempt(agent, f"_{helper}", f'extern "C" int {helper}(void) {{\n'
                      f"    return KeQueryPerformanceCounter() + D_{demo.GLOBAL:08X};\n}}\n", slug)
    assert res["matched"], res["text"]


def test_ghidra_gets_the_xbe_as_its_memory_image_with_sections_and_seeds():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    image = scratch_xbe.memory_image(xbe)
    assert len(image) == xbe.image_size and image[:4] == b"XBEH"
    assert image[demo.TEXT - demo.BASE:][:0x40] == demo.text() and image[demo.DATA - demo.BASE:][:4] == bytes.fromhex("78563412")
    # the entry point, and helper (called after int3 padding); pushes_global is called by nobody
    assert scratch_xbe.function_starts(xbe) == [ENTRY, HELPER]
    assert scratch_xbe.ghidra_layout(xbe).splitlines() == [
        "block XBE_HEADERS 10000 11000 rw", "block .text 11000 11040 x", "block .rdata 12000 1200C rw",
        "block .data 13000 13004 rw", f"entry {ENTRY:X}", f"entry {HELPER:X}"]
    # a section set aside (the XDK's own code) stays data: Ghidra doesn't analyse it
    assert "block .text 11000 11040 rw" in scratch_xbe.ghidra_layout(xbe, frozenset({".text"}))


@pytest.mark.skipif(not ghidra.available(), reason="Ghidra (and Java 21) not installed")
def test_ghidra_finds_xbe_functions_without_an_xbe_loader():
    xbe = scratch_xbe.read_xbe(demo.xbe())
    rows = scratch_xbe.find_functions(xbe, "demo.xbe", timeout=900)
    assert {(r["entry"], r["end"]) for r in rows} >= {(ENTRY, ENTRY + 0x16), (HELPER, HELPER + 0x0D)}
    # what Ghidra didn't reach, analyse() still makes a function of its own
    assert [f.addr for f in scratch_pe.analyse(xbe, rows, linker_padding=True)] == [ENTRY, HELPER, PUSHES]


def _coff(name: str, code: bytes, relocs: list[int], machine: int = 0x14C, more: tuple = ()) -> bytes:
    """A COFF object with one code section holding `name` (DIR32 relocations at `relocs`), as /Gy writes them;
    `more`: (name, offset) of further functions in the same section, as an assembler writes them."""
    import struct

    body = code + b"".join(struct.pack("<IIH", at, 1, 6) for at in relocs)
    head = struct.pack("<HHIIIHH", machine, 1, 0, 20 + 40 + len(body), 2 + len(more), 0, 0)
    section = struct.pack("<8sIIIIIIHHI", b".text", 0, 0, len(code), 60, 60 + len(code), 0, len(relocs), 0, 0x60500020)
    symbols = struct.pack("<8sIhHBB", name.encode().ljust(8, b"\0"), 0, 1, 0x20, 2, 0)
    symbols += b"".join(struct.pack("<8sIhHBB", n.encode().ljust(8, b"\0"), at, 1, 0, 2, 0) for n, at in more)
    symbols += struct.pack("<8sIhHBB", b"_D", 0, 0, 0, 2, 0)
    return head + section + body + symbols + struct.pack("<I", 4)


def _archive(members: list[tuple[str, bytes]]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'644':<8}{len(data):<10}`\n".encode() + data + b"\n" * (len(data) & 1)
    return out


def test_xdk_library_code_is_found_by_its_bytes_with_relocations_as_wildcards(tmp_path):
    # a homemade "library": a 20-byte function that loads a global (relocated) and loops, and the same bytes as an
    # LTCG member (compiler intermediate code, machine 0), which is skipped
    fn = bytes.fromhex("8b0d00000000") + bytes.fromhex("33c0400fafc1413bc87cf8c3cc")[:13] + b"\xc3"
    lib = tmp_path / "XMYLIB.LIB"
    lib.write_bytes(_archive([("myfn.obj", _coff("_myfn", fn, [2])), ("ltcg.obj", _coff("_ltcg", fn[::-1], [], 0))]))
    code = b"\xcc" * 16 + bytes.fromhex("8b0d78563412") + fn[6:] + b"\xcc" * 12 + fn[::-1]
    found = xdklib.match([(0x20000, code)], [lib])
    assert list(found) == [0x20010]
    hit = found[0x20010]
    assert (hit.size, hit.symbol, hit.library, hit.member) == (len(fn), "_myfn", "XMYLIB.LIB", "myfn.obj")
    assert hit.reason == "XDK library code: _myfn from XMYLIB.LIB (myfn.obj)"
    # the libraries matched: the ones the version table names and the C runtimes, never LTCG ones
    libs = tmp_path / "lib"
    libs.mkdir()
    for n in ("XMYLIB.lib", "libcmt.lib", "d3d8ltcg.lib", "other.lib"):
        (libs / n).write_bytes(b"")
    assert [p.name for p in xdklib.libraries(libs, ["XMYLIB", "D3D8LTCG"])] == ["XMYLIB.lib", "libcmt.lib"]


def _program(text: bytes, data: bytes = b"") -> scratch_pe.PE:
    """A program holding hand-assembled code at 0x11000 and data at 0x12000, in the shape both readers give."""
    sections = [scratch_pe.Section(".text", 0x11000, len(text), 0x1000, len(text), True),
                scratch_pe.Section(".rdata", 0x12000, max(len(data), 4), 0x2000, len(data), False)]
    raw = bytes(0x1000) + text.ljust(0x1000, b"\xcc") + data
    return scratch_pe.PE(raw, 0x10000, 0x3000, 0x11000, 0, sections)


def _row(entry: int, end: int) -> dict:
    return {"entry": entry, "end": end, "name": f"FUN_{entry:08x}", "source": "DEFAULT", "convention": "__cdecl",
            "purge": 0, "params": 0}


def _starts_and_sizes(pe, rows) -> list[tuple[int, int]]:
    return [(f.addr, f.size) for f in scratch_pe.analyse(pe, rows, linker_padding=True)]


def test_a_function_that_returns_midway_keeps_the_code_after_the_ret():
    # test ecx, ecx; je L; xor eax, eax; ret; L: mov eax, 1; ret -- Ghidra stopped at the first ret and made the
    # rest a function of its own, as it does with switch cases it can't tie to their switch
    text = bytes.fromhex("85c9 7403 33c0 c3 b801000000 c3").ljust(0x10, b"\xcc") + b"\xc3"
    pe = _program(text)
    rows = [_row(0x11000, 0x11007), _row(0x11007, 0x1100D), _row(0x11010, 0x11011)]
    assert _starts_and_sizes(pe, rows) == [(0x11000, 0x0D), (0x11010, 1)]
    # called from somewhere, the same start is a function: shared code, not a false start
    called = bytes.fromhex("85c9 7403 33c0 c3 b801000000 c3").ljust(0x10, b"\xcc") + bytes.fromhex("e8f2ffffff c3")
    assert [a for a, _ in _starts_and_sizes(_program(called), rows)] == [0x11000, 0x11007, 0x11010]


def test_a_purge_ghidra_could_not_work_out_is_no_purge():
    assert scratch_pe.decorate("func_00011000", "__stdcall", 2147483647, 0) == "_func_00011000"
    assert scratch_pe.decorate("func_00011000", "__stdcall", 8, 2) == "_func_00011000@8"


def test_a_run_of_small_methods_ghidra_missed_becomes_one_function_each():
    # or eax, -1; ret | xor eax, eax; ret | mov al, 1; ret: each padded with int3 to 16 bytes, only the first known
    text = b"".join(bytes.fromhex(h).ljust(0x10, b"\xcc") for h in ("83c8ffc3", "33c0c3", "b001c3"))
    assert _starts_and_sizes(_program(text), [_row(0x11000, 0x11004)]) == [(0x11000, 4), (0x11010, 3), (0x11020, 3)]


def test_a_byte_table_ends_at_the_first_byte_past_its_jump_table():
    import struct

    jt, bt = 0x11018, 0x11020
    text = (b"\x0f\xb6\x81" + struct.pack("<I", bt)            # movzx eax, byte [ecx + bt]
            + b"\xff\x24\x85" + struct.pack("<I", jt)          # jmp [eax*4 + jt]
            + bytes.fromhex("b801000000c3 33c0c3 cc")          # case 0, case 1, padding
            + struct.pack("<II", 0x1100E, 0x11014)             # the jump table
            + bytes.fromhex("00010001").ljust(0x10, b"\xcc")   # the byte table, then padding
            + bytes.fromhex("b802000000c3"))                   # a method only a vtable reaches
    fns = scratch_pe.analyse(_program(text), [_row(0x11000, 0x11017)], linker_padding=True)
    assert [(f.addr, f.size) for f in fns] == [(0x11000, 0x24), (0x11030, 6)]
    assert [r for r in fns[0].relocs if r[2] is None and r[0] >= 0x18] == [(0x18, DIR32, None, 0x0E),
                                                                          (0x1C, DIR32, None, 0x14)]


def test_vtables_and_tail_jumps_seed_ghidra_but_a_lone_word_does_not():
    import struct

    text = b"".join(bytes.fromhex(h).ljust(0x10, b"\xcc") for h in ("e93b000000", "33c0c3", "b001c3", "c3", "c3"))
    vtable = struct.pack("<II", 0x11010, 0x11020) + bytes(8) + struct.pack("<I", 0x11030)  # then a lone word
    pe = _program(text, vtable)
    # the entry, the vtable's two methods, and the function the entry tail-jumps to; not the lone word's target
    assert scratch_xbe.function_starts(pe) == [0x11000, 0x11010, 0x11020, 0x11040]
    assert {0x11010, 0x11020, 0x11030} <= scratch_pe.referenced(pe)


def test_library_functions_split_what_ghidra_merged_and_drop_its_starts_inside_them():
    lib = {0x11000: xdklib.LibraryFunction(0x11000, 0x30, "_a", "libcmt.lib", "a.obj"),
           0x11030: xdklib.LibraryFunction(0x11030, 0x10, "_b", "libcmt.lib", "b.obj")}
    rows = [_row(0x11000, 0x11040), _row(0x11010, 0x11020), _row(0x11050, 0x11060)]
    out = scratch_xbe.with_library_code(rows, lib)
    assert [(r["entry"], r["end"], r.get("exact", False)) for r in out] == [
        (0x11000, 0x11030, True), (0x11030, 0x11040, True), (0x11050, 0x11060, False)]
    assert out[1]["source"] == "LIBRARY"
    # analyse() keeps a library function's extent even where its own flow would say otherwise
    text = bytes.fromhex("c3").ljust(0x30, b"\x90") + bytes.fromhex("33c0c3").ljust(0x10, b"\xcc") + b"\xcc" * 0x10
    fns = scratch_pe.analyse(_program(text + b"\xc3"), out, linker_padding=True)
    assert [(f.addr, f.size) for f in fns][:2] == [(0x11000, 0x30), (0x11030, 0x10)]


def test_an_assembly_object_holding_several_functions_is_matched_function_by_function(tmp_path):
    one, two = bytes(range(0x40, 0x54)) + b"\xc3", bytes(range(0x60, 0x74)) + b"\xc3"  # 21 bytes each
    lib = tmp_path / "libcmt.lib"
    lib.write_bytes(_archive([("seh.obj", _coff("_one", one + two, [], more=(("_two", len(one)),)))]))
    assert [(s, len(b)) for s, b, _ in xdklib.code_sections(_coff("_one", one + two, [], more=(("_two", 21),)))] == \
        [("_one", 21), ("_two", 21)]
    # the program links only the second one: matched whole, the section wouldn't fit anywhere
    found = xdklib.match([(0x20000, b"\xcc" * 16 + two + b"\xcc" * 11)], [lib])
    assert [(a, h.symbol, h.size) for a, h in found.items()] == [(0x20010, "_two", 21)]


def test_small_library_functions_are_matched_by_their_whole_bytes_next_to_library_code(tmp_path):
    tiny = bytes.fromhex("33c0c3")  # xor eax, eax; ret: too short to search for
    lib = tmp_path / "libcmt.lib"
    lib.write_bytes(_archive([("tiny.obj", _coff("_tiny", tiny, []))]))
    known = {0x20000: xdklib.LibraryFunction(0x20000, 0x20, "_big", "libcmt.lib", "big.obj")}
    functions = [(0x10000, tiny), (0x10010, b"\xc3"), (0x20000, bytes(0x20)), (0x20020, tiny), (0x20030, tiny + b"\x90")]
    found = xdklib.match_small(functions, [lib], known)
    # next to library code, it's the library's; the same bytes among the game's functions stay the game's
    assert list(found) == [0x20020] and found[0x20020].symbol == "_tiny"


def test_a_kernel_import_stub_is_set_aside_as_library_code():
    import struct

    data = bytearray(demo.xbe())
    at = PUSHES - demo.BASE
    data[at:at + 16] = (b"\xff\x25" + struct.pack("<I", demo.RDATA)).ljust(16, b"\xcc")
    xbe = scratch_xbe.read_xbe(bytes(data))
    fns = [scratch_pe.Function(HELPER, 0x0D, "_h"), scratch_pe.Function(PUSHES, 6, "_stub")]
    assert scratch_xbe.set_aside(xbe, fns, {}, []) == {
        PUSHES: "XDK library code: the linker's stub for the kernel import KeQueryPerformanceCounter"}


def test_twins_fingerprint_coff_objects_and_speak_in_the_names_the_c_writes():
    from decompnet.app import twins

    # mov eax, [global]; ret -- the same code reading two different globals: twins
    a = twins.object_prints(_coff("_fa", bytes.fromhex("a178563412c3"), [1]))
    b = twins.object_prints(_coff("_fb", bytes.fromhex("a1efbeaddec3"), [1]))
    other = twins.object_prints(_coff("_fc", bytes.fromhex("a178563412c20400"), [1]))
    assert list(a) == ["_fa"] and a["_fa"].key == b["_fb"].key
    assert a["_fa"].key != other["_fc"].key and a["_fa"].size == 6
    assert a["_fa"].refs == ["_D"]  # what the relocation names (the helper's one data symbol)
    assert [twins.c_name(s) for s in ("_func_00011000", "@func_00011000@8", "_D_00402034", "__imp__Sleep@4")] == [
        "func_00011000", "func_00011000", "D_00402034", "__imp__Sleep@4"]


def test_xdk_sections_are_set_aside_by_name():
    names = [".text", "XMV", "D3D", "XGRPH", "DSOUND", ".data", "XACTENG", "MYLIB"]
    assert xdklib.library_sections(names, ["XAPILIB", "XACTENG", "D3D8"]) == {"XMV", "D3D", "XGRPH", "DSOUND",
                                                                              "XACTENG"}


LIB = demo.LIBRARY  # xbe(libraries=True): XPP's functions ("d" and "a" called by nobody), its data at demo.TABLE
LIB_FNS = sorted(LIB.values())


def test_library_sections_hold_x86_code_by_evidence_not_by_name():
    """XPP holds x86 code (two of its starts are each called from two places), then data; DOLBY holds another
    processor's program (no call reaches into it, and no XDK library function matches in it): it stays data. A
    library function matched by its bytes is evidence enough on its own."""
    xbe = scratch_xbe.read_xbe(demo.xbe(libraries=True))
    names = frozenset(xdklib.library_sections([s.name for s in xbe.sections], [lib.name for lib in xbe.libraries]))
    assert names == {"XPP", "DOLBY"} and all(s.code for s in xbe.sections if s.name in names)  # (the flags say code)
    sites = scratch_xbe.call_sites(xbe)
    assert sites[LIB["b"]] == {LIB["a"], LIB["c"]} and sites[LIB["c"]] == {LIB["d"] + 5, LIB["a"] + 5}
    assert scratch_xbe.library_code_ends(xbe, names, {}) == {"XPP": demo.TABLE}  # past b's padding: the data
    hit = xdklib.LibraryFunction(demo.DSP, 16, "_f", "x.lib", "x.obj")
    assert scratch_xbe.library_code_ends(xbe, names, {demo.DSP: hit}) == {"XPP": demo.TABLE, "DOLBY": demo.DSP + 16}


def test_the_analysis_sees_a_library_sections_data_and_another_processors_program_as_data():
    xbe = scratch_xbe.read_xbe(demo.xbe(libraries=True))
    view = scratch_xbe.analysis_view(xbe, frozenset({"XPP", "DOLBY"}), {"XPP": demo.TABLE})
    assert [(s.name, s.va, s.size, s.code) for s in view.sections[3:]] == [
        ("XPP", demo.LIB, 0x40, True), ("XPP", demo.TABLE, 0x40, False), ("DOLBY", demo.DSP, 0x40, False)]
    assert view.read(demo.TABLE, 4) == bytes.fromhex("80000000") and xbe.sections[3].size == 0x80  # (a copy)
    layout = scratch_xbe.ghidra_layout(view).splitlines()
    assert {"block XPP 14000 14040 x", "block XPP_2 14040 14080 rw", "block DOLBY 15000 15040 rw"} <= set(layout)
    # seeds: the called starts, never the data; analyse() makes no function of the table, which a sweep would take
    starts = scratch_xbe.function_starts(view)
    assert {LIB["b"], LIB["c"]} <= set(starts) and not [a for a in starts if a >= demo.TABLE]
    fns = scratch_pe.analyse(view, _ghidra_rows(ENTRY, HELPER, LIB["d"], LIB["b"]), linker_padding=True)
    assert [f.addr for f in fns] == [ENTRY, HELPER, PUSHES, *LIB_FNS]
    b = next(f for f in fns if f.addr == LIB["b"])
    assert (b.size, b.relocs) == (6, [(1, DIR32, f"_D_{demo.TABLE:08X}", 0)])
    # the whole section as code: the sweep made functions of the table
    whole = scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER, LIB["d"], LIB["b"]), linker_padding=True)
    assert [f.addr for f in whole if f.addr >= demo.TABLE]


def _importing(tmp_path, monkeypatch, rows):
    """create() as far as writing the project, Ghidra's rows given (`rows`); returns (what's written, Ghidra's calls,
    the log)."""
    game = tmp_path / "default.xbe"
    game.write_bytes(demo.xbe(libraries=True))
    (tmp_path / "msvc" / "7.1").mkdir(parents=True)
    monkeypatch.setattr(scratch_xbe, "tool_args", lambda log: ["--msvc", str(tmp_path / "msvc"), "--xdk", str(tmp_path)])
    monkeypatch.setattr(scratch_xbe.toolchains, "path", lambda name: tmp_path / "msvc")
    monkeypatch.setattr(ghidra, "available", lambda: True)
    calls = []
    monkeypatch.setattr(scratch_xbe, "find_functions", lambda xbe, name, skip=frozenset(): calls.append((xbe, skip))
                        or rows)
    monkeypatch.setattr(scratch_xbe, "library_code", lambda xbe, xdk: ({}, []))
    written, said = {}, []
    monkeypatch.setattr(scratch_pe, "write_project", lambda root, game, **kw: written.update(kw) or {})
    return game, written, calls, said


@pytest.mark.parametrize("scope", ["game", "program"])
def test_every_import_analyses_the_library_sections_with_x86_code_and_sets_them_aside(scope, tmp_path, monkeypatch):
    """Whatever the scope: Ghidra gets XPP's code (its data and DOLBY as data blocks), and XPP's functions get a
    source file of their own and are set aside as the XDK's; the scope only decides that when the project is
    measured. The manifest lists the sections analysed, and never says anything was left out."""
    rows = _ghidra_rows(ENTRY, HELPER, PUSHES, LIB["d"], LIB["b"], demo.TABLE + 4, demo.DSP)  # (two in data)
    game, written, calls, said = _importing(tmp_path, monkeypatch, rows)
    scratch_xbe.create(tmp_path / "p", game, compiler="MSVC/7.1", ltcg=False, scope=scope, log=said.append)
    (view, skip), = calls
    assert skip == frozenset() and [s.name for s in view.sections if not s.code][-2:] == ["XPP", "DOLBY"]
    assert {u: [f.addr for f in fns] for u, fns in written["groups"].items()} == {
        f"text_{ENTRY:08X}": [ENTRY, HELPER, PUSHES], f"xdk_{LIB['d']:08X}": LIB_FNS}
    assert written["set_aside"] == {f.name: "XDK library code: the XPP section" for f in written["groups"][
        f"xdk_{LIB['d']:08X}"]}
    assert written["manifest"]["library_sections"] == ["XPP"] and "set_aside_unimported" not in written["manifest"]
    assert any("XPP (code to 0x00014040)" in s for s in said) and any("no x86 code in DOLBY" in s for s in said)
    # the library code refers to the game's functions by their names: a callback pushed, a tail call
    d = written["groups"][f"xdk_{LIB['d']:08X}"][0]
    assert [r[2] for r in d.relocs] == [f"_func_{ENTRY:08X}", f"_func_{LIB['c']:08X}", f"_func_{HELPER:08X}"]
    assert consoles.get("xbox").sets_aside and consoles.get("xbox").describe()["sets_aside"]


def test_an_ltcg_import_gives_library_units_no_harness_driver(tmp_path, monkeypatch):
    """Library code isn't the game's link-time code generation: its units build as plain units, with no driver."""
    from decompnet.forks import ltcg as ltcg_mode

    game, written, _, _ = _importing(tmp_path, monkeypatch, _ghidra_rows(ENTRY, HELPER, LIB["d"], LIB["b"]))
    scratch_xbe.create(tmp_path / "p", game, compiler="MSVC/7.1", ltcg=True, log=lambda *_: None)
    assert written["prepare"] is ltcg_mode.prepare and written["manifest"]["ltcg"] is True
    root = tmp_path / "proj"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "configure.py").write_text("LTCG = False\n")
    written["prepare"](root, list(written["groups"]))
    assert sorted(p.name for p in (root / "harness").iterdir()) == [f"text_{ENTRY:08X}.drv.cpp"]


def _older_project(root: Path) -> dict:
    """A project as an import before every one analysed the library sections made it: .text's functions only, and
    a manifest saying the library sections were left out."""
    import json

    xbe = scratch_xbe.read_xbe(demo.xbe(libraries=True))
    (root / "orig").mkdir(parents=True)
    (root / "orig" / "demo.xbe").write_bytes(xbe.data)
    fns = scratch_pe.analyse(xbe, _ghidra_rows(ENTRY, HELPER, PUSHES), linker_padding=True)
    fns = [f for f in fns if f.addr < demo.TEXT + 0x1000]
    conf = root / "config" / "demo"
    conf.mkdir(parents=True)
    units = {u: [scratch_pe.function_entry(xbe, f) for f in g] for u, g in scratch_pe.units(fns).items()}
    (conf / "functions.json").write_text(json.dumps({"exe": "orig/demo.xbe", "image_base": xbe.image_base,
                                                     "units": units}, indent=1))
    manifest = {"created": "from scratch", "platform": "xbox", "version": "demo",
                "game": {"path": "orig/demo.xbe"}, "setup": [["python", "tools/configure.py", "demo"]],
                "set_aside_unimported": "the XDK's library sections (DOLBY, XPP)"}
    (root / ".decomp.wtf.json").write_text(json.dumps(manifest))
    return units


def test_an_older_project_gets_the_library_sections_it_lacks_and_keeps_what_it_has(tmp_path, monkeypatch):
    import json

    from decompnet.forks.project import ForkProject

    root = tmp_path / "p"
    units = _older_project(root)
    fp = ForkProject(root)
    xbox = consoles.get("xbox")
    assert scratch_xbe.unanalysed_sections(root, fp.manifest) == ["XPP"]
    assert xbox.unanalysed(fp) == "the XDK's library sections (1 not analysed yet: XPP)"
    monkeypatch.setattr(ghidra, "available", lambda: True)
    monkeypatch.setattr(scratch_xbe, "_xdk_folder", lambda manifest: None)
    calls = []
    rows = _ghidra_rows(ENTRY, LIB["d"], LIB["b"], demo.TABLE + 4)  # (Ghidra's entry point row, one in data)
    monkeypatch.setattr(scratch_xbe, "find_functions", lambda xbe, name, skip=frozenset(): calls.append(skip) or rows)
    said, sections = scratch_xbe.analyse_library_sections(root, log=lambda *_: None)
    assert sections == ["XPP"] and said.startswith("4 functions in the XDK's library sections XPP are in 1 new source "
                                                   "file, set aside")
    assert calls == [frozenset({".text"})]  # Ghidra analyses only the sections it lacks
    info = json.loads((root / "config" / "demo" / "functions.json").read_text())
    assert {u: info["units"][u] for u in units} == units  # what the project had stays as it was
    new = info["units"][f"xdk_{LIB['d']:08X}"]
    assert [f["addr"] for f in new] == LIB_FNS
    # references to the project's own functions name them, as an import of everything at once would
    assert [r[2] for r in new[0]["relocs"]] == [f"_func_{ENTRY:08X}", f"_func_{LIB['c']:08X}", f"_func_{HELPER:08X}"]
    aside = json.loads((root / "config" / "demo" / "set_aside.json").read_text())
    assert aside == {f["name"]: "XDK library code: the XPP section" for f in new}
    assert (root / "src" / "auto" / f"xdk_{LIB['d']:08X}.cpp").read_text().startswith("/* 4 functions from 0x00014000")
    # again: nothing left to bring in
    assert scratch_xbe.analyse_library_sections(root, log=lambda *_: None) == (None, ["XPP"])
    assert scratch_xbe.unanalysed_sections(root, fp.manifest) == []


needs_xbox_build = pytest.mark.skipif(
    any(toolchains.installed(t) is None for t in ("msvc", "objdiff-cli", "xdk"))
    or (sys.platform != "win32" and not toolchains.installed("wibo-xbox")),
    reason="needs Visual C++ (msvc, proprietary), your own XDK set up in Setup, objdiff and wibo-xbox")


@needs_xbox_build
def test_an_older_project_brings_the_library_sections_in_from_settings_keeping_its_matches(tmp_path, monkeypatch):
    """End to end, Ghidra's rows given: a project imported the way older imports did (no library sections), with a
    match; Settings' analysis brings XPP in through reanalyse (configured, built and rebuilt again, committed), set
    aside while the project covers the game's own code, and the match stays."""
    import json
    import subprocess

    monkeypatch.setattr(ghidra, "available", lambda: True)
    rows = _ghidra_rows(ENTRY, HELPER, PUSHES, LIB["d"], LIB["b"])
    monkeypatch.setattr(scratch_xbe, "find_functions", lambda xbe, name, skip=frozenset(): rows)
    ends = scratch_xbe.library_code_ends
    monkeypatch.setattr(scratch_xbe, "library_code_ends", lambda *a: {})  # as older imports: none analysed
    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    (tmp_path / "ws").mkdir()
    slug = net.import_rom(demo.xbe(libraries=True), name="default.xbe", confirmed=True, log=lambda *_: None)
    root = Path(net.project_row(slug)["root"])
    fp = net.forks.get(slug)[1]
    fp.update_manifest(library_sections=None, set_aside_unimported="the XDK's library sections (DOLBY, XPP)")
    monkeypatch.setattr(scratch_xbe, "library_code_ends", ends)
    agent, _ = net.local_agent("xbox-agent")
    helper = f"func_{HELPER:08X}"
    decl = (f'extern "C" __declspec(dllimport) int KeQueryPerformanceCounter(void);\n'
            f'extern "C" int D_{demo.GLOBAL:08X};\n')
    assert net.forks.edit_file(agent, slug, "include/common.h", "", decl, "kernel").startswith("✅")
    res = net.attempt(agent, f"_{helper}", f'extern "C" int {helper}(void) {{\n'
                      f"    return KeQueryPerformanceCounter() + D_{demo.GLOBAL:08X};\n}}\n", slug)
    assert res["matched"], res["text"]
    assert net.overview(slug)["unanalysed"] == "the XDK's library sections (1 not analysed yet: XPP)"

    said = net.forks.analyse_unanalysed(slug, log=lambda *_: None)
    assert said and said.startswith("4 functions in the XDK's library sections XPP"), said
    status = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert status[f"_{helper}"] == "matched"
    assert {status[f"_func_{a:08X}"] for a in LIB_FNS} == {"asm"}  # set aside: the game's own code
    manifest = json.loads((root / ".decomp.wtf.json").read_text())
    assert manifest["library_sections"] == ["XPP"] and "set_aside_unimported" not in manifest
    assert net.overview(slug)["unanalysed"] is None
    log = subprocess.run(["git", "log", "--format=%s", "-1"], cwd=root, capture_output=True, text=True).stdout
    assert log.startswith("Analyse the game again: 4 functions")
    net.forks.set_scope(slug, "program", log=lambda *_: None)
    status = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert {status[f"_func_{a:08X}"] for a in LIB_FNS} == {"open"} and status[f"_{helper}"] == "matched"


class _Forks:
    """forkengine's reanalyse and sync as Xbox.analyse_unanalysed uses them: `outcome` "kept" (the step's change
    stays), "taken back" (the rebuild broke) or "failed" (the step raised)."""

    def __init__(self, root: Path, outcome: str):
        from decompnet.forks.project import ForkProject

        self.fp, self.outcome, self.synced = ForkProject(root), outcome, 0

    def reanalyse(self, slug, step, paths=("config",), fix=False, log=print):
        assert paths == ("config",) and fix
        try:
            said = step(self.fp)
        except ForkError:
            return None
        return said if self.outcome == "kept" else None

    def get(self, slug):
        return None, self.fp, {}

    def sync(self, slug, log=print):
        self.synced += 1


@pytest.mark.parametrize("outcome", ["kept", "taken back", "failed"])
def test_bringing_the_library_sections_in_is_recorded_once_it_is_kept(outcome, tmp_path, monkeypatch):
    import json

    root = tmp_path / "p"
    _older_project(root)
    monkeypatch.setattr(ghidra, "available", lambda: True)
    monkeypatch.setattr(scratch_xbe, "_xdk_folder", lambda manifest: None)
    rows = [] if outcome == "failed" else _ghidra_rows(LIB["d"], LIB["b"])
    monkeypatch.setattr(scratch_xbe, "find_functions", lambda xbe, name, skip=frozenset(): rows)
    net = type("Net", (), {"forks": _Forks(root, outcome)})()
    said = consoles.get("xbox").analyse_unanalysed(net, "p", log=lambda *_: None)
    manifest = json.loads((root / ".decomp.wtf.json").read_text())
    if outcome == "kept":
        assert said.startswith("4 functions") and manifest["library_sections"] == ["XPP"]
        assert "set_aside_unimported" not in manifest and manifest["set_aside"] == "config/demo/set_aside.json"
        assert net.forks.synced == 1  # measured again with the new functions set aside
        assert consoles.get("xbox").unanalysed(net.forks.fp) is None
    else:  # (reanalyse takes the files back itself) Settings goes on offering it
        assert said is None and "library_sections" not in manifest and net.forks.synced == 0
        assert manifest["set_aside_unimported"]


def _fake_xdk(top: Path) -> Path:
    """A folder shaped like an unpacked XDK (empty files with its names: no Microsoft code)."""
    xbox = top / "XDK" / "xbox"
    (xbox / "include").mkdir(parents=True)
    (xbox / "lib").mkdir()
    (xbox / "include" / "XTL.h").write_bytes(b"")
    (xbox / "lib" / "xapilib.lib").write_bytes(b"")
    return xbox


def test_the_xdk_is_the_users_own_folder_checked_and_never_copied(tmp_path, monkeypatch):
    monkeypatch.setenv("DECOMPNET_TOOLCHAINS", str(tmp_path / "tc"))
    xbox = _fake_xdk(tmp_path / "mine")
    tc = toolchains.get("xdk")
    assert tc.local and tc.proprietary and tc.supported and not tc.parts
    with pytest.raises(toolchains.ToolchainError, match="give the folder"):
        toolchains.install("xdk", accept_license=True)
    with pytest.raises(toolchains.ToolchainError, match="proprietary"):
        toolchains.install("xdk", folder=tmp_path / "mine")
    with pytest.raises(toolchains.ToolchainError, match="include/xtl.h"):
        toolchains.install("xdk", accept_license=True, folder=tmp_path)
    with pytest.raises(toolchains.ToolchainError, match="isn't set up"):
        toolchains.local_folder("xdk")
    # the folder above it is fine: the xbox folder inside is found, names compared as Windows compares them
    assert toolchains.install("xdk", accept_license=True, folder=tmp_path / "mine", log=lambda *_: None) == xbox.resolve()
    assert toolchains.local_folder("xdk") == xbox.resolve()
    assert [p.name for p in (tmp_path / "tc" / "xdk").iterdir()] == [toolchains.MANIFEST]  # nothing copied
    row = next(r for r in toolchains.status() if r["id"] == "xdk")
    assert row["installed"] and row["local"] and row["folder"] == str(xbox.resolve())
    (xbox / "lib" / "xapilib.lib").unlink()
    with pytest.raises(toolchains.ToolchainError, match="isn't at"):
        toolchains.local_folder("xdk")


def test_xbox_builds_ask_for_the_xdk_and_take_a_local_wibo_xbox(tmp_path, monkeypatch):
    monkeypatch.setenv("DECOMPNET_TOOLCHAINS", str(tmp_path / "tc"))
    real = toolchains.installed
    monkeypatch.setattr(toolchains, "installed", lambda tid, linux=None: {} if tid == "msvc" else real(tid, linux))
    with pytest.raises(ForkError, match="XDK's headers and libraries.*Setup"):
        scratch_xbe.tool_args()
    toolchains.install("xdk", accept_license=True, folder=_fake_xdk(tmp_path / "mine"), log=lambda *_: None)
    built = tmp_path / "wibo"
    built.write_bytes(b"")
    monkeypatch.setenv("DECOMP_WIBO_XBOX", str(built))
    args = scratch_xbe.tool_args()
    assert args[2:4] == ["--xdk", str((tmp_path / "mine" / "XDK" / "xbox").resolve())]
    if sys.platform != "win32":
        assert args[4:] == ["--wibo", str(built)]
        monkeypatch.setenv("DECOMP_WIBO_XBOX", str(tmp_path / "missing"))
        with pytest.raises(ForkError, match="DECOMP_WIBO_XBOX"):
            scratch_xbe.tool_args()
