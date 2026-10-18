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
from decompnet.consoles.xbox import xboxkrnl, xdvdfs
from decompnet.forks.project import ForkError

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("demo_xbe_build", ROOT / "projects" / "demo-xbe" / "build.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

ENTRY, HELPER, PUSHES = (demo.FUNCTIONS[k] for k in ("entry", "helper", "pushes_global"))


def _ghidra_rows(*starts: int) -> list[dict]:
    """What Ghidra's function list says about the demo (where each function's last instruction ends)."""
    ends = {ENTRY: ENTRY + 0x16, HELPER: HELPER + 0x0D, PUSHES: PUSHES + 0x10}
    return [{"entry": s, "end": ends[s], "name": f"FUN_{s:08x}", "source": "DEFAULT", "convention": "__cdecl",
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


def test_importing_an_xbox_game_says_xbox_projects_arent_finished(tmp_path):
    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    (tmp_path / "ws").mkdir()
    for data, name in ((demo.xbe(), "default.xbe"), (demo.xiso(demo.xbe()), "demo.iso")):
        assert consoles.identify(data) is consoles.get("xbox")
        with pytest.raises(ForkError, match="Xbox projects aren't finished yet"):
            net.import_rom(data, name=name, confirmed=True, log=lambda *_: None)
    assert not any(p.name != ".decomp" for p in (tmp_path / "ws").iterdir())
    assert consoles.get("xbox").status == consoles.BETA


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
