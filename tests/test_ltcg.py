"""Link-time code generation (LTCG): games built with /GL and /LTCG, judged through a harness link.

A /GL object holds the compiler's intermediate code, so the project links each unit with a driver and stand-ins into
a DLL with /LTCG (the template's tools/ltcg.py), and tools/dll2coff.py cuts the unit's functions back out into the
object objdiff compares, with an address mapping check objdiff doesn't make. The unit tests here run dll2coff on a
hand-made DLL; the end-to-end test builds a homemade two-file program with the XDK's compiler and linker, where the
linker passes an argument in a register, and runs only where Visual C++, your XDK, objdiff and wibo-xbox are set up.
"""

import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.forks import ltcg, objdiff, scratch_pe, scratch_xbe
from decompnet.forks.scratch_pe import DIR32, REL32

TOOLS = Path(scratch_pe.__file__).with_name("pc_template") / "tools"


def _tool(name: str):
    sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(f"template_{name}", TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dll2coff = _tool("dll2coff")
template_ltcg = _tool("ltcg")

BASE = 0x10000000
# Ours (the harness DLL): F1 reads g_a twice and calls F2; F2 reads a D_ global and switches through a jump table.
F1 = bytes.fromhex("a1 00200010" "03 05 00200010" "e8 10000000" "c3")  # call: 0x1000100b + 5 + 0x10 = 0x10001020
F2 = bytes.fromhex("8b 0d 04200010" "ff 24 85 30100010" "c3" "c3" "90" "2d100010" "2e100010")
RELOC_SITES = [0x1001, 0x1007, 0x1022, 0x1029, 0x1030, 0x1034]
MAP = """ Address         Publics by Value              Rva+Base       Lib:Object

 0001:00000000       ?F1@@YAHXZ                 10001000 f   a.obj
 0001:00000020       ?F2@@YAHH@Z                10001020 f   a.obj
 0002:00000000       ?g_a@@3HA                  10002000     a.obj
 0002:00000004       _D_00030004                10002004     a.obj
"""


def _pe(sections: list[tuple[str, int, bytes]], relocs: list[int]) -> bytes:
    """A minimal PE32 DLL at BASE: the fields dll2coff reads, the sections, and a base relocation table (`relocs`:
    the relocated words' addresses relative to BASE)."""
    pages: dict[int, list[int]] = {}
    for r in relocs:
        pages.setdefault(r & ~0xFFF, []).append(r & 0xFFF)
    table = b""
    for page, offs in sorted(pages.items()):
        entries = b"".join(struct.pack("<H", 0x3000 | o) for o in offs) + (b"\0\0" if len(offs) % 2 else b"")
        table += struct.pack("<II", page, 8 + len(entries)) + entries
    sections = [*sections, (".reloc", 0x1000 * (len(sections) + 1), table)]
    count = len(sections)
    head = bytearray(0x400)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, 0x44, 0x14C, count, 0, 0, 0, 0xE0, 0x2102)
    opt = 0x58
    struct.pack_into("<H", head, opt, 0x10B)
    struct.pack_into("<I", head, opt + 28, BASE)
    struct.pack_into("<I", head, opt + 56, 0x1000 * (count + 1))
    struct.pack_into("<I", head, opt + 92, 16)
    struct.pack_into("<II", head, opt + 96 + 5 * 8, sections[-1][1], len(table))
    body = bytearray()
    for i, (name, rva, data) in enumerate(sections):
        raw = 0x400 + len(body)
        struct.pack_into("<8sIIII", head, opt + 0xE0 + 40 * i, name.encode(), len(data), rva, 0x200, raw)
        body += data.ljust(0x200, b"\0")
    return bytes(head) + bytes(body)


def _dll() -> bytes:
    text = F1 + b"\xcc" * (0x20 - len(F1)) + F2 + b"\xcc" * 8
    return _pe([(".text", 0x1000, text), (".data", 0x2000, bytes(8))], RELOC_SITES)


def _project(tmp_path: Path, second_global: int = 0x30000) -> tuple[Path, dict]:
    """The original (its bytes and functions.json, as scratch_pe would write them) and the harness DLL and map."""
    f1 = bytes.fromhex("a1 00000300" "03 05") + struct.pack("<I", second_global) + bytes.fromhex("e8 10000000 c3")
    f2 = bytes.fromhex("8b 0d 04000300" "ff 24 85 30100100" "c3" "c3" "90" "2d100100" "2e100100")
    exe = (f1 + b"\xcc" * (0x20 - len(f1)) + f2).ljust(0x40, b"\xcc")  # F1 at 0x11000, F2 at 0x11020
    (tmp_path / "game.bin").write_bytes(exe)
    info = {"exe": str(tmp_path / "game.bin"), "sha1": __import__("hashlib").sha1(exe).hexdigest(), "units": {"u": [
        {"name": "?F1@@YAHXZ", "addr": 0x11000, "offset": 0, "size": len(f1), "relocs": [
            [1, DIR32, "_D_00030000", 0], [7, DIR32, f"_D_{second_global:08X}", 0], [12, REL32, "?F2@@YAHH@Z", 0]]},
        {"name": "?F2@@YAHH@Z", "addr": 0x11020, "offset": 0x20, "size": 0x18, "relocs": [
            [2, DIR32, "_D_00030004", 0], [9, DIR32, None, 0x10], [0x10, DIR32, None, 0x0D], [0x14, DIR32, None, 0x0E]]},
    ]}}
    (tmp_path / "functions.json").write_text(json.dumps(info))
    (tmp_path / "u.dll").write_bytes(_dll())
    (tmp_path / "u.map").write_text(MAP)
    src = tmp_path / "u.cpp"
    src.write_text("// FUNCTION: 0x11000\nint F1()\n{ return 0; }\n\n// FUNCTION: 0x11020\nint F2(int x)\n{ return x; }\n")
    return src, info


def _run_dll2coff(tmp_path: Path, src: Path) -> tuple[bytes, dict]:
    out = tmp_path / "u.obj"
    subprocess.run([sys.executable, str(TOOLS / "dll2coff.py"), str(tmp_path / "functions.json"), "u",
                    str(tmp_path / "u.dll"), str(tmp_path / "u.map"), str(out), str(src)], check=True, cwd=tmp_path)
    return out.read_bytes(), json.loads(out.with_suffix(".ltcg.json").read_text())


def _coff(data: bytes) -> tuple[list[tuple[int, list[tuple[int, int, int]]]], list[str]]:
    """(sections: (size, [(offset, symbol index, type)]), symbol names) of a COFF object."""
    count, sym_at, nsyms = struct.unpack_from("<HxxxxII", data, 2)
    strings = sym_at + 18 * nsyms
    names = []
    for i in range(nsyms):
        raw = data[sym_at + 18 * i:sym_at + 18 * i + 8]
        if raw[:4] == b"\0\0\0\0":
            off = strings + struct.unpack_from("<I", raw, 4)[0]
            names.append(data[off:data.index(b"\0", off)].decode())
        else:
            names.append(raw.rstrip(b"\0").decode())
    sections = []
    for i in range(count):
        size, raw, rel_at, _, nrel = struct.unpack_from("<IIIIH", data, 20 + 40 * i + 16)
        sections.append((size, [struct.unpack_from("<IIH", data, rel_at + 10 * k) for k in range(nrel)]))
    return sections, names


def test_functions_are_cut_from_the_dll_by_their_annotations_with_the_originals_layout(tmp_path):
    src, _ = _project(tmp_path)
    data, report = _run_dll2coff(tmp_path, src)
    sections, names = _coff(data)
    # one section per function, from its symbol to the next less the int3 padding; the jump table stays inside F2
    assert [s for s, _ in sections] == [len(F1), 0x18]
    f1 = [(off, names[i], t) for off, i, t in sections[0][1]]
    assert f1 == [(1, "?g_a@@3HA", DIR32), (7, "?g_a@@3HA", DIR32), (12, "?F2@@YAHH@Z", REL32)]
    f2 = [(off, names[i], t) for off, i, t in sections[1][1]]
    # the table's address and its entries are labels inside the function, named as tools/delink.py names them
    assert f2 == [(2, "_D_00030004", DIR32), (9, "$L00011030", DIR32), (0x10, "$L0001102D", DIR32),
                  (0x14, "$L0001102E", DIR32)]
    assert names[:2] == ["?F1@@YAHXZ", "?F2@@YAHH@Z"]  # the original's symbols, so objdiff pairs them
    assert report["functions"]["?F1@@YAHXZ"]["conflicts"] == [] and report["functions"]["?F1@@YAHXZ"]["pairs"] == 3
    assert report["functions"]["?F2@@YAHH@Z"]["conflicts"] == [] and report["problems"] == []


def test_a_split_global_fails_the_address_mapping_check_objdiff_would_pass(tmp_path):
    # the original reads two globals where ours reads one twice: same instructions, different meaning
    src, _ = _project(tmp_path, second_global=0x30008)
    _, report = _run_dll2coff(tmp_path, src)
    assert report["functions"]["?F1@@YAHXZ"]["conflicts"] == ["yours 0x10002000 <- orig 0x30000 and 0x30008"]
    base = tmp_path / "u.obj"
    found = objdiff.mapping_conflicts(base, "?F1@@YAHXZ")
    assert [m.describe() for m in found] == ["yours 0x10002000 <- orig 0x30000 and 0x30008"]
    assert objdiff.mapping_conflicts(base, "?F2@@YAHH@Z") == []


def test_a_function_the_map_lacks_is_reported_and_left_out(tmp_path):
    src, _ = _project(tmp_path)
    src.write_text(src.read_text().replace("int F2(int x)", "int Missing(int x)"))
    data, report = _run_dll2coff(tmp_path, src)
    assert len(_coff(data)[0]) == 1
    assert report["problems"] == ["0x00011020 ?Missing@@ isn't in the map (not called from the driver, or inlined "
                                  "everywhere)"]


def test_annotations_name_map_symbols_and_constructors_need_an_explicit_one(tmp_path):
    p = tmp_path / "a.cpp"
    p.write_text("// FUNCTION: 0x100\nvoid Car::Drive(int)\n{}\n// FUNCTION: 0x200\nCar::Car()\n{}\n"
                 "// FUNCTION: 0x300 ??0Car@@QAE@XZ\nCar::Car(int)\n{}\n// TARGET 0x400 _Free\n")
    hints, problems = dll2coff.annotations([p])
    assert hints == {0x100: "?Drive@Car@@", 0x300: "??0Car@@QAE@XZ", 0x400: "_Free"}
    assert len(problems) == 1 and "FUNCTION 0x200" in problems[0]


def test_a_unit_joins_harness_mode_once_its_driver_defines_harness_entry(tmp_path):
    h = tmp_path / "harness"
    h.mkdir()
    (h / "u.drv.cpp").write_text(ltcg.DRIVER.format(unit="u"))
    (h / "u.standins.cpp").write_text('// HARNESS-LINK: d3d8ltcg.lib /d2:"-inlT56"\n')
    (h / "u2.drv.cpp").write_text("")
    driver, extras = template_ltcg.harness_files("u", h)
    assert extras == [h / "u.standins.cpp"]
    assert not template_ltcg.has_entry(driver)  # the skeleton's entry is commented out
    driver.write_text('extern "C" __declspec(dllexport) void HarnessEntry(int *p)\n{\n}\n')
    assert template_ltcg.has_entry(driver)
    assert template_ltcg.link_flags([driver, *extras]) == ["d3d8ltcg.lib", "/d2:-inlT56"]


def _xdk_tools() -> tuple[Path, Path, Path | None] | None:
    """(Visual C++ pack, the user's XDK folder, wibo-xbox or None on Windows), or None when any is missing."""
    try:
        xdk = toolchains.local_folder("xdk")
    except toolchains.ToolchainError:
        return None
    if toolchains.installed("msvc") is None or toolchains.installed("objdiff-cli") is None:
        return None
    wibo = None
    if sys.platform != "win32":
        if not toolchains.installed("wibo-xbox"):
            return None
        wibo = toolchains.binary("wibo-xbox")
    return toolchains.path("msvc"), xdk, wibo


needs_ltcg_tools = pytest.mark.skipif(_xdk_tools() is None, reason="needs Visual C++ (msvc, proprietary), your own XDK "
                                      "set up in Setup, objdiff and (off Windows) wibo-xbox")

# The homemade game: Accumulate is only called from Entry, in another file, so the linker gives it a convention of
# its own (with /GL, an argument arrives in a register); the original's two files are linked with /LTCG like a game.
GAME_LIB = """volatile int g_total;
volatile int g_count;
volatile int g_last;

int Accumulate(int *values, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++)
        s += values[i] * 3;
    g_total += s;
    g_count++;
    g_last = g_total;
    return s;
}
"""
GAME_MAIN = """int Accumulate(int *values, int n);

extern "C" __declspec(dllexport) int Entry(int *v)
{
    return Accumulate(v, 4) + Accumulate(v + 4, 2);
}
"""


def _xdk_run(wibo: Path | None, exe: Path, args: list[str], cwd: Path) -> None:
    res = subprocess.run([*([str(wibo)] if wibo else []), str(exe), *args], cwd=cwd, capture_output=True, text=True,
                         errors="replace", timeout=300)
    assert res.returncode == 0, res.stdout + res.stderr


def _original(tmp_path: Path, msvc: Path, xdk: Path, wibo: Path | None) -> tuple[Path, int, int]:
    """The homemade game linked like an LTCG game: (its DLL, Accumulate's address, its size less padding)."""
    work = tmp_path / "orig"
    work.mkdir()
    (work / "lib.cpp").write_text(GAME_LIB)
    (work / "main.cpp").write_text(GAME_MAIN)
    cl = msvc / "7.1" / "Bin" / "cl.exe"
    for name in ("lib", "main"):
        _xdk_run(wibo, cl, [*scratch_xbe.LTCG_CL_FLAGS, "/GL", f"/I{xdk / 'include'}", f"{name}.cpp", f"/Fo{name}.obj"],
                 work)
    link = next(p for p in (xdk / "bin" / "vc71" / "Link.Exe", msvc / "7.1" / "Bin" / "link.exe") if p.exists())
    _xdk_run(wibo, link, [*template_ltcg.LINK_FLAGS, "/MAP:game.map", "/OUT:game.dll", "lib.obj", "main.obj"], work)
    syms = dll2coff.map_symbols(work / "game.map")
    img = dll2coff.Image((work / "game.dll").read_bytes())
    addr = next(a for s, a in syms.items() if "Accumulate" in s)
    end = dll2coff.extent(img, addr, sorted(set(syms.values())))
    return work / "game.dll", addr, end - addr


def _ltcg_project(tmp_path: Path, msvc: Path, xdk: Path, wibo: Path | None) -> tuple[Path, str]:
    """A project for the homemade game, as scratch_xbe writes one in LTCG mode: (its root, Accumulate's symbol)."""
    game, addr, size = _original(tmp_path, msvc, xdk, wibo)
    pe = scratch_pe.read_pe(game.read_bytes())
    fn = scratch_pe.analyse(pe, [{"entry": addr, "end": addr + size, "name": "", "source": "DEFAULT"}],
                            linker_padding=True)[0]
    root = tmp_path / "proj"
    shutil.copytree(TOOLS, root / "tools")
    cfg = root / "tools" / "configure.py"
    text = cfg.read_text().replace('MSVC_VERSION = "6.0"', 'MSVC_VERSION = "7.1"')
    cfg.write_text(text.replace('CL_FLAGS = ["/nologo", "/c", "/O2", "/W3", "/GX"]',
                                f"CL_FLAGS = {json.dumps(scratch_xbe.LTCG_CL_FLAGS)}"))
    ltcg.prepare(root, ["u"])
    (root / "config" / "v").mkdir(parents=True)
    (root / "config" / "v" / "functions.json").write_text(json.dumps({
        "exe": str(game), "sha1": __import__("hashlib").sha1(game.read_bytes()).hexdigest(),
        "image_base": pe.image_base, "units": {"u": [{"name": fn.name, "addr": fn.addr, "offset": pe.offset(fn.addr),
                                                      "size": fn.size, "relocs": [list(r) for r in fn.relocs]}]}}))
    (root / "include").mkdir()
    (root / "include" / "common.h").write_text(scratch_pe.TYPES_H)
    (root / "src" / "auto").mkdir(parents=True)
    # named func_<address>, as decompdecomp names a game's functions: plain builds rename it too (tools/names.py)
    (root / "src" / "auto" / "u.cpp").write_text(f'#include "common.h"\n\n{GAME_LIB}'.replace(
        "Accumulate", f"func_{addr:08X}"))
    return root, fn.name


def _build_and_judge(root: Path, symbol: str, msvc: Path, xdk: Path, wibo: Path | None) -> objdiff.FunctionDiff:
    args = ["--msvc", str(msvc), "--xdk", str(xdk), *(["--wibo", str(wibo)] if wibo else [])]
    for cmd in ([sys.executable, "tools/configure.py", "v", *args], ["ninja", "build/v/src/auto/u.obj",
                                                                   "build/v/target/u.obj"]):
        res = subprocess.run(cmd, cwd=root, capture_output=True, text=True, errors="replace", timeout=300)
        assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    return objdiff.diff(root / "build/v/target/u.obj", root / "build/v/src/auto/u.obj", symbol, root,
                        options=objdiff.judge_options())


@needs_ltcg_tools
def test_a_function_with_a_register_convention_matches_through_the_harness_link_and_not_alone(tmp_path):
    msvc, xdk, wibo = _xdk_tools()
    root, symbol = _ltcg_project(tmp_path, msvc, xdk, wibo)
    # without a driver the unit compiles on its own (no /GL): the standard convention, not the game's
    alone = _build_and_judge(root, symbol, msvc, xdk, wibo)
    assert alone.match_percent is not None and alone.match_percent < 100.0
    # with a driver calling it the way the game's Entry does, the link gives it the game's convention
    name = re.search(r"func_[0-9A-F]{8}", (root / "src" / "auto" / "u.cpp").read_text()).group(0)
    (root / "harness" / "u.drv.cpp").write_text(GAME_MAIN.replace("Entry", "HarnessEntry").replace("Accumulate", name))
    linked = _build_and_judge(root, symbol, msvc, xdk, wibo)
    assert linked.matched, linked.render()
    report = json.loads((root / "build/v/src/auto/u.ltcg.json").read_text())
    assert report["functions"][symbol]["conflicts"] == [] and report["functions"][symbol]["pairs"] >= 2
    # the last read from another global than the original's: objdiff still says 100%, the mapping check doesn't
    src = root / "src" / "auto" / "u.cpp"
    src.write_text(src.read_text().replace("g_last = g_total;", "g_last = g_count;"))
    split = _build_and_judge(root, symbol, msvc, xdk, wibo)
    assert split.match_percent == 100.0 and not split.matched
    assert "refers to other things" in split.literals_note()


def test_the_originals_side_keeps_a_cut_tail_call_whole_and_takes_no_flag_mask_for_an_address():
    # F: `and edx, <an address inside G>` (a flag mask in a program loaded low, as Xbox games are), `push G` (a
    # callback: a real address), then a tail call into G, whose last byte Ghidra's function body leaves out
    f = bytes.fromhex("81e2 14100010" "68 10100010" "e9 00000000")
    g = bytes.fromhex("9090909090909090c3")
    code = f + g
    pe = scratch_pe.PE(code, BASE, 0x2000, BASE + 0x1000, 0,
                       [scratch_pe.Section(".text", BASE + 0x1000, len(code), 0, len(code), True)])
    rows = [{"entry": BASE + 0x1000, "end": BASE + 0x100F, "name": "", "source": "DEFAULT"},
            {"entry": BASE + 0x1010, "end": BASE + 0x1019, "name": "", "source": "DEFAULT"}]
    fn = scratch_pe.analyse(pe, rows, linker_padding=True)[0]
    assert fn.size == 0x10
    assert fn.relocs == [(7, DIR32, "_func_10001010", 0), (12, REL32, "_func_10001010", 0)]
    # a body that runs over the linker's int3 padding (into a function Ghidra missed) stops before it
    padded = f[:-5] + bytes.fromhex("c3") + b"\xcc" * 4 + g
    pe.data = padded
    pe.sections[0] = scratch_pe.Section(".text", BASE + 0x1000, len(padded), 0, len(padded), True)
    rows[0]["end"] = BASE + 0x1010
    assert [(f.size, f.pad) for f in scratch_pe.analyse(pe, rows, linker_padding=True)][0] == (0x0C, 4)


def test_an_ltcg_project_gets_the_setting_and_a_driver_per_game_unit(tmp_path):
    shutil.copytree(TOOLS, tmp_path / "tools")
    ltcg.prepare(tmp_path, ["text_00011000", "xdk_001D0000"])
    assert "\nLTCG = True\n" in (tmp_path / "tools" / "configure.py").read_text()
    assert (tmp_path / "harness" / "text_00011000.drv.cpp").read_text().startswith("// Harness driver for")
    assert not (tmp_path / "harness" / "xdk_001D0000.drv.cpp").exists()  # the XDK's own code is set aside
    assert "/GL" not in scratch_xbe.LTCG_CL_FLAGS and "/Ob1" in scratch_xbe.LTCG_CL_FLAGS
