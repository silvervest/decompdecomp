"""What compile_and_diff's diff shows agents. On Burnout 3 every long result was cut ("N more rows not shown", N 27
to 181) and the only way to see the rest was another compile; and a target row loading a float constant by address
(`mulss xmm0, [_D_003A1248]`) didn't say which constant, so agents spent read_data calls (or compiles) finding out."""

import struct

import pytest

from decompnet import scoring
from decompnet.app.forkengine import with_constant_values
from decompnet.arch import x86
from decompnet.network import NetworkError

from .test_claims import _game


def _rows(n):
    return [("|", f"add eax, {i}", f"add eax, {i + 1}") for i in range(n)]


def test_a_cut_diff_says_last_diff_shows_the_rest():
    text = scoring.render_rows(_rows(200))
    assert "more rows not shown: fix these first; last_diff(function) shows every row" in text
    assert "last_diff" not in scoring.render_rows(_rows(5))


def test_last_diff_gives_every_row_of_the_agents_last_compile_without_compiling(tmp_path):
    net, _ = _game(tmp_path, [("f", 200, "open")])
    a, _ = net.local_agent("a")
    fid = net.store.one("SELECT id FROM functions WHERE name='f'")["id"]
    with pytest.raises(NetworkError, match="compile_and_diff first"):
        net.last_diff(a, "f", "game")
    net.keep_diff(a.id, fid, _rows(200))
    text = net.last_diff(a, "f", "game")
    assert "not shown" not in text and "add eax, 199" in text and "not a new compile" in text
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts")["n"] == 0  # nothing recorded
    b, _ = net.local_agent("b")
    with pytest.raises(NetworkError, match="compile_and_diff first"):
        net.last_diff(b, "f", "game")  # another agent's compile isn't yours


def test_x86_float_operands_by_address():
    assert x86.float_operands("mulss xmm0, dword ptr [_D_003A1248]") == [(0x3A1248, "f")]
    assert x86.float_operands("fld qword ptr [D_003A1250]") == [(0x3A1250, "d")]
    assert x86.float_operands("fmul dword ptr [D_003A1248+0x4]") == [(0x3A124C, "f")]
    assert x86.float_operands("comisd xmm1, qword ptr [D_00400000]") == [(0x400000, "d")]
    assert x86.float_operands("mov eax, dword ptr [D_003A1248]") == []  # not a float
    assert x86.float_operands("fstp dword ptr [D_003A1248]") == []  # a store, not a constant
    assert x86.float_operands("fild dword ptr [D_003A1248]") == []  # an integer
    assert x86.float_operands("mulss xmm0, xmm1") == []


class _Console:
    arch, big_endian = "x86", False

    def __init__(self, data):
        self.data = data

    def data_bytes(self, fp, addr, length):
        return self.data.get((addr, length))


def test_the_diff_shows_the_value_of_the_float_the_target_loads():
    console = _Console({(0x3A1248, 4): struct.pack("<f", 0.017453292), (0x3A1250, 8): struct.pack("<d", 0.5)})
    rows = [(" ", "mulss xmm0, [_D_003A1248]", "mulss xmm0, [_D_003A1248]"),
            ("i", "mulss xmm0, [_D_003A1248]", "mulss xmm0, [$A10000000]"),
            ("|", "fld qword ptr [D_003A1250]", "fld dword ptr [x]"),
            ("i", "movss xmm1, [D_00999999]", "movss xmm1, [y]")]  # not in the copy: left alone
    out = with_constant_values(rows, console, None)
    assert out[0] == rows[0]  # equal rows aren't read
    assert out[1][2] == "mulss xmm0, [$A10000000]   ; target's D_003A1248 = 0.0174532924f"
    assert out[2][2].endswith("; target's D_003A1250 = 0.5")
    assert out[3] == rows[3]
    mips = _Console({})
    mips.arch = "mips"
    assert with_constant_values(rows, mips, None) == rows
