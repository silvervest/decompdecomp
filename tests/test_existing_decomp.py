"""Continuing an existing PC or Xbox decompilation in a project made here: its functions have real names and say
which original function they are with `// FUNCTION: 0x<address>` annotations, its harness drivers include headers
and other units' sources, and part of the program is middleware that isn't the game's code."""

import json

from decompnet.app.forkengine import ForkEngine, _set_aside
from decompnet.forks import csource, objdiff
from decompnet.forks.project import ForkProject

SOURCE = """#include "ai/behaviour.h"

// FUNCTION: 0x0001a8f0
// Steps the behaviour: true while it runs.
bool CAIBehaviour::Update(int dt)
{
    if (dt > 0) { m_t += dt; }
    return m_t < 100;
}

// FUNCTION: 0x1A920 ?Reset@CAIBehaviour@@QAEXXZ NONMATCHING
#pragma optimize("", off)
void CAIBehaviour::Reset()
{
    m_t = 0;
}
#pragma optimize("", on)

// FUNCTION: 0x1A960
void CAIBehaviour::Declared();

// FUNCTION: 0x1A9A0 ?Start@CRig@@QAEXPAUCOwner@@@Z
// the types it needs come first
struct COwner { char pad[0x40]; int m_40; };
static const int k_table[2] = { 1, 2 };
void CRig::Start(COwner *o)
{
    m_owner = o;
}
"""


def test_a_function_is_found_by_its_function_annotation_whatever_its_name():
    span = csource.find(SOURCE, csource.address_key(0x1A8F0))
    assert SOURCE[span[0]:span[1]] == "bool CAIBehaviour::Update(int dt)\n{\n    if (dt > 0) { m_t += dt; }\n" \
                                      "    return m_t < 100;\n}\n"
    assert csource.defined_name(SOURCE, span) == "CAIBehaviour::Update"
    span = csource.find(SOURCE, csource.address_key(0x1A920))  # pragma lines between are passed over
    assert SOURCE[span[0]:span[1]].startswith("void CAIBehaviour::Reset()\n{")
    assert csource.find(SOURCE, csource.address_key(0x1A960)) is None  # a declaration isn't a definition
    assert csource.find(SOURCE, csource.address_key(0x1A900)) is None
    span = csource.find(SOURCE, csource.address_key(0x1A9A0))  # past a struct and an initialised table
    assert SOURCE[span[0]:span[1]] == "void CRig::Start(COwner *o)\n{\n    m_owner = o;\n}\n"
    dtor = "void __stdcall Foo::~Foo()\n{\n}\n"
    assert csource.defined_name(dtor, (0, len(dtor))) == "Foo::~Foo"
    # replacing it keeps the annotation (it isn't part of the definition)
    out = csource.replace(SOURCE, csource.address_key(0x1A8F0), "bool CAIBehaviour::Update(int dt)\n{\n    return 0;\n}")
    assert "// FUNCTION: 0x0001a8f0\n// Steps the behaviour: true while it runs.\nbool CAIBehaviour::Update(int dt)\n" \
           "{\n    return 0;\n}\n\n// FUNCTION: 0x1A920" in out


def test_the_engine_looks_a_pc_or_xbox_function_up_by_its_address_first():
    names = ForkEngine._names({"symbol": "_func_0001A8F0@4"}, {"name": "_func_0001A8F0@4"})
    assert names == [csource.address_key(0x1A8F0), "_func_0001A8F0@4", "func_0001A8F0"]
    engine = ForkEngine.__new__(ForkEngine)
    assert engine._find(SOURCE, names)[1] == csource.find(SOURCE, csource.address_key(0x1A8F0))
    # a project whose report gives addresses, with no address in the symbol
    assert ForkEngine._names({"symbol": "Update"}, {"name": "Update", "vram": 0x8000A000})[0] == \
        csource.address_key(0x8000A000)
    assert ForkEngine._names({"symbol": "Update"}, {"name": "Update"}) == ["Update"]


def test_progress_counts_the_games_own_code_with_middleware_set_aside_by_range(tmp_path):
    conf = tmp_path / "config" / "v"
    conf.mkdir(parents=True)
    fns = [{"name": f"_func_{a:08X}", "addr": a, "size": 0x10} for a in (0x11000, 0x11010, 0x200000, 0x200010)]
    (conf / "functions.json").write_text(json.dumps({"units": {"game": fns[:2], "rw": fns[2:3], "xdk": fns[3:]}}))
    (conf / "set_aside.json").write_text(json.dumps({
        "_func_00200010": "XDK D3D8 (d3d8.lib)",  # what an Xbox import writes: symbol -> why
        "ranges": [{"from": "0x200000", "to": "0x200010", "why": "RenderWare 3.6"}]}))
    (tmp_path / ".decomp.wtf.json").write_text(json.dumps({"version": "v", "platform": "xbox"}))
    aside = _set_aside(ForkProject(tmp_path))  # found beside functions.json, even without the manifest naming it
    assert aside == {"_func_00200010": "XDK D3D8 (d3d8.lib)", "_func_00200000": "RenderWare 3.6"}
    rep = {"measures": {"total_functions": 4, "matched_functions": 2, "total_code": "64", "matched_code": "32",
                        "matched_code_percent": 50.0},
           "units": [{"name": "game", "functions": [{"name": "_func_00011000", "size": "16", "fuzzy_match_percent": 100},
                                                    {"name": "_func_00011010", "size": "48", "fuzzy_match_percent": 50}]},
                     {"name": "rw", "functions": [{"name": "_func_00200000", "size": "16", "fuzzy_match_percent": 100}]},
                     {"name": "xdk", "functions": [{"name": "_func_00200010", "size": "16"}]}]}
    m = objdiff.game_measures(rep, set(aside))
    assert (m["total_functions"], m["matched_functions"], m["total_code"], m["matched_code"]) == (2, 1, "64", "16")
    assert m["matched_code_percent"] == 25.0 and m["all_functions"] == 4 and m["set_aside_functions"] == 2
    assert objdiff.game_measures(rep, set()) == rep["measures"]
    assert objdiff.expand_set_aside({"functions": {"0x11010": "CRT"}}, {"units": {"game": fns}}) == \
        {"_func_00011010": "CRT"}
