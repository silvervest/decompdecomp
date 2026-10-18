"""configure.py in an LTCG project: a unit whose driver (made from the skeleton) defines HarnessEntry gets its
harness link, a HARNESS-LINK line that can't be read stops configure with where it is and leaves the last
build.ninja whole, and projects made before a template fix get the fixed tools."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from decompnet.forks import ltcg, scratch_pe
from decompnet.forks.project import ForkProject

TEMPLATE = Path(scratch_pe.__file__).with_name("pc_template")
# the skeleton's comment as projects made before this fix have it in every driver
OLD_LINE = '// - `// HARNESS-LINK: <flags>` on a line here adds linker flags (d3d8ltcg.lib, /d2:"-inlT56"...).\n'


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "p"
    shutil.copytree(TEMPLATE, root)
    ltcg.prepare(root, ["u"])
    (root / "config" / "v").mkdir(parents=True)
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"exe": "orig/v.xbe", "sha1": "0", "units": {
        "u": [{"name": "_func_00011000", "addr": 0x11000, "offset": 0, "size": 1, "relocs": []}]}}))
    (root / "src" / "auto").mkdir(parents=True)
    (root / "src" / "auto" / "u.cpp").write_text("// FUNCTION: 0x11000\nvoid func_00011000() {}\n")
    (root / "include").mkdir()
    return root


def _configure(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "tools/configure.py", "v", "--msvc", str(root / "msvc")], cwd=root,
                          capture_output=True, text=True)


def _entry(root: Path, extra: str = "") -> None:
    drv = root / "harness" / "u.drv.cpp"
    text = drv.read_text().replace('// extern "C" __declspec(dllexport) void HarnessEntry(void)\n// {\n// }\n',
                                   'extern "C" __declspec(dllexport) void HarnessEntry(void)\n{\n}\n')
    drv.write_text(extra + text)


def test_a_skeleton_driver_with_harness_entry_gets_the_harness_link(tmp_path):
    root = _project(tmp_path)
    assert "HARNESS-LINK:" not in ltcg.DRIVER  # the skeleton doesn't spell the directive out
    _entry(root, OLD_LINE)  # an old skeleton's comment only mentions it: not a directive (it has an open quote)
    res = _configure(root)
    assert res.returncode == 0, res.stderr
    ninja = (root / "build.ninja").read_text().replace("$\n", "")
    assert "build build/v/ltcg/u/u.dll | build/v/ltcg/u/u.map: ltcg_link" in ninja
    assert "build build/v/src/auto/u.obj | build/v/src/auto/u.ltcg.json: ltcg_coff" in ninja
    assert not (root / "build.ninja.tmp").exists() and json.loads((root / "objdiff.json").read_text())["units"]


def test_an_unreadable_harness_link_line_says_where_and_keeps_the_last_build_file(tmp_path):
    root = _project(tmp_path)
    assert _configure(root).returncode == 0
    before = (root / "build.ninja").read_text()
    _entry(root, '// HARNESS-LINK: /d2:"-inlT56\n')
    res = _configure(root)
    assert res.returncode != 0
    assert "u.drv.cpp:1: can't read the HARNESS-LINK flags" in res.stderr and "Traceback" not in res.stderr
    assert (root / "build.ninja").read_text() == before


def test_projects_made_before_a_template_fix_get_the_fixed_tools_with_their_settings(tmp_path):
    root = _project(tmp_path)
    cfg = root / "tools" / "configure.py"
    cfg.write_text(cfg.read_text().replace('MSVC_VERSION = "6.0"', 'MSVC_VERSION = "7.1"'))
    (root / "tools" / "ltcg.py").write_text("# an older ltcg.py\n")
    (root / ".decomp.wtf.json").write_text(json.dumps({"created": "from scratch", "platform": "xbox", "setup": []}))
    fp = ForkProject(root)
    assert scratch_pe.refresh_tools(fp, log=lambda *_: None) == ["ltcg.py"]
    assert (root / "tools" / "ltcg.py").read_text() == (TEMPLATE / "tools" / "ltcg.py").read_text()
    text = cfg.read_text()
    assert 'MSVC_VERSION = "7.1"' in text and "LTCG = True" in text  # its own settings kept
    assert scratch_pe.refresh_tools(fp, log=lambda *_: None) == []
