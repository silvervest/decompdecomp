"""Which CL an Xbox project's build compiles with: on Windows itself the XDK's own, elsewhere the portable 7.1."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "src" / "decompnet" / "consoles" / "pc" / "project_template" / "tools"


def _configure(tmp_path: Path, platform: str) -> str:
    """build.ninja of an empty Xbox project, configured as if on `platform`, with stand-in compiler folders."""
    root = tmp_path / platform
    shutil.copytree(TOOLS, root / "tools")
    cfg = root / "tools" / "configure.py"
    cfg.write_text(cfg.read_text().replace('MSVC_VERSION = "6.0"', 'MSVC_VERSION = "7.1"'))
    (root / "config" / "v").mkdir(parents=True)
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"exe": "orig/g.xbe", "units": {}}))
    (root / "include").mkdir()
    msvc, xdk = tmp_path / "msvc", tmp_path / "xdk"
    for exe in (msvc / "7.1" / "Bin" / "CL.EXE", xdk / "bin" / "vc71" / "CL.Exe"):
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"")
    run = (f"import runpy, sys; sys.platform = {platform!r}; sys.path.insert(0, 'tools'); "
           f"sys.argv = ['configure.py', 'v', '--msvc', {str(msvc)!r}, '--xdk', {str(xdk)!r}]; "
           "runpy.run_path('tools/configure.py', run_name='__main__')")
    res = subprocess.run([sys.executable, "-c", run], cwd=root, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr[-2000:]
    return (root / "build.ninja").read_text()


def _compiler(ninja: str) -> str:
    """The compiler the cl rule runs (ninja_syntax wraps the line after `--compiler`)."""
    return re.search(r"--compiler(?: \$\n)?\s+(\S+)", ninja).group(1).replace("\\", "/")


def test_on_windows_an_xbox_game_compiles_with_the_xdks_own_cl(tmp_path):
    """The portable 7.1's cl.exe doesn't start on Windows itself (the runtime DLLs wibo stands in for on Linux)."""
    assert _compiler(_configure(tmp_path, "win32")).endswith("xdk/bin/vc71/CL.Exe")


def test_elsewhere_an_xbox_game_keeps_the_portable_cl(tmp_path):
    assert _compiler(_configure(tmp_path, "linux")).endswith("msvc/7.1/Bin/CL.EXE")
