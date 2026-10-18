#!/usr/bin/env python3
"""Write build.ninja and objdiff.json for this PC (Windows) decompilation, then run `ninja`.

    python tools/configure.py VERSION --msvc DIR [--wibo PATH] [--xdk DIR]

An Xbox game (--xdk: your own XDK's xbox folder) compiles against the XDK's headers instead of Visual C++'s.

The build cuts every function out of your copy of the game (orig/, see config/VERSION/functions.json) into objects,
one per source file (tools/delink.py), and compiles src/ with the game's Visual C++ (run through wibo on Linux and
macOS). objdiff.json (for objdiff and decompdecomp) compares every source file's functions with the original's.
`ninja export` rebuilds the game's program from the matched functions and your copy, with the game's own linker
(an Xbox game's: the XDK's, then its imagebld), and says whether it's byte for byte your copy (tools/export.py).
Made by decompdecomp.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import ninja_syntax

# Settings (decompdecomp wrote these for this game; change them if the game was built differently)
MSVC_VERSION = "6.0"
CL_FLAGS = ["/nologo", "/c", "/O2", "/W3", "/GX"]  # /GX: C++ exceptions, as games of the time were built
# Link-time code generation (games built with /GL and /LTCG): units whose driver in harness/ defines HarnessEntry
# compile with CL_FLAGS plus /GL and link in harness mode (tools/ltcg.py); the rest compile with CL_FLAGS alone.
LTCG = False

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
parser = argparse.ArgumentParser(description="Writes build.ninja and objdiff.json")
parser.add_argument("version", help="game version (a directory in config/)")
parser.add_argument("--msvc", required=True, help="Visual C++ directory (holds 6.0/Bin/CL.EXE, 7.1/Bin/cl.exe, ...)")
parser.add_argument("--wibo", default="", help="runs the Windows compilers on Linux and macOS")
parser.add_argument("--xdk", default="", help="an Xbox game: your own XDK's xbox folder (holds include/xtl.h)")
args = parser.parse_args()

VERSION = args.version
CONFIG = Path("config") / VERSION / "functions.json"
BUILD = Path("build") / VERSION
MSVC = Path(args.msvc) / MSVC_VERSION
CL = next((p for p in (MSVC / "Bin" / "CL.EXE", MSVC / "Bin" / "cl.exe") if p.exists()), MSVC / "Bin" / "CL.EXE")
WRAP = f'"{args.wibo}" ' if args.wibo and sys.platform != "win32" else ""
PY = f'"{sys.executable}"'
SH = "cmd /c " if sys.platform == "win32" else ""  # ninja starts commands without a shell: && needs one on Windows
# the headers: Visual C++'s own for a PC game; for an Xbox game the XDK's (its C runtime and xtl.h replace them)
INCLUDE = Path(args.xdk) / "include" if args.xdk else MSVC / "Include"


def q(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv)


def files(top: str, suffixes: tuple[str, ...]) -> list[Path]:
    return sorted(p for p in Path(top).rglob("*") if p.suffix.lower() in suffixes)


def source_of(unit: str) -> str:
    """A unit's source file: C++ (.cpp), or C (.c) in projects made before decompdecomp wrote C++."""
    cpp = Path("src") / "auto" / f"{unit}.cpp"
    return cpp.as_posix() if cpp.exists() or not cpp.with_suffix(".c").exists() else cpp.with_suffix(".c").as_posix()


def linker() -> Path:
    """The game's linker: an Xbox game's is the XDK's own (bin/vc71), a PC game's the Visual C++ it was built with."""
    xbin = Path(args.xdk) / "bin" / "vc71"
    found = [xbin / "Link.Exe", xbin / "link.exe"] if args.xdk else []
    return next((p for p in [*found, MSVC / "Bin" / "link.exe", MSVC / "Bin" / "LINK.EXE"] if p.exists()),
                found[0] if found else MSVC / "Bin" / "link.exe")


def main() -> None:
    units = json.loads(CONFIG.read_text(encoding="utf-8"))["units"]
    headers = [str(p) for p in files("include", (".h", ".hpp"))]
    # written aside and put in place whole: a configure that stops half way (a driver it can't read) leaves the
    # last build.ninja, so ninja runs this again and shows why, instead of missing the rest of the build
    with open("build.ninja.tmp", "w", encoding="utf-8") as f:
        n = ninja_syntax.Writer(f)
        n.rule("delink", f"{PY} tools/delink.py {CONFIG} {BUILD / 'target'}", restat=True)
        # then the original's names on what it compiled to (C++ mangles them: tools/names.py)
        n.rule("cl", f'{SH}{WRAP}"{CL}" {q(CL_FLAGS)} /Iinclude "/I{INCLUDE}" $cflags /Fo$out $in'
               f' && {PY} tools/names.py {CONFIG} $out')
        n.rule("configure", f"{PY} tools/configure.py {q(sys.argv[1:])}", generator=True)

        targets = [str(BUILD / "target" / f"{u}.obj") for u in units]
        n.build(targets, "delink", [str(CONFIG), "tools/delink.py"])
        objs, harness_units, harness_files = [], set(), []
        if LTCG:  # ---- LTCG harness mode (tools/ltcg.py, tools/dll2coff.py)
            import ltcg

            xbin = Path(args.xdk) / "bin" / "vc71"
            link = next((p for p in (xbin / "Link.Exe", xbin / "link.exe", MSVC / "Bin" / "link.exe") if p.exists()),
                        xbin / "Link.Exe")
            lib = next((p for p in (xbin / "Lib.Exe", xbin / "lib.exe", MSVC / "Bin" / "lib.exe") if p.exists()),
                       xbin / "Lib.Exe")
            harness_units, harness_files = ltcg.write_rules(
                n, units=list(units), source_of=source_of, build=BUILD, config=CONFIG, cl=CL, link=link, lib=lib,
                wrap=WRAP, py=PY, sh=SH, include=INCLUDE, libpath=Path(args.xdk) / "lib" if args.xdk else None,
                cl_flags=CL_FLAGS, headers=headers)
            objs += [str(BUILD / Path(source_of(u)).with_suffix(".obj")) for u in sorted(harness_units)]
        # ---- end of LTCG harness mode
        for src in files("src", (".c", ".cpp")):
            if src.parent == Path("src") / "auto" and src.stem in harness_units:
                continue
            obj = BUILD / src.with_suffix(".obj")
            n.build(str(obj), "cl", str(src), implicit=[*headers, str(CONFIG), "tools/names.py"])
            objs.append(str(obj))
        n.build("all_source", "phony", objs)
        n.build("prepare", "phony", [*targets, *objs])
        # `ninja export`: the game's program rebuilt from the project and checked byte for byte (tools/export.py)
        xdk = [f'--xdk "{args.xdk}"'] if args.xdk else []
        wibo = [f'--wibo "{args.wibo}"'] if WRAP else []
        n.rule("export", " ".join([f"{PY} tools/export.py {CONFIG} {BUILD / 'export'}", f'--link "{linker()}"',
                                   *wibo, *xdk]), description="rebuild the game's program and compare it")
        n.build(str(BUILD / "export" / "export.json"), "export", [*targets, *objs],
                implicit=["tools/export.py", "objdiff.json"])
        n.build("export", "phony", [str(BUILD / "export" / "export.json")])
        n.build("build.ninja", "configure", ["tools/configure.py", str(CONFIG), *headers, *harness_files,
                                             *[str(s) for s in files("src", (".c", ".cpp"))]])
        n.default(["prepare"])
    os.replace("build.ninja.tmp", "build.ninja")

    objdiff = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "custom_make": "ninja", "custom_args": [], "build_target": False, "build_base": True,
        "watch_patterns": ["*.c", "*.cpp", "*.h", "*.hpp"],
        "units": [{"name": u, "target_path": str(BUILD / "target" / f"{u}.obj"),
                   "base_path": str(BUILD / "src" / "auto" / f"{u}.obj"),
                   "metadata": {"source_path": source_of(u), "complete": False}} for u in units],
    }
    Path("objdiff.json.tmp").write_text(json.dumps(objdiff, indent=2), encoding="utf-8")
    os.replace("objdiff.json.tmp", "objdiff.json")


if __name__ == "__main__":
    main()
