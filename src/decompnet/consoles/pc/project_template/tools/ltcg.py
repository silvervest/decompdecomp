#!/usr/bin/env python3
"""Link-time code generation (LTCG) mode: build a source file the way a game compiled with /GL and linked with
/LTCG was built, so its functions can be compared with the original's.

    python tools/ltcg.py support OUT.lib --cl CL --lib LIB [--wibo WIBO]

Why: with /GL the compiler writes its intermediate code into the object, not machine code, and the linker generates
the code for the whole program at once. It then picks a function's calling convention from its callers (`this` or
arguments in EAX, ESI, EDI or EBX instead of ECX and the stack) and inlines across source files. So a function's
bytes depend on who calls it and on what it calls, and an object compiled on its own can't be compared at all.

The build links each source file in harness mode instead (tools/configure.py writes the rules from here):

- src/auto/<unit>.cpp, the decompiled code;
- harness/<unit>.drv.cpp, the driver: `extern "C" __declspec(dllexport) void HarnessEntry(...)` calling the unit's
  functions the way the original's call sites do (which registers hold what, which constants are passed), so the
  linker gives them the original's conventions;
- harness/<unit>.<anything>.cpp, stand-ins: the functions and data the unit uses from elsewhere in the game, with
  bodies shaped enough like the real ones (what they read and preserve) that the linker treats them alike. A file
  named <unit>.<name>.nogl.cpp is compiled without /GL: a stand-in for code the game's link couldn't see into
  (middleware, the XDK's own libraries).

All of it is compiled with /GL and linked into a DLL with /LTCG and a map (the XDK's own Link.Exe: through
wibo-xbox on Linux and macOS), with a library of C runtime stubs (support.lib, built here) for what the compiler
calls implicitly. A `// HARNESS-LINK: <flags>` line in any of those files adds linker flags for that unit, such as
`d3d8ltcg.lib` (the XDK's LTCG Direct3D, so its inlined code is generated alike) or `/d2:"-inlT56"`.
tools/dll2coff.py then cuts the unit's functions out of the DLL into the object objdiff compares.

A unit whose driver doesn't define HarnessEntry yet is compiled as a plain unit, without /GL: leaf functions with
standard conventions match that way too. Made by decompdecomp.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# The driver's entry point, defined (not commented out): a unit is built in harness mode once its driver has one.
ENTRY = re.compile(r'^[ \t]*extern[ \t]+"C"[^\n;]*\bHarnessEntry[ \t]*\(', re.M)
# a line of its own (a comment that only mentions the directive, as older driver skeletons did, isn't one)
LINK_LINE = re.compile(r"^[ \t]*//[ \t]*HARNESS-LINK:[ \t]*([^\r\n]*)", re.M)

# What the compiler calls without the source asking for it (floating point, 64-bit arithmetic, stack probes,
# pure virtual calls, structure copies). Builds link with /NODEFAULTLIB, so these stubs stand in for the C runtime:
# one object each in support.lib, so a stub is only pulled in when nothing else defines it. The 64-bit helpers are
# undecorated, take their operands on the stack and pop them (ret 16), as the C runtime's do.
CRT_STUBS = {
    "fltused": "int _fltused = 0x9875;\n",
    "purecall": "int __cdecl _purecall(void) { return 0; }\n",
    "ftol2": "long __cdecl _ftol2(void) { return 0; }\n",
    "chkstk": "void __cdecl _chkstk(void) { }\n",
    "allmul": "__declspec(naked) void _allmul(void) { __asm ret 16 }\n",
    "alldiv": "__declspec(naked) void _alldiv(void) { __asm ret 16 }\n",
    "allrem": "__declspec(naked) void _allrem(void) { __asm ret 16 }\n",
    "aulldiv": "__declspec(naked) void _aulldiv(void) { __asm ret 16 }\n",
    "aullrem": "__declspec(naked) void _aullrem(void) { __asm ret 16 }\n",
    "alldvrm": "__declspec(naked) void _alldvrm(void) { __asm ret 16 }\n",
    "aulldvrm": "__declspec(naked) void _aulldvrm(void) { __asm ret 16 }\n",
    "allshl": "__declspec(naked) void _allshl(void) { __asm ret }\n",
    "allshr": "__declspec(naked) void _allshr(void) { __asm ret }\n",
    "aullshr": "__declspec(naked) void _aullshr(void) { __asm ret }\n",
    "atexit": "int __cdecl atexit(void (__cdecl *f)(void)) { return f != 0; }\n",
    "memset": "void *__cdecl memset(void *d, int c, unsigned n) { char *p = (char *)d; while (n--) *p++ = (char)c;"
              " return d; }\n",
    "memcpy": "void *__cdecl memcpy(void *d, const void *s, unsigned n) { char *p = (char *)d;"
              " const char *q = (const char *)s; while (n--) *p++ = *q++; return d; }\n",
}
LINK_FLAGS = ["/nologo", "/DLL", "/NOENTRY", "/NODEFAULTLIB", "/OPT:REF", "/LTCG"]


def harness_files(unit: str, harness: Path = Path("harness")) -> tuple[Path, list[Path]]:
    """(driver, stand-ins) of a unit: harness/<unit>.drv.cpp and every other harness/<unit>.*.cpp."""
    driver = harness / f"{unit}.drv.cpp"
    extras = sorted(p for p in harness.glob(f"{unit}.*.cpp") if p != driver)
    return driver, extras


def has_entry(driver: Path) -> bool:
    try:
        return bool(ENTRY.search(driver.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        return False


def link_flags(paths: list[Path]) -> list[str]:
    """The extra linker flags of `// HARNESS-LINK:` lines. link.exe takes a single /d2:, so the last one wins."""
    out: list[str] = []
    for p in paths:
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in LINK_LINE.finditer(text):
            try:
                out += shlex.split(m.group(1).strip())
            except ValueError as e:  # an unclosed quote: say where, configure stops with it
                line = text.count("\n", 0, m.start()) + 1
                raise SystemExit(f"{p}:{line}: can't read the HARNESS-LINK flags ({e}): "
                                 f"{m.group(0).strip()}") from None
    d2 = [f for f in out if f.lower().startswith("/d2:")]
    return [f for f in out if not f.lower().startswith("/d2:")] + d2[-1:]


def write_rules(n, *, units: list[str], source_of, build: Path, config: Path, cl: Path, link: Path, lib: Path,
                wrap: str, py: str, sh: str, include: Path, libpath: Path | None, cl_flags: list[str],
                headers: list[str]) -> tuple[set[str], list[str]]:
    """Ninja rules and builds for every unit whose driver defines HarnessEntry. Returns (those units, the harness
    files the build depends on, so editing a driver re-runs configure)."""
    q = subprocess.list2cmdline
    out = build / "ltcg"
    # what each file includes (headers, another unit's source a driver includes) is its dependency: tools/cldeps.py
    n.rule("ltcg_cc", f'{sh}{py} tools/cldeps.py $out -- {wrap}"{cl}" $flags /Iinclude /Iharness "/I{include}"'
                      f' /showIncludes /Fo$out $in', deps="gcc", depfile="$out.d")
    support = out / "support.lib"
    n.rule("ltcg_support", f'{py} tools/ltcg.py support $out --cl "{cl}" --lib "{lib}"'
                           + (f" --wibo {wrap.strip()}" if wrap else ""))
    n.build(str(support), "ltcg_support", implicit=["tools/ltcg.py"])
    libdir = f' "/LIBPATH:{libpath}"' if libpath else ""
    n.rule("ltcg_link", f'{sh}{wrap}"{link}" {q(LINK_FLAGS)}{libdir} /MAP:$map /OUT:$out $extra $in',
           description="LTCG link $out")
    n.rule("ltcg_coff", f"{py} tools/dll2coff.py {config} $unit $dll $map $out $sources")

    harness_paths = sorted(str(p) for p in Path("harness").rglob("*") if p.is_file()) if Path("harness").is_dir() else []
    done = set()
    gl = [f for f in cl_flags if f.upper() != "/GL"] + ["/GL"]
    for unit in units:
        driver, extras = harness_files(unit)
        src = Path(source_of(unit))
        if not src.exists() or not has_entry(driver):
            continue
        sources = [src, driver, *extras]
        objs = []
        for i, path in enumerate(sources):
            obj = out / unit / f"{i:02d}_{path.stem.replace('.', '_')}.obj"
            flags = [f for f in gl if f.upper() != "/GL"] if ".nogl." in path.name.lower() else gl
            n.build(str(obj), "ltcg_cc", str(path), implicit=["tools/cldeps.py"], variables={"flags": q(flags)})
            objs.append(str(obj))
        dll, mapf = out / unit / f"{unit}.dll", out / unit / f"{unit}.map"
        n.build(str(dll), "ltcg_link", [*objs, str(support)], implicit_outputs=[str(mapf)],
                variables={"map": str(mapf), "extra": q(link_flags(sources))})
        base = build / src.with_suffix(".obj")
        n.build([str(base)], "ltcg_coff", [str(dll)], implicit=[str(mapf), str(config), "tools/dll2coff.py",
                                                               "tools/delink.py", "tools/names.py", *map(str, sources)],
                implicit_outputs=[str(base.with_suffix(".ltcg.json"))],
                variables={"unit": unit, "dll": str(dll), "map": str(mapf), "sources": q([str(s) for s in sources])})
        done.add(unit)
    return done, harness_paths


def _run(cmd: list[str]) -> None:
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if res.returncode:
        sys.exit(f"{subprocess.list2cmdline(cmd)} failed:\n{res.stdout}{res.stderr}")


def support(out: Path, cl: str, lib: str, wibo: str) -> None:
    """support.lib: the C runtime stubs, one object each."""
    work = out.parent / "support"
    work.mkdir(parents=True, exist_ok=True)
    wrap = [wibo] if wibo and sys.platform != "win32" else []
    objs = []
    for name, body in CRT_STUBS.items():
        c, o = work / f"crt_{name}.c", work / f"crt_{name}.obj"
        c.write_text("#pragma function(memset, memcpy)\n" + body, encoding="utf-8")
        _run([*wrap, cl, "/nologo", "/c", "/O1", os.path.relpath(c), f"/Fo{os.path.relpath(o)}"])
        objs.append(os.path.relpath(o))
    _run([*wrap, lib, "/nologo", f"/OUT:{os.path.relpath(out)}", *objs])


def main() -> None:
    p = argparse.ArgumentParser(description="LTCG harness mode helpers")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("support", help="build support.lib (C runtime stubs)")
    s.add_argument("out", type=Path)
    s.add_argument("--cl", required=True)
    s.add_argument("--lib", required=True)
    s.add_argument("--wibo", default="")
    a = p.parse_args()
    if a.cmd == "support":
        support(a.out, a.cl, a.lib, a.wibo)


if __name__ == "__main__":
    main()
