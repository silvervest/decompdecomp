"""Ghidra drafts: decompiled C for platforms m2c doesn't read (x86, AArch64, Xbox 360 PowerPC, SuperH...).

Optional: Ghidra is large (540 MB) and needs Java 21+. Headless Ghidra analyses a unit's target object once
and decompiles all its functions; the result is cached next to the project, so the cost (tens of seconds,
mostly starting the JVM) is paid once per source file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

from .. import toolchains
from ..limits import capped


def available() -> bool:
    return toolchains.installed("ghidra") is not None and toolchains.java_version() >= 21


def _headless() -> Path:
    base = toolchains.path("ghidra") / "support"
    return base / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")


def _run_script(binary: Path, script: str, timeout: float, *, analyse: bool = True, image: bytes | None = None,
                layout: str | None = None, import_args: tuple[str, ...] = ()) -> list[dict]:
    """Import `binary` into a throwaway Ghidra project, run one of our post-scripts on it and return the JSON objects
    it wrote, one per line ([] when Ghidra failed or took longer than `timeout`). `image`: import these bytes under
    the binary's name instead (with `import_args` saying how: a loader, a processor); `layout`: lines for the
    DecompWtfLayout pre-script (sections and entry points of a program Ghidra has no loader for)."""
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        for name in (script, *(["DecompWtfLayout.java"] if layout is not None else [])):
            src = resources.files("decompnet.forks").joinpath("ghidra_scripts", name)
            (scripts / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = Path(tmp) / "out.jsonl"
        target = Path(tmp) / binary.name
        if image is None:
            shutil.copyfile(binary, target)
        else:
            target.write_bytes(image)
        pre = []
        if layout is not None:
            (Path(tmp) / "layout.txt").write_text(layout, encoding="utf-8")
            pre = ["-preScript", "DecompWtfLayout.java", str(Path(tmp) / "layout.txt")]
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), *import_args, "-scriptPath", str(scripts),
                *pre, "-postScript", script, str(out), "-deleteProject", *([] if analyse else ["-noanalysis"])]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return []
        rows = []
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        return rows


def decompile_object(obj: Path, cache_dir: Path, timeout: float = 900) -> dict[str, str]:
    """name -> decompiled C for every function in an object file (cached by the object's content)."""
    key = hashlib.sha1(obj.read_bytes()).hexdigest()[:16]
    cache = cache_dir / f"{obj.stem}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return {}
    result = {row["name"]: row["c"] for row in _run_script(obj, "DecompWtfExport.java", timeout)}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result), encoding="utf-8")
    return result


def functions(program: Path, timeout: float = 3600) -> list[dict]:
    """Every function Ghidra's analysis finds in a whole program (a Windows .exe: Ghidra reads its imports, exports and
    the C runtime's functions too): {"entry", "end", "name", "source", "purge", "convention", "params", "thunk"}."""
    return _run_script(program, "DecompWtfFunctions.java", timeout)


def functions_in_image(name: str, image: bytes, base: int, layout: str, timeout: float = 3600) -> list[dict]:
    """Every function Ghidra's analysis finds in a program it has no loader for (an Xbox XBE): `image` is the program
    as it lies in memory from `base` (each section's bytes at its address), imported as raw x86 code with the
    Windows calling conventions; `layout` cuts it into sections and seeds the entry points (DecompWtfLayout.java).
    Rows as functions() gives them."""
    args = ("-loader", "BinaryLoader", "-loader-baseAddr", f"0x{base:X}", "-processor", "x86:LE:32:default",
            "-cspec", "windows")
    return _run_script(Path(name), "DecompWtfFunctions.java", timeout, image=image, layout=layout, import_args=args)
