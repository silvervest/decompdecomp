"""Paths the user types: on Windows decompdecomp runs in WSL, where a path copied from Explorer is under /mnt."""

from pathlib import Path

from decompnet import hostenv


def _kernel(monkeypatch, tmp_path, release: str) -> None:
    f = tmp_path / "osrelease"
    f.write_text(release, encoding="utf-8")
    monkeypatch.setattr(hostenv, "KERNEL_RELEASE", f)


def test_a_windows_path_typed_in_wsl_is_the_same_folder_under_mnt(monkeypatch, tmp_path):
    _kernel(monkeypatch, tmp_path, "6.6.87.2-microsoft-standard-WSL2")
    assert hostenv.local_path(r"C:\Users\sam\XDK\xbox") == Path("/mnt/c/Users/sam/XDK/xbox")
    assert hostenv.local_path('"D:/Program Files/XDK"') == Path("/mnt/d/Program Files/XDK")
    assert hostenv.local_path("E:") == Path("/mnt/e")
    assert hostenv.local_path("/home/sam/xdk") == Path("/home/sam/xdk")  # a Linux path stays as it is


def test_elsewhere_a_path_is_taken_as_written(monkeypatch, tmp_path):
    _kernel(monkeypatch, tmp_path, "6.8.0-45-generic")
    assert hostenv.local_path(" '/opt/xdk' ") == Path("/opt/xdk")
    assert hostenv.local_path(r"C:\XDK") == Path(r"C:\XDK")
