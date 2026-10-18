# wibo for the Xbox XDK 5849 toolchain

[wibo](https://github.com/decompals/wibo) 1.2.0 runs the XDK's `CL.Exe`, but the stock `Link.Exe` and `Lib.Exe` do not
run: `Link.Exe` aborts on the first call to `kernel32!lstrcmpiA`, and `/LTCG` links fail when the linker delay-loads
`OLEAUT32.dll`. Four patches add what is missing, so the XDK 5849 compiler (Visual C++ 7.1, 13.10.3077) and linker
(7.10.3077) run on Linux unmodified, with the usual `/GL` + `/LTCG` flow. Nothing here is sent upstream.

Where things live:

- **The patches** are commits on the `xbox` branch of our wibo fork, https://github.com/silvervest/wibo (on top of
  tag 1.2.0). `wibo.ref` pins the commit Xbox projects use.
- **The release binary** is a release of that fork. wibo's own CI builds it when a tag (e.g. `1.2.0-xbox.1`) is
  pushed there: static, in wibo's Alpine image, after wibo's test suite. The fork publishes it instead of leaving a
  draft. `toolchains.toml`'s `[wibo-xbox]` entry pins the release's `wibo-x86_64` by sha256.
- **The local recipe** is `build.sh`:

```sh
packaging/wibo/build.sh [output-dir]                 # clones the pinned commit, builds, prints the sha256
WIBO_DOCKER=1 packaging/wibo/build.sh [output-dir]   # the same, in wibo's Alpine image, as the release is built
```

Without Docker it needs git, cmake, ninja, python3, libclang and a linker that understands `--image-base` (LLD). The
default preset is `release64-clang`. With GCC, use `WIBO_PRESET=release64`. If the distro has no `libclang.so` or
`ld.lld`, pass them through `WIBO_CMAKE_ARGS` (for example
`-DLIBCLANG_LIBRARY=/path/libclang.so -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld`).

To change the patches:
1. Commit on the fork's `xbox` branch.
2. Push a new tag there (`1.2.0-xbox.N`) and wait for the fork's CI to publish the release.
3. Update `commit=` in `wibo.ref`, and the URL and sha256 of `[wibo-xbox]` in `toolchains.toml`.

## What the patches add

| Commit | Adds | Why |
|---|---|---|
| 641aac7 | A minimal built-in `OLEAUT32.dll`: `SysAllocString` (ordinal 2), `SysFreeString` (6), `GetErrorInfo` (200, always "no error object") | `Link.Exe` delay-loads these on `/LTCG` links. A missing module made the delay-load helper raise an exception (exit code 126). |
| 5716c58 | `lstrcmpA/W`, `lstrcmpiA/W`, `CopyFileA/W`, `ExpandEnvironmentStringsA/W`, `SearchPathA`, `OpenEventA`, `OpenFileMappingA`, `GetThreadLocale`, `LoadLibraryExA`, `FormatMessageW`, user32 `CharNextA` | `lstrcmpiA` is called on every `Link.Exe` and `Lib.Exe` run. The others are imports of `CL.Exe`, `C1xx.Dll`, `Link.Exe` and the `mspdb` DLLs that wibo aborts on when they are called. |
| 7155135 | `MapViewOfFileEx` at a caller-chosen address is tracked and may replace a released `VirtualAlloc` range | `Link.Exe` probes for free space with `VirtualAlloc`/`VirtualFree` and maps each library there. Without this, a link against the 22 MB `d3d8ltcg.lib` fails with `LNK1104: cannot open file 'TEMPFILE'`. |
| ddf4634 | `rpcrt4!UuidCreate` (random version-4 GUID) | `mspdb71.dll` signs a PDB with it, so `cl /Zi` and `link /DEBUG` aborted without it. |

Shortcuts, so nobody is surprised later:

- `lstrcmp*` compare bytes (`lstrcmpi`: ASCII case folding, `lstrcmpiW`: the C library's `towlower`), not the thread
  locale's word sort. Enough for identifiers and paths.
- `OpenFileMappingA` always reports "not found" (wibo does not register named file mappings); `OpenEventA` finds events
  created through `CreateEvent`.
- `FormatMessageW` supports only `FORMAT_MESSAGE_FROM_SYSTEM` and produces a generic "Win32 error N." text.
- `CharNextA` assumes a single-byte code page; `GetThreadLocale` returns the default user LCID.

## Running the XDK tools

Copy the XDK's `bin/vc71` directory somewhere writable (never modify the original), then, as the XDK tools expect
Windows-style paths:

```sh
export INCLUDE='Z:\path\to\XDK\xbox\include' LIB='Z:\path\to\XDK\xbox\lib'
wibo vc71/CL.Exe /nologo /c /O2 /GL Z:/path/to/file.cpp /Fo/path/to/file.obj
wibo vc71/Link.Exe /nologo /DLL /NOENTRY /NODEFAULTLIB /LTCG /OUT:/path/to/case.dll file.obj
```

A source file given as a Unix absolute path is parsed as an option by `cl`; use a relative path or `Z:/...`
(wibo maps `Z:` to the Linux root).
