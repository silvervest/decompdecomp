# Original Xbox (XDK, Visual C++ 7.1)

An Xbox game is a Windows-style x86 program. It was built with Visual C++ from Microsoft's Xbox Development Kit
(the XDK) and packed as an XBE. Read the x86 guide first: registers, calling conventions and frames are the same.
This guide is what differs.

The compiler and the headers
- The compiler is Visual C++ 7.1 (XDK 5849 ships build 13.10.3077). The project builds with the same files.
- The headers are the user's own XDK (`xtl.h`, the Xbox `d3d8.h`, the XDK's C runtime). Include `<xtl.h>` when you
  need Xbox types. Never copy XDK headers into the project.
- The default flags are `/O2 /G6 /GF /Gy /arch:SSE /D_XBOX`. The project's tools/configure.py holds them.
- `/Gy` gives every function its own section. The linker pads functions to 16 bytes with int3 (0xCC). That padding
  isn't part of a function: don't try to match it.

Kernel calls
- There is no import table. The kernel thunk table is a list of slots, one per xboxkrnl.exe export. The loader
  fills each slot with the kernel function's address.
- A kernel call is `call dword ptr [slot]`. The project names each slot `__imp__<Name>`, as a Windows import:
  `__imp__NtClose`, `__imp__KeQueryPerformanceCounter`.
- In C, declare the kernel function as an import: `extern "C" __declspec(dllimport) LONG NTAPI NtClose(HANDLE);`.
  Most of them are declared by `xtl.h` already. Kernel data (`KeTickCount`) is read through its slot too.

Visual C++ 7.1 with /arch:SSE
- Floats still mostly use x87 (`fld`, `fstp`). With /arch:SSE the compiler also uses SSE for some float code:
  `movss`, `addss`, `mulss`, `comiss`, and `cvttss2si` for float to int instead of a call to `_ftol`.
- Compares through SSE end in `comiss xmm0, xmm1` and a jump on the flags. Compares through x87 still use
  `fcomp` + `fnstsw ax` + `test ah, N`.
- `__declspec(align(16))` locals give an aligned frame: `push ebp; mov ebp, esp; and esp, -16`. Arguments are then
  read through ebp and locals through esp.
- 7.1 schedules more freely than 6.0: statement order changes less of the output, types and declarations more.
- Intrinsics (`memcpy`, `memset`, `strlen`, `abs`, `fabs`, `sqrt`) are expanded inline at /O2.
- Direct3D calls are often inlined push-buffer writes from the XDK's `d3d8.h`: stores to a buffer pointer and a
  compare against its end, with a call to make room. Write the D3D call; don't spell out the stores.

Library code set aside
- Much of an XBE is the XDK's own code: Direct3D, DirectSound, XNet, XOnline, the media and sound libraries, the C
  runtime and XAPI. It's Microsoft's, not the game's.
- decompdecomp leaves the XDK's library sections out of the project. It matches the user's XDK libraries against
  `.text` and sets those functions aside, as hand-written assembly is set aside. You don't get them.
- Library code the matcher missed can still reach you (a hotfix build of a library, a function too short to match
  safely). If a function looks like CRT or XAPI code (`_memcpy`, `_strcmp`, `XapiInitProcess`, `__security_check`),
  say so with a note and release it.

Link-time code generation (LTCG)
- Some games were built with `/GL` and linked with `/LTCG`. Then functions take arguments and `this` in eax, esi,
  edi or ebx, with no standard convention, and code is inlined across files.
- Signs: a call right after loading eax/esi/edi/ebx, in a callee that reads them without saving them, and callees
  without the usual prologue for their argument count.
- The import tells from the program (its log and `.decomp.wtf.json`'s `ltcg_detected` say why); the user can
  also choose (the import's LTCG setting, or `DECOMP_XBOX_LTCG=1/0`).
- Plain compiles can't match those functions. In a project made without the LTCG mode, note it ("LTCG register
  convention") and release it.
- In an LTCG project (its `.decomp.wtf.json` says `"ltcg": true`), the brief shows each function's convention in
  the original: the registers it reads before writing (its register parameters), its stack arguments, `ret N`, the
  registers it saves, and a few call sites with what they load just before the call.
- `standins_for(unit)` writes a starting point for a unit's harness from the original's references: stand-ins for
  the data and functions it uses from elsewhere (each with its convention), a HarnessEntry with the call sites of
  each of the unit's functions, and the declarations its source needs. Write them with edit_file, then shape them.
- A unit is linked in harness mode once its driver `harness/<unit>.drv.cpp` defines
  `extern "C" __declspec(dllexport) void HarnessEntry(...)`:
  - the driver calls the unit's functions the way the original's call sites do: look at a caller's code right
    before the call (what eax/esi/edi/ebx/ecx hold, which pushes are constants) and write a call that gives the
    linker the same facts;
  - `harness/<unit>.<name>.cpp` hold stand-ins for what the unit calls or reads elsewhere, shaped like the real
    ones (which registers they read, preserve and return). `<name>.nogl.cpp` compiles without `/GL`, for code the
    game's link couldn't see into (middleware, XDK libraries);
  - `// HARNESS-LINK: <flags>` adds linker flags for the unit (`d3d8ltcg.lib` when it inlines Direct3D calls);
  - functions are found by func_<address> in their names, or by `// FUNCTION: 0x<address> [map symbol]` before
    the definition (needed for constructors, destructors and operators).
- A unit's function can read 100% and still not be a match: its references must map one to one onto the
  original's (one original global is always the same one of yours), and a reference that says which original
  address it means (a `D_<address>` or `func_<address>` name, or a global with `// GLOBAL: 0x<address>` on the line
  before its declaration) must mean the one the original uses there; floats and strings must have its values. The
  judge says so when they don't, and progress doesn't count the function.
