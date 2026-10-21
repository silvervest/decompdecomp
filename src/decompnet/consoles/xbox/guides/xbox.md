# Original Xbox (XDK, Visual C++ 7.1)

An Xbox game is an x86 program built with Visual C++ 7.1 from Microsoft's XDK and packed as an XBE. Registers,
calling conventions and frames are as in the x86 guide; this is what differs.

The compiler, headers and kernel
- Visual C++ 7.1 (XDK 5849: 13.10.3077), default flags `/O2 /G6 /GF /Gy /arch:SSE /D_XBOX` (tools/configure.py).
  The headers are the user's own XDK: include `<xtl.h>` for Xbox types; never copy XDK headers into the project.
- `/Gy` pads functions to 16 bytes with int3: that padding isn't part of a function.
- Kernel calls are `call dword ptr [__imp__<Name>]` (the kernel thunk table, named like Windows imports). Declare
  them as imports (`extern "C" __declspec(dllimport) LONG NTAPI NtClose(HANDLE);`); `xtl.h` declares most.
- /arch:SSE: floats are mostly x87 (`fld`, `fcomp` + `fnstsw ax`), some SSE (`movss`, `mulss`, `comiss`,
  `cvttss2si` instead of `_ftol`). `__declspec(align(16))` locals give `and esp, -16` frames. Intrinsics
  (`memcpy`, `strlen`, `fabs`, `sqrt`) are inline at /O2. Direct3D calls are often inlined push-buffer writes from
  `d3d8.h`: write the D3D call, not the stores.
- The XDK's own code (Direct3D, DirectSound, XNet, the C runtime, XAPI) is set aside and never reaches you, unless
  the project covers the whole program: then its functions (units named `xdk_<address>`) are yours too, built as
  plain units (no harness driver is made for them). In a project of the game's own code, if a function still looks like CRT or XAPI code (`_memcpy`,
  `XapiInitProcess`), say so in a note and release it.

Link-time code generation (LTCG)
Games built with `/GL` and `/LTCG` pass arguments and `this` in eax, esi, edi or ebx, with no standard convention,
and inline across files. In a project made without the LTCG mode (no `"ltcg": true` in `.decomp.wtf.json`), plain
compiles can't match those functions: note "LTCG register convention" and release. In an LTCG project:
- A unit whose driver `harness/<unit>.drv.cpp` defines `extern "C" __declspec(dllexport) void HarnessEntry(...)` is
  compiled with /GL and linked with /LTCG through that harness; your compile_and_diff goes through it, and the
  linker picks the registers from the driver's calls. Write ordinary C/C++ and compile: a register convention is
  never a reason to release such a function untried.
  - The driver calls the unit's functions the way the original's call sites do: what eax/esi/edi/ebx/ecx hold
    right before the call, which pushes are constants.
  - `harness/<unit>.<name>.cpp` holds stand-ins for what the unit calls or reads elsewhere, shaped like the real
    ones (registers read, preserved, returned); `<name>.nogl.cpp` compiles without /GL (code the game's link
    couldn't see into: middleware, XDK libraries). `// HARNESS-LINK: <flags>` adds linker flags (`d3d8ltcg.lib`).
  - Functions are found by func_<address> in their names or `// FUNCTION: 0x<address> [map symbol]` before the
    definition (needed for constructors, destructors and operators).
  - `standins_for(unit)` writes a starting point: stand-ins with their conventions, a HarnessEntry with each
    function's call sites, declarations, and the structs its functions look like members of.
- The brief shows each function's convention in the original: registers read before written, stack arguments,
  `ret N`, registers saved, and call sites with what they load before the call. When yours differs, fix the
  driver's call or a stand-in so it looks like the original's call site.
- Adding a helper function or a call site changes conventions under LTCG. The linker specialises a callee with
  a single call site (arguments left where that caller has them, saves dropped); a second caller (a helper, a
  driver call, a stand-in) can make it standard again, or the reverse. After adding one, check the convention
  evidence again (the brief's convention against your compile's), and keep the original's number of call sites.
- Member functions: `this` can arrive in any register (Accum::Add gets it in esi); write a member function when
  the brief says the function is one, and it still matches. A free function's pointer can arrive the same way:
  prefer a member function when its struct has other member functions (`get_class`). A function using two
  registers at the same offsets is a function of two objects ("Two objects alike").
- Unresolved names: the harness link goes on without them (`/FORCE:UNRESOLVED`) and the judge writes the
  original's reference in their place. The brief and compile_and_diff list them by kind:
  - data (a global, a D_<address>, a pool constant): not always harmless. Under LTCG the compiler sees a
    global's definition, type and constness, and an unresolved one can change scheduling and code around its
    loads. Define it, with its real type, in the unit or a harness file; don't release or wait for it. An
    unresolved D_<address> isn't checked, so a wrong address only shows once it's defined;
  - a callee called with a standard convention (__cdecl, __stdcall, __thiscall): harmless;
  - a callee passed arguments in other registers: the call differs until a definition is in the link. Write a
    stand-in shaped like the original's yourself, in the same claim (RunAccum: 83% to a match that way);
  - a callee the original inlines (no call to it in the target): its body must be in the link;
  - library code (XDK, C runtime): leave it unresolved, declared as its header has it; a /GL stand-in changes
    the calls to it (sprintf: a match unresolved, 89% stood in). If one is needed, `<name>.nogl.cpp`.
- Float constants the target loads by address (the diff shows their values): try both forms, the literal (`0.5f`)
  and an `extern const float D_<address>`, and keep the better score; the loads schedule differently and either
  can win (ParticleStep matched only with the literal; on Burnout 3 the literal gave 59.1%, the externs 65.8%).
  On equal scores prefer the literal: the game's literal lives in .rdata, and a named D_ extern doesn't port.
  Sometimes the matching form is a folded expression (`1.0f - 1.3f`, not `-0.3f`).
- 100% isn't a match until the references map one to one onto the original's, a name that says an address
  (`D_<address>`, `func_<address>`, a global with `// GLOBAL: 0x<address>` before it) means the original's, and
  floats and strings have its values. The judge says so when they don't.
- `volatile` in a harness driver or stand-in, to steer the compiler, is forbidden. The harness must reproduce the
  original's call sites and callees faithfully: on Burnout 3, unfaithful harness contexts gave false MATCHes the
  final link lost. In the game's own source, `volatile` is allowed only as a documented exception (a comment
  saying why) when it's the only form that matches.
