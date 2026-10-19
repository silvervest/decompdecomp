# Roadmap

What's planned for decompdecomp, roughly in order, and why. Every item keeps the rule that matters most: a match is
byte-identical after linking (ROM mode) or objdiff 100% (fork mode). Nothing here accepts code that only does the
same thing.

Want to work on one? Open an issue first, so two people don't build the same thing. CONTRIBUTING.md has the rest.

## What works where

Each feature and the platforms it covers today. A — is a gap: pick one up (the notes under the table say where to
start). Keep this table true when a feature ships or reaches another platform.

| Feature | N64 | PS1 | PS2 | GBA | GameCube · Wii | DS | Windows PC | Xbox | Public decomps |
| :-- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Start from your own copy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ XBE or disc, your own XDK | fork by address |
| Judge | link · compare | link · compare | link · compare | link · compare | objdiff | objdiff | objdiff | objdiff | objdiff |
| Machine drafts (m2c, Ghidra for x86) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ Ghidra | ✓ Ghidra | by architecture |
| Autopilot: free matches from drafts | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | — |
| Twins: free matches from identical code | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ COFF fingerprints | ✓ (an XDK test program: a free match) | ✓ |
| Permuter on near misses | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (an XDK test program: a method matched) | ✓ |
| Hand-written assembly set aside | ✓ | ✓ | ✓ | — | ✓ | — | — | — | MIPS, PowerPC |
| Kernel and BIOS stubs set aside | — | ✓ | ✓ | — | — | — | — | ✓ XDK library code | — |
| Function-end reports (`report_boundary`) | ✓ | ✓ | ✓ | — | — | — | — | — | — |
| Compiler ranges and suggestions | ✓ | ✓ | ✓ | ✓ | the project's build | the project's build | the project's build | the project's build | the project's build |
| Compiler map and the judge's survey | ✓ | ✓ | ✓ | — | — | — | — | — | — |
| Range checks: a range applies after its neighbours confirm it | ✓ | ✓ | ✓ | — | — | — | — | — | — |
| C++ classes from the code (`get_class`) | ✓ | ✓ | ✓ | — | — | — | ✓ structs and classes, member functions in briefs (the Xbox reader; untested on a PC program) | ✓ structs and classes, member functions in briefs and stand-ins (XDK test programs) | — |
| Rebuildable export | ✓ | ✓ | ✓ | ✓ | the project | the project | `ninja export` (homemade programs) | `ninja export`: the game's linker and imagebld, LTCG units from their harness links | the project |
| LTCG games (`/GL`: register conventions, cross-file inlining) | | | | | | | | harness mode, detected at import (or chosen); convention evidence, stand-in drafts, data check | |
| Rooms: decompile together | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | as PC (untested) | ✓ |

Where to start on a gap:
- **ARM (GBA, DS)**: assembly detection is `handwritten.py` (`mips_reason` and `ppc_reason` show the shape); the
  compiler map and class recovery read MIPS in `compilermap.quirks` and `classes.scan`, and want an ARM reader.
- **PowerPC (GameCube, Wii)**: class recovery and the compiler map work on a project's objects in fork mode, not on a
  ROM; the reader is the part to write (CodeWarrior's vtable pointer is often not at offset 0). x86's is
  `forks/methods.py` (it reads the program and functions.json, as the convention evidence does).
- **x86 member functions**: `forks/methods.py` can't tell a free function taking a pointer from a member function
  when LTCG moves both into a register, and it groups a base class's functions, and a member object's at +0, with
  the object they're called on. Names from another build (below) would settle both.
- **Windows PC**: autopilot needs drafts that compile (Ghidra's output doesn't, as it is). The export
  (`tools/export.py`) is tested on homemade programs only: a real game's import table and resources are carried as
  bytes and its headers are your copy's, and a program with base relocations (.reloc) is untested (it links /FIXED).
- **PC and Xbox export**: data has no relocations of its own, so the rebuilt program can't move (the modding-ready
  check below is the next step). A game built with link-time code generation is rebuilt from each unit's harness
  link; a whole-program /LTCG link of the matched source needs all of the game's code as source.
- **Function-end reports** cut MIPS functions (`engine._cut`); GBA has its own splitter (`_split_gba`).
- **Xbox**: rooms haven't been run on Xbox (the room tests use a DS game). Twins and the permuter have only been
  seen on a small test program built with the XDK, not on a real game yet.

## Recently done

- **Agents try before they release, and say what a function waits for.** On a real LTCG Xbox game agents released
  functions seconds after claiming them, untried (12,565 releases, median 5 s), reading the harness link's
  unresolved names as a to-do. Measured on demo_ltcg, each reference left unresolved and then defined: data and
  callees with a standard convention change nothing (the judge writes the original's references in their place);
  callees the original passes registers or inlines do (RunAccum 83% -> match with two stand-ins), and library
  code must stay unresolved (sprintf stood in: 100% -> 89%). Briefs and compile_and_diff now split a function's
  unresolved names into those (`forks/unresolved.py`), and a field of an unresolved global no longer reads as an
  address conflict. release_function answers a release before compile_and_diff's move-on rule once with what to
  do; a release without a compile doesn't count against the session; `needs=<function>` records a prerequisite:
  the function waits (claimed last), the one it needs goes first and is handed over, and the match brings the
  waiting one back first. Notes saying "already matched" on a function that doesn't match are marked out of date.
- **Matches stay matched on PC and Xbox.** A free function that another function of its file calls was listed twice
  by objdiff (the delinked original carried an undefined copy of its name), and the unscored copy set the match back
  to open at the next attempt in the file. Each function now counts once, and delink.py refers to the definition.
  With matches kept, twins and the permuter give free matches on an XDK test program.

- **Range checks** (MIPS ROM projects). An agent's "this range was built by another compiler" is a hypothesis: the
  judge tests the functions next to it (their matches, agents' attempts, the survey, habits), and where nothing
  settles it the nearest neighbour goes to an agent as a task. A range applies once a second function matches only
  with its compiler; refuted neighbours on both sides make it a quirk (dismissed, with a note on the function). The
  applied ranges can be checked again the same way (a report). On GTA San Andreas's 72 ranges: 12 confirmed, about
  25 resting on one function, about 36 with no function whose C needs their compiler.

- **Compiler map** (MIPS: PlayStation 2, PlayStation, N64): which compiler built each part of the game. Measured on
  GTA San Andreas, compilers' habits only rule compilers out (-G0 code never reads through `$gp`; its CodeWarrior
  code never uses branch-likely), so what rules a compiler in is the judge: the survey builds agents' C for unmatched
  functions with each compiler the project uses, and C that matches with another compiler (and not today's)
  confirms it. Confirmations spread over their neighbours (one object file is one compiler) up to the furthest
  evidence; a run big enough becomes a suggestion, checked against every matched function. The ROM map shows it
  (Compiler view); agents read it with `compiler_map` and in `get_function`.
- **C++ classes from the game's code** (MIPS: PlayStation 2, PlayStation, N64). Constructors store their class's
  vtable into the object; from those stores decompdecomp finds each class, its virtual functions, its base class and
  every field its functions touch (offset, type). Agents read them with `get_class`; `get_function` names the fields
  of `this` a function uses. On GTA San Andreas: 507 classes, and the recovered entity layout (position at +4, matrix
  pointer at +0x14, model index at +0x22) is the one found by hand. Why: functions with virtual calls matched 7% of
  the time against 62% for the rest, because agents guessed the layouts.
- **Structs and classes for PC and Xbox** (MSVC, fork mode, `forks/methods.py`). A function that uses `this` (ecx
  under __thiscall; under LTCG the register the convention evidence finds) as the base of field accesses is a member
  function; functions called on one global object, local or returned pointer, passing `this` on, or sitting in a
  vtable a constructor stores are one struct or class, with the fields they touch. The brief says "Looks like a
  member function of ..." with the declaration to write, `get_class` has the layout and a declaration, and
  `standins_for` drafts the structs. Why: on an Xbox test program agents wrote Accum::Add as a free function taking
  an `Accum *`. Measured against the link maps of the XDK test programs: "is a member function" precision 100% /
  recall 100% without LTCG (fog: 35 of 35; the demo: 7 of 7), 94% / 85% (fog) and 69% / 100% (the demo) with LTCG,
  where free functions taking a pointer in a register look the same.
- **Linux packages**: a `.deb` and an AppImage with their own Python, built for each release.
- **Its own window and a tray icon**, so closing the window doesn't stop helper agents.

## Next

### Twins across your games

Twins already give free matches for code a game has more than once. PlayStation 2 games share RenderWare, Sony's
libraries and libc, so a library function matched in one of your games should be tried in all your others: a
fingerprint index shared by your projects, the same trial, the same judge. No agent time; nothing leaves your
computer.

### Names from another build you own

Many games have a second build with symbols: a demo, a prototype, or a port to another platform. C++ symbols say the
class and the parameter types, so carrying them over gives agents real signatures. Pair functions by the text and
constants they use, spread the pairs through the call graph, and let the user approve the names in bulk (as boundary
reports are approved now). Names only: matching is unaffected. It also names the classes `get_class` finds.

### C++ classes for PowerPC

The class recovery reads MIPS and x86 (MSVC, PC and Xbox) today. GameCube and Wii (CodeWarrior: the vtable pointer
often isn't at offset 0) work the same way with their own instruction reader, in fork mode.

### A modding-ready check for the export

The export rebuilds the game byte for byte; mods need code that can move. Build a second copy with padding inserted
and report every address that is still hard-coded ("93% movable, 41 addresses left"). The matching build stays as
it is.

### A shareable progress card

An image with % matched, functions and platform, for READMEs and posts. No game code in it.

## Later

- A tray icon on Windows (decompdecomp runs in WSL there; it needs a small Windows program).
- macOS.
