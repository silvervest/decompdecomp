"""Find and replace one function in a C or C++ source file.

Handles real definitions (including K&R and C++ `Class::method` forms) and the stubs decomp projects use for
functions that aren't decompiled yet: `INCLUDE_ASM(...)`, `GLOBAL_ASM(...)` / `#pragma GLOBAL_ASM(...)`.
"""

from __future__ import annotations

import re

_COMMENT_OR_STRING = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def _blank(text: str) -> str:
    """Same length, with comments and strings blanked, so braces inside them don't count."""
    return _COMMENT_OR_STRING.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def _stub(text: str, name: str) -> tuple[int, int] | None:
    pat = re.compile(rf"^[ \t]*(?:#\s*pragma\s+)?(?:INCLUDE_ASM|GLOBAL_ASM|INCLUDE_RODATA_FN)\s*\((?:[^;\n]*[\"/,\s]){re.escape(name)}(?:\.s)?[\"\s]*\)\s*;?[ \t]*\n?", re.M)
    m = pat.search(text)
    return (m.start(), m.end()) if m else None


def is_stub(code: str) -> bool:
    """True for an asm stub (INCLUDE_ASM / GLOBAL_ASM line) rather than a C definition."""
    return bool(re.match(r"\s*(?:#\s*pragma\s+)?(?:INCLUDE_ASM|GLOBAL_ASM|INCLUDE_RODATA_FN)\s*\(", code))


ADDRESS_KEY = "// FUNCTION: 0x"  # find(text, address_key(va)): the definition annotated with the original's address
_ANNOTATION = re.compile(r"^[ \t]*//[ \t]*FUNCTION:[ \t]*0x([0-9a-fA-F]+)\b[^\n]*(?:\n|$)", re.M)


def address_key(addr: int) -> str:
    """A name for find() meaning the definition after a `// FUNCTION: 0x<address>` annotation (reccmp's form, which
    decompilations of PC and Xbox games put before each function: its own name can be anything)."""
    return f"{ADDRESS_KEY}{addr:X}"


def _block_end(clean: str, brace: int) -> int:
    depth, k = 0, brace
    while k < len(clean):
        depth += (clean[k] == "{") - (clean[k] == "}")
        k += 1
        if depth == 0:
            break
    return k


def _annotated(text: str, addr: int) -> tuple[int, int] | None:
    """The first function definition after the annotation, before the next one: types and declarations the code
    needs may come in between (`struct CRigOwner { ... };`)."""
    found = list(_ANNOTATION.finditer(text))
    clean = None
    for n, m in enumerate(found):
        if int(m.group(1), 16) != addr:
            continue
        clean = clean if clean is not None else _blank(text)
        bound = found[n + 1].start() if n + 1 < len(found) else len(text)
        pos = m.end()
        while True:
            brace = clean.find("{", pos, bound)
            if brace < 0:
                break  # only declarations up to the next annotation
            head_at = max(clean.rfind(";", pos, brace), clean.rfind("}", pos, brace), pos - 1) + 1
            head = clean[head_at:brace]
            if "(" not in head or re.match(r"\s*(?:typedef\s+)?(?:struct|class|union|enum|namespace)\b", head):
                pos = _block_end(clean, brace)  # a type (or a brace initialiser): past it
                continue
            i = head_at
            while i < brace:  # comments, blank and #pragma lines before the definition's first line
                end = text.find("\n", i)
                end = len(text) if end < 0 else end
                line = text[i:end].strip()
                if line and not line.startswith(("//", "#")):
                    break
                i = end + 1
            k = _block_end(clean, brace)
            if k < len(text) and text[k] == "\n":
                k += 1
            return min(i, brace), k
    return None


def defined_name(text: str, span: tuple[int, int]) -> str | None:
    """The name a definition gives its function (`CAIBehaviour::Update` for `void CAIBehaviour::Update(int)`)."""
    head = _blank(text[span[0]:span[1]]).split("(", 1)[0]
    m = re.search(r"((?:[\w~<>]+::)*~?\w+|(?:[\w<>]+::)*operator\s*\S+)\s*$", head)
    return m.group(1) if m else None


def find(text: str, name: str) -> tuple[int, int] | None:
    """(start, end) of the definition of `name`, or of its asm stub; None when absent. `name` may be an
    address_key(): the definition annotated with that address."""
    if name.startswith(ADDRESS_KEY):
        return _annotated(text, int(name[len(ADDRESS_KEY):], 16))
    clean = _blank(text)
    simple = name.split("::")[-1]
    if "::" in name:  # Class::method: match it exactly
        pat = re.compile(rf"(?<![\w:~]){re.escape(name)}\s*\(")
    else:  # plain name: also match a definition written as Class::name
        pat = re.compile(rf"(?<![\w:~])(?:[\w~<>]+::)*{re.escape(name)}\s*\(")
    for m in pat.finditer(clean):
        # walk to the end of the parameter list
        depth, i = 0, m.end() - 1
        while i < len(clean):
            c = clean[i]
            depth += (c == "(") - (c == ")")
            i += 1
            if depth == 0:
                break
        # a definition continues with optional qualifiers (const, throw()) or K&R parameter declarations, then '{'
        j = i
        while j < len(clean) and clean[j].isspace():
            j += 1
        if j < len(clean) and clean[j] == ";":
            continue  # a prototype or a call
        while j < len(clean) and clean[j] != "{":
            nxt = clean.find(";", j)
            brace = clean.find("{", j)
            if brace == -1:
                j = len(clean)
                break
            if nxt == -1 or brace < nxt:
                j = brace
                break
            if any(c in clean[j:nxt] for c in "(){}="):
                j = len(clean)
                break
            j = nxt + 1  # one K&R parameter declaration
        if j >= len(clean) or clean[j] != "{":
            continue
        line_start = clean.rfind("\n", 0, m.start()) + 1
        if clean[line_start:m.start()].strip().startswith(("#", "return", "if", "else")):
            continue
        # include the return type / storage class on preceding lines that belong to this declaration
        start = line_start
        prev_end = start - 1
        while prev_end > 0:
            prev_start = clean.rfind("\n", 0, prev_end) + 1
            prev = clean[prev_start:prev_end].strip()
            if prev and not prev.endswith((";", "}", "{", ")")) and not prev.startswith("#") and re.fullmatch(r"[\w\s\*&:<>,]+", prev):
                start = prev_start
                prev_end = prev_start - 1
            else:
                break
        depth, k = 0, j
        while k < len(clean):
            depth += (clean[k] == "{") - (clean[k] == "}")
            k += 1
            if depth == 0:
                break
        if k < len(text) and text[k] == "\n":
            k += 1
        return start, k
    return _stub(text, simple)


# reccmp's annotations (`// FUNCTION: 0x...`, `// GLOBAL:`, `// STUB:`) say which of the original's functions a
# definition is: the project's markers, not a description of it
_MARKER = re.compile(r"//\s*[A-Z][A-Z_]*:")


def comment_above(text: str, start: int) -> int:
    """Where the comment right above a definition (at `start`, a line's start) begins: its `//` lines and `/* */`
    blocks, with no blank line between, up to a marker such as `// FUNCTION:`; `start` when there's none. A polished
    function's comment saying what it does belongs to it (a project's file kept only the definition)."""
    at = start
    while at > 0:
        prev = text.rfind("\n", 0, at - 1) + 1
        line = text[prev:at].strip()
        if line.startswith("//") and not _MARKER.match(line):
            at = prev
        elif line.endswith("*/") and (opens := text.rfind("/*", 0, at)) >= 0 \
                and not text[text.rfind("\n", 0, opens) + 1:opens].strip():
            at = text.rfind("\n", 0, opens) + 1
        else:
            break
    return at


def get(text: str, name: str) -> str | None:
    span = find(text, name)
    return text[span[0]:span[1]] if span else None


def replace(text: str, name: str, code: str) -> str:
    """Put `code` in place of the function (or its stub); append it when the function isn't there yet."""
    code = code.strip("\n") + "\n"
    span = find(text, name)
    if span is None:
        return text.rstrip("\n") + "\n\n" + code
    return text[:span[0]] + code + text[span[1]:]
