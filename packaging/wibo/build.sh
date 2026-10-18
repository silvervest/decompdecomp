#!/usr/bin/env bash
# Build wibo 1.2.0 plus the patch series in packaging/wibo/patches/ (Xbox XDK 5849 Link.Exe / Lib.Exe support).
#
#   packaging/wibo/build.sh [output-dir]       (default: packaging/wibo/out)
#
# Clones decompals/wibo at tag 1.2.0 into <output-dir>/wibo-src, applies the patches with `git am`, builds the
# 64-bit Linux release binary and prints its sha256. The binary is <output-dir>/wibo.
#
# Build requirements (Linux x86_64): git, cmake, ninja, a C++20 compiler, python3, libclang (used by wibo's
# trampoline generator) and a linker that understands --image-base (LLD).
#   Default preset: release64-clang (needs clang, lld and libclang from your distro).
# Overrides:
#   WIBO_PRESET      cmake preset to use (e.g. release64 for GCC + LLD)
#   WIBO_CMAKE_ARGS  extra cmake configure arguments, e.g.
#                    "-DLIBCLANG_LIBRARY=/path/libclang.so -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld"
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(mkdir -p "${1:-$here/out}" && cd "${1:-$here/out}" && pwd)"
src="$out/wibo-src"
preset="${WIBO_PRESET:-release64-clang}"

rm -rf "$src"
git clone --quiet https://github.com/decompals/wibo "$src"
git -C "$src" checkout --quiet 1.2.0
git -C "$src" -c user.name=decompdecomp -c user.email=decompdecomp@localhost am --quiet "$here"/patches/*.patch

cd "$src"
# shellcheck disable=SC2086
cmake --preset "$preset" ${WIBO_CMAKE_ARGS:-}
cmake --build --preset "$preset" --target wibo

cp "$src/build/$preset/wibo" "$out/wibo"
sha256sum "$out/wibo"
