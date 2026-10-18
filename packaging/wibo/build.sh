#!/usr/bin/env bash
# Build the wibo that Xbox projects use (our fork's `xbox` branch, pinned in wibo.ref) from source.
#
#   packaging/wibo/build.sh [output-dir]       (default: packaging/wibo/out)
#
# The release binary decompdecomp installs is a release of the wibo fork, built by wibo's own CI from the same commit
# in wibo's Alpine image (static, with wibo's tests). This script is the local recipe: it clones the pinned commit into
# <output-dir>/wibo-src, builds the 64-bit Linux release binary and prints its sha256. The binary is <output-dir>/wibo.
#
# With Docker (WIBO_DOCKER=1) it builds as the release does: a static binary in wibo's Alpine image. Without Docker it
# needs (Linux x86_64): git, cmake, ninja, a C++20 compiler, python3, libclang (used by wibo's trampoline generator)
# and a linker that understands --image-base (LLD).
#   Default preset: release64-clang (needs clang, lld and libclang from your distro).
# Overrides:
#   WIBO_PRESET      cmake preset to use (e.g. release64 for GCC + LLD)
#   WIBO_CMAKE_ARGS  extra cmake configure arguments, e.g.
#                    "-DLIBCLANG_LIBRARY=/path/libclang.so -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld"
#   WIBO_REPO, WIBO_COMMIT   build another wibo than the one wibo.ref pins
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(mkdir -p "${1:-$here/out}" && cd "${1:-$here/out}" && pwd)"
src="$out/wibo-src"
preset="${WIBO_PRESET:-release64-clang}"
repo="${WIBO_REPO:-$(sed -n 's/^repo=//p' "$here/wibo.ref")}"
commit="${WIBO_COMMIT:-$(sed -n 's/^commit=//p' "$here/wibo.ref")}"

rm -rf "$src"
git clone --quiet "$repo" "$src"
git -C "$src" checkout --quiet "$commit"
version="$(git -C "$src" describe --tags --always)"

if [ "${WIBO_DOCKER:-0}" = 1 ]; then
    docker build --quiet --file "$src/Dockerfile" --target export --build-arg BUILD_TYPE=release \
        --build-arg WIBO_VERSION="$version" --output "type=local,dest=$out/docker" "$src"
    cp "$out/docker/wibo" "$out/wibo"
else
    cd "$src"
    # shellcheck disable=SC2086
    cmake --preset "$preset" -DWIBO_VERSION:STRING="$version" ${WIBO_CMAKE_ARGS:-}
    cmake --build --preset "$preset" --target wibo
    cp "$src/build/$preset/wibo" "$out/wibo"
fi
echo "wibo $version"
sha256sum "$out/wibo"
