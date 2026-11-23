#!/usr/bin/env bash
set -euo pipefail

target=${1:?missing Rust target}
binary=${2:?missing executable path}
bytes=$(wc -c < "$binary")
printf 'Executable `%s` (%s): %d bytes\n' "${binary##*/}" "$target" "$bytes" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

# The default Linux musl build was measured locally. Other targets report size only.
if [[ $target == x86_64-unknown-linux-musl ]] && (( bytes > 4 * 1024 * 1024 )); then
    echo 'The default x86_64 musl executable exceeds its 4 MiB budget.' >&2
    exit 1
fi
