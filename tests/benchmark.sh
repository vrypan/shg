#!/bin/sh
set -eu

shg=${SHG_BIN:-zig-out/bin/shg}
shg_config=${SHG_CONFIG_BIN:-zig-out/bin/shg-config}
lines=${SHG_BENCH_LINES:-100000}

case $lines in
    ''|*[!0-9]*|0) printf '%s\n' "SHG_BENCH_LINES must be a positive integer" >&2; exit 2 ;;
esac

tmp=${TMPDIR:-/tmp}/shg-bench-$$
xdg=$tmp/xdg
history=$tmp/history
mkdir -p "$xdg"
trap 'rm -rf "$tmp"' EXIT

HOMEBREW_PREFIX= XDG_CONFIG_HOME="$xdg" "$shg_config" defaults -y >/dev/null
HOMEBREW_PREFIX= XDG_CONFIG_HOME="$xdg" "$shg_config" compile >/dev/null

awk -v lines="$lines" 'BEGIN {
    for (i = 0; i < lines; i++) {
        printf "git status --short clean-command-%d\n", i
    }
}' > "$history"

bytes=$(wc -c < "$history" | tr -d ' ')
printf 'shg scan benchmark: %s lines, %s bytes\n' "$lines" "$bytes"
printf '%s\n' 'command: shg history --one-line --path <generated-history>'

time -p env XDG_CONFIG_HOME="$xdg" "$shg" history --one-line --path "$history" >/dev/null
