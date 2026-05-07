#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

zig build >/dev/null

shg=zig-out/bin/shg
tp=testdata/corpus/true_positives/zsh_sample.txt
fp=testdata/corpus/false_positives/bash_safe.txt
full_secret=sk-abcdefghijklmnopqrstuvwxyz012345678901234567

run_capture() {
    status=0
    output=$("$@" 2>&1) || status=$?
}

run_capture "$shg" scan --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '5 finding(s) detected (3 high, 2 medium, 0 low).'
printf '%s\n' "$output" | grep -q 'type:    credential_url'
if printf '%s\n' "$output" | grep -q "$full_secret"; then
    printf '%s\n' "redacted scan output leaked full secret" >&2
    exit 1
fi

run_capture "$shg" scan --show-full --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$full_secret"

run_capture "$shg" scan --path "$fp"
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'

run_capture "$shg" scan --json --path "$tp"
test "$status" -eq 2
printf '%s\n' "$output" | grep -q "unknown option '--json'"

run_capture "$shg" patterns --json
test "$status" -eq 2
printf '%s\n' "$output" | grep -q "unknown option '--json'"
