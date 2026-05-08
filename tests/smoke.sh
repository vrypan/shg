#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

shg=${SHG_BIN:-zig-out/bin/shg}
tp=testdata/corpus/true_positives/zsh_sample.txt
fp=testdata/corpus/false_positives/bash_safe.txt
full_secret=sk-abcdefghijklmnopqrstuvwxyz012345678901234567

say() {
    printf '%s\n' "$*"
}

run_capture() {
    status=0
    output=$("$@" 2>&1) || status=$?
}

say "TEST scan true-positive corpus"
run_capture "$shg" scan --env false --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '5 finding(s) detected (3 high, 2 medium, 0 low).'
printf '%s\n' "$output" | grep -q 'type:    credential_url'
if printf '%s\n' "$output" | grep -q "$full_secret"; then
    printf '%s\n' "redacted scan output leaked full secret" >&2
    exit 1
fi
say "PASS scan true-positive corpus"

say "TEST scan true-positive corpus with --show-full"
run_capture "$shg" scan --env false --show-full --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$full_secret"
say "PASS scan true-positive corpus with --show-full"

say "TEST scan false-positive corpus"
run_capture "$shg" scan --env false --path "$fp"
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'
say "PASS scan false-positive corpus"

say "TEST scan environment variables"
run_capture env -i SHG_SMOKE_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345 "$shg" scan --hist false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '<env>'
printf '%s\n' "$output" | grep -q 'type:    github_token'
if printf '%s\n' "$output" | grep -q 'ghp_abcdefghijklmnopqrstuvwxyz012345'; then
    printf '%s\n' "environment scan output leaked full secret" >&2
    exit 1
fi
say "PASS scan environment variables"

say "SMOKE PASS"
