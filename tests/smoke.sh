#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

shg=${SHG_BIN:-zig-out/bin/shg}
shg_config=${SHG_CONFIG_BIN:-zig-out/bin/shg-config}

# A brew-installed shg ships system defaults under $HOMEBREW_PREFIX; clear it
# so shg-config uses the test XDG dir instead of short-circuiting to Homebrew.
HOMEBREW_PREFIX=
export HOMEBREW_PREFIX
tp=testdata/corpus/true_positives/zsh_sample.txt
fp=testdata/corpus/false_positives/bash_safe.txt
full_secret=sk-abcdefghijklmnopqrstuvwxyz012345678901234567
tmp=${TMPDIR:-/tmp}/shg-smoke-$$
xdg=$tmp/xdg
mkdir -p "$xdg"
trap 'rm -rf "$tmp"' EXIT

say() {
    printf '%s\n' "$*"
}

run_capture() {
    status=0
    output=$("$@" 2>&1) || status=$?
}

say "TEST missing compiled rules warning"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$fp"
test "$status" -eq 2
printf '%s\n' "$output" | grep -q 'shg: no compiled rules found; run shg-config compile'
say "PASS missing compiled rules warning"

say "TEST write default config files"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg_config" defaults -y
test "$status" -eq 0
test -s "$xdg/shg/ignore.default.shg"
test -s "$xdg/shg/match.default.shg"
test -s "$xdg/shg/paths.default.shg"
grep -q 'prefix:SSH_AUTH_SOCK=' "$xdg/shg/ignore.default.shg"
grep -q 'PRIVATE KEY' "$xdg/shg/match.default.shg"
grep -q '~/.zsh_history' "$xdg/shg/paths.default.shg"
printf '%s\n' 'custom-default-content' > "$xdg/shg/match.default.shg"
run_capture sh -c 'printf "n\nn\nn\n" | env XDG_CONFIG_HOME="$1" "$2" defaults' sh "$xdg" "$shg_config"
test "$status" -eq 0
grep -q 'custom-default-content' "$xdg/shg/match.default.shg"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg_config" defaults -y
test "$status" -eq 0
grep -q 'PRIVATE KEY' "$xdg/shg/match.default.shg"
if grep -q 'custom-default-content' "$xdg/shg/match.default.shg"; then
    printf '%s\n' "defaults -y did not overwrite existing file" >&2
    exit 1
fi
say "PASS write default config files"

say "TEST create compiled config rules"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg_config" compile
test "$status" -eq 0
test -s "$xdg/shg/rules.bin"
say "PASS create default compiled config rules"

say "TEST configured history paths"
home=$tmp/home
mkdir -p "$home"
printf '%s\n' 'echo ghp_abcdefghijklmnopqrstuvwxyz012345' > "$home/.zsh_history"
run_capture env XDG_CONFIG_HOME="$xdg" HOME="$home" "$shg" scan --env false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$home/.zsh_history"
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS configured history paths"

say "TEST --path accepts a directory and walks it"
walkdir=$tmp/walk/nested
mkdir -p "$walkdir"
printf '%s\n' 'ls -la' > "$tmp/walk/clean_history"
printf '%s\n' 'echo ghp_abcdefghijklmnopqrstuvwxyz012345' > "$walkdir/session.jsonl"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$tmp/walk"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$walkdir/session.jsonl"
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS --path accepts a directory and walks it"

say "TEST environment history path"
histfile=$tmp/custom_history
printf '%s\n' 'echo ghp_abcdefghijklmnopqrstuvwxyz012345' > "$histfile"
run_capture env XDG_CONFIG_HOME="$xdg" HISTFILE="$histfile" "$shg" scan --env false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$histfile"
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS environment history path"

say "TEST piped history"
run_capture sh -c 'printf "%s\n" "echo ghp_abcdefghijklmnopqrstuvwxyz012345" | env XDG_CONFIG_HOME="$1" "$2" scan --env false' sh "$xdg" "$shg"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '<stdin>'
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS piped history"

say "TEST oversized history line is skipped, scan continues"
longfile=$tmp/long_history
{
    awk 'BEGIN { printf "echo "; for (i = 0; i < 70000; i++) printf "a"; printf "\n" }'
    printf '%s\n' 'echo ghp_abcdefghijklmnopqrstuvwxyz012345'
} > "$longfile"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$longfile"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q 'skipped 1 oversized line(s)'
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS oversized history line is skipped, scan continues"

say "TEST explicit path ignores piped history"
run_capture sh -c 'printf "%s\n" "echo ghp_abcdefghijklmnopqrstuvwxyz012345" | env XDG_CONFIG_HOME="$1" "$2" scan --env false --path "$3"' sh "$xdg" "$shg" "$fp"
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'
say "PASS explicit path ignores piped history"

say "TEST scan true-positive corpus"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$tp" --level low
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '5 finding(s) detected (3 high, 2 medium, 0 low).'
printf '%s\n' "$output" | grep -q '\[credential_url\]'
if printf '%s\n' "$output" | grep -q "$full_secret"; then
    printf '%s\n' "redacted scan output leaked full secret" >&2
    exit 1
fi
say "PASS scan true-positive corpus"

say "TEST scan true-positive corpus with --redacted=false"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --redacted=false --path "$tp" --level low
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$full_secret"
say "PASS scan true-positive corpus with --redacted=false"

say "TEST scan false-positive corpus"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$fp"
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'
say "PASS scan false-positive corpus"

say "TEST scan environment variables"
run_capture env -i XDG_CONFIG_HOME="$xdg" SHG_SMOKE_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345 "$shg" scan --hist false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '<env>'
printf '%s\n' "$output" | grep -q '\[inline_assign\]'
if printf '%s\n' "$output" | grep -q 'ghp_abcdefghijklmnopqrstuvwxyz012345'; then
    printf '%s\n' "environment scan output leaked full secret" >&2
    exit 1
fi
say "PASS scan environment variables"

say "TEST skip known non-secret environment variables"
run_capture env -i XDG_CONFIG_HOME="$xdg" \
    SSH_AUTH_SOCK=/tmp/ssh-agent/socket \
    STARSHIP_SESSION_KEY=abcdefghijklmnopqrstuvwxyz0123456789 \
    GPG_AGENT_INFO=/tmp/gpg-agent:1234:1 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-session \
    PWD=/Users/example/project \
    OLDPWD=/Users/example \
    OLD_PWD=/Users/example/old \
    "$shg" scan --hist false
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'
say "PASS skip known non-secret environment variables"

say "TEST compiled config rules"
printf '%s\n' 'IGNORED_TOKEN=' > "$xdg/shg/ignore.local.shg"
printf '%s\n' 'custom-secret-pattern' > "$xdg/shg/match.local.shg"
printf '%s\n' 'extra-secret-pattern' > "$xdg/shg/match.extra.shg"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg_config" compile
test "$status" -eq 0
run_capture env -i XDG_CONFIG_HOME="$xdg" \
    IGNORED_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345 \
    CUSTOM_VALUE=custom-secret-pattern \
    EXTRA_VALUE=extra-secret-pattern \
    "$shg" scan --hist false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '\[config_check\]'
printf '%s\n' "$output" | grep -q 'EXTRA_VALUE'
if printf '%s\n' "$output" | grep -q 'ghp_abcdefghijklmnopqrstuvwxyz012345'; then
    printf '%s\n' "ignore.*.shg did not suppress ignored token" >&2
    exit 1
fi
say "PASS compiled config rules"

say "TEST shg env scans environment only"
run_capture env -i XDG_CONFIG_HOME="$xdg" SHG_SMOKE_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345 "$shg" env
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '<env>'
say "PASS shg env scans environment only"

say "TEST shg history scans a history file"
histf=$tmp/hist_only
printf '%s\n' 'echo ghp_abcdefghijklmnopqrstuvwxyz012345' > "$histf"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" history --path "$histf"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$histf"
printf '%s\n' "$output" | grep -q '\[known_token\]'
say "PASS shg history scans a history file"

say "TEST shg deep scans transcripts (per session)"
adir=$tmp/agents/.claude/projects/p
mkdir -p "$adir"
agent_tok=ghp_abcdefghijklmnopqrstuvwxyz012345
printf '%s\n' "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":\"env dump $agent_tok\"}]}}" > "$adir/s.jsonl"
printf '%s\n' "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":\"again $agent_tok\"}]}}" >> "$adir/s.jsonl"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" deep --path "$adir"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$adir/s.jsonl"
printf '%s\n' "$output" | grep -q 'known_token'
printf '%s\n' "$output" | grep -q '(2'
printf '%s\n' "$output" | grep -q 'delete the affected session files'
# distinct token reported once, not once per occurrence
test "$(printf '%s\n' "$output" | grep -c 'known_token')" -eq 1
if printf '%s\n' "$output" | grep -q "$agent_tok"; then
    printf '%s\n' "deep output leaked full secret" >&2
    exit 1
fi
say "PASS shg deep scans transcripts (per session)"

say "TEST shg deep is strict by default, --thorough loosens"
tdir=$tmp/thorough/.claude/projects/p
mkdir -p "$tdir"
printf '%s\n' "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":\"$agent_tok and max_output_tokens=max_output_tokens_value_here\"}]}}" > "$tdir/s.jsonl"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" deep --path "$tdir"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q 'known_token'
if printf '%s\n' "$output" | grep -q 'inline_assign'; then
    printf '%s\n' "deep strict default showed a loose detector" >&2
    exit 1
fi
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" deep --path "$tdir" --thorough
test "$status" -eq 1
printf '%s\n' "$output" | grep -q 'inline_assign'
say "PASS shg deep is strict by default, --thorough loosens"

say "TEST deprecated shg agents still works and warns"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" agents --path "$adir"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "'agents' is deprecated"
printf '%s\n' "$output" | grep -q 'known_token'
say "PASS deprecated shg agents still works and warns"

say "SMOKE PASS"
