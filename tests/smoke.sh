#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

shg=${SHG_BIN:-zig-out/bin/shg}
shg_config=${SHG_CONFIG_BIN:-zig-out/bin/shg-config}
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
grep -q 'ghp_' "$xdg/shg/match.default.shg"
grep -q '~/.zsh_history' "$xdg/shg/paths.default.shg"
printf '%s\n' 'custom-default-content' > "$xdg/shg/match.default.shg"
run_capture sh -c 'printf "n\nn\nn\n" | env XDG_CONFIG_HOME="$1" "$2" defaults' sh "$xdg" "$shg_config"
test "$status" -eq 0
grep -q 'custom-default-content' "$xdg/shg/match.default.shg"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg_config" defaults -y
test "$status" -eq 0
grep -q 'ghp_' "$xdg/shg/match.default.shg"
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
printf '%s\n' "$output" | grep -q 'type:    config_check'
say "PASS configured history paths"

say "TEST scan true-positive corpus"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '5 finding(s) detected (3 high, 2 medium, 0 low).'
printf '%s\n' "$output" | grep -q 'type:    credential_url'
if printf '%s\n' "$output" | grep -q "$full_secret"; then
    printf '%s\n' "redacted scan output leaked full secret" >&2
    exit 1
fi
say "PASS scan true-positive corpus"

say "TEST scan true-positive corpus with --show-full"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --show-full --path "$tp"
test "$status" -eq 1
printf '%s\n' "$output" | grep -q "$full_secret"
say "PASS scan true-positive corpus with --show-full"

say "TEST scan false-positive corpus"
run_capture env XDG_CONFIG_HOME="$xdg" "$shg" scan --env false --path "$fp"
test "$status" -eq 0
printf '%s\n' "$output" | grep -q 'No findings detected.'
say "PASS scan false-positive corpus"

say "TEST scan environment variables"
run_capture env -i XDG_CONFIG_HOME="$xdg" SHG_SMOKE_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345 "$shg" scan --hist false
test "$status" -eq 1
printf '%s\n' "$output" | grep -q '<env>'
printf '%s\n' "$output" | grep -q 'type:    inline_assign'
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
printf '%s\n' "$output" | grep -q 'type:    config_check'
printf '%s\n' "$output" | grep -q 'EXTRA_VALUE'
if printf '%s\n' "$output" | grep -q 'ghp_abcdefghijklmnopqrstuvwxyz012345'; then
    printf '%s\n' "ignore.*.shg did not suppress ignored token" >&2
    exit 1
fi
say "PASS compiled config rules"

say "SMOKE PASS"
