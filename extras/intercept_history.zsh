# Allow # comments in interactive shells (required for # SHGOK / # SHGNOK).
setopt INTERACTIVE_COMMENTS

#
# It will check every command line before it is saved to history.
# If shg considers it sensitive, it will still be executed, but 
# it will not be saved.
#
# activate it and enter something like this to see it in action:
# password=A3-gF-GhhhDfe-X6-78s
# 
# To override in special cases, add "# SHGOK" at the end of the line.
# password=A3-gF-GhhhDfe-X6-78s # SHGOK
#

zshaddhistory() {
    local cmd="${1%$'\n'}"

    # "# SHGOK"  — skip check, force save to history.
    [[ "$cmd" == *"# SHGOK" ]]  && return 0

    # "# SHGNOK" — skip check, suppress history write immediately.
    [[ "$cmd" == *"# SHGNOK" ]] && return 1

    # Scan only the piped command line: --stdin reads it, --hist/--env off so we
    # do not also scan history files or the environment here.
    local H M L
    read H M L < <(printf '%s\n' "$cmd" | shg scan --stdin --hist=false --env=false --level=medium --summary 2>/dev/null)
    if (( H + M + L > 0 )); then
        print -P "%F{red}[shg] Warning: possible secret detected — not saved to history.%f" >&2
        return 1
    fi
    return 0
}
