# shg integrations

## Shell startup scan

Add a call to `shg scan` at the end of your shell's rc file to get a quick
security check every time a new shell opens. Using `--one-line` keeps the
output compact; `--level high` limits noise to the most critical findings only.

### zsh — `~/.zshrc`

If you installed `shg` with Homebrew:

```sh
echo 'source "$(brew --prefix)/share/shg/extras/check_on_startup.sh"' >> ~/.zshrc
```

Otherwise, add manually:

```sh
if command -v shg &>/dev/null; then
  shg scan --env=true --hist=true --one-line --level high 2>/dev/null || _shg_rc=$?
  [ "${_shg_rc:-0}" -eq 1 ] && echo "Run shg for more info"
  unset _shg_rc
fi
```

### bash — `~/.bashrc`

If you installed `shg` with Homebrew:

```sh
echo 'source "$(brew --prefix)/share/shg/extras/check_on_startup.sh"' >> ~/.bashrc
```

Otherwise, add manually:

```sh
if command -v shg &>/dev/null; then
  shg scan --env=true --hist=true --one-line --level high 2>/dev/null || _shg_rc=$?
  [ "${_shg_rc:-0}" -eq 1 ] && echo "Run shg for more info"
  unset _shg_rc
fi
```

### fish — `~/.config/fish/config.fish`

If you installed `shg` with Homebrew:

```sh
echo 'source (brew --prefix)/share/shg/extras/check_on_startup.fish' >> ~/.config/fish/config.fish
```

Otherwise, add manually:

```fish
if command -q shg
    shg scan --env=true --hist=true --one-line --level high 2>/dev/null
    if test $status -eq 1
        echo "Run shg for more info"
    end
end
```

> **Note on performance.** Environment scanning is instant. History file
> scanning is very fast, but adds a small startup delay proportional to history size.
> If startup latency matters, use `--hist=false` to scan only the environment, or limit
> the scope (ex: `--path ~/.zsh_history`) to scan a single file.

---

## zsh: intercept history before it is saved

zsh's `zshaddhistory` hook is called before each command is written to history.
Returning 1 prevents the command from being saved at all — making this the
ideal place to catch secrets before they ever land in `~/.zsh_history`.

If you installed `shg` with Homebrew enable it with:

```sh
echo 'source "$(brew --prefix)/share/shg/extras/intercept_history.zsh"' >> ~/.zshrc
```

Otherwise, add to `~/.zshrc`:

```zsh
zshaddhistory() {
    local cmd="${1%$'\n'}"

    # "# SHGOK"  — skip check, force save to history.
    [[ "$cmd" == *"# SHGOK" ]]  && return 0

    # "# SHGNOK" — skip check, suppress history write immediately.
    [[ "$cmd" == *"# SHGNOK" ]] && return 1

    local H M L
    read H M L < <(printf '%s\n' "$cmd" | shg scan --level=medium --summary 2>/dev/null)
    if (( H + M + L > 0 )); then
        print -P "%F{red}[shg] Warning: possible secret detected — not saved to history.%f" >&2
        return 1
    fi
    return 0
}
```

The hook receives the command line as `$1` before zsh writes it. If `shg`
finds a match the command is dropped from history and a warning is printed to
stderr. The command still executes normally — only the history entry is
suppressed. You can add `# SHGOK` or `# SHGNOK` to the end of a command line to
override the default behaviour.

| Suffix | Behaviour |
|---|---|
| `# SHGOK` | skip scan, save to history |
| `# SHGNOK` | skip scan, do NOT save to history |

After adding the hook, restart your shell and test:

```zsh
$ password=A3-gF-GhhhDfe-X6-78s
$ history

# use "# SHGOK" to save to history, even if a secret is detected
$ password=A3-gF-GhhhDfe-X6-78s # SHGOK 
$ history
```

```zsh
export DEPLOY_TOKEN=ghp_abc123... # SHGOK   ← known secret, save anyway
curl http://internal/api?token=xyz # SHGNOK  ← don't save, no need to scan
```

> **bash / fish note.** Neither shell has an equivalent pre-history hook.
> bash's `PROMPT_COMMAND` and fish's `fish_preexec` both fire too late to
> cleanly prevent the history write.
