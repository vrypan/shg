# shg — Shell Guard

Scan shell history files for accidentally persisted secrets.

> [!IMPORTANT]
> `shg` will not make you 100% safe. 
> But it will make you safer, and help you build some good shell habits.

`shg` reads your shell history and flags entries that look like API keys,
passwords, bearer tokens, credential URLs, and private keys. Secrets are
**redacted in all output by default** — the full value is never printed.

```
$ shg scan

[!!!] export OPENAI_API_KEY=s*************...**************5
      ~/.zsh_history:148 [inline_assign]

[!!!] curl -H "Authorization: Bearer g*************...**************5...
      ~/.zsh_history:576 [auth_header]

2 finding(s) detected (2 high, 0 medium, 0 low).
Remove flagged history entries and rotate affected credentials.
```

## Features

- Detects secrets across five categories (see [Detection](#detection))
- Redacts secrets in output — safe to share or log
- Auto-discovers bash, zsh, fish, and common REPL histories
- Offline and local — no network access, no telemetry
- Single static binary, ~220 KB

## Installation

**Build from source** (requires Zig 0.16):

```sh
git clone https://github.com/vrypan/shg
cd shg
zig build
# binaries at zig-out/bin/shg and zig-out/bin/shg-config
```

## Usage

```
shg <command> [options]

Commands:
  scan      Scan history files for secrets (default)
  patterns  List all detection patterns and examples
  version   Print version
```

### scan

```
shg scan [options]

Options:
  -p, --path <FILE>            History file to scan [repeatable]
      --env[=BOOL]             Scan environment variables [default: true]
      --hist[=BOOL]            Scan history files [default: true]
      --level <LEVEL>          low|medium|high [default: high]
      --entropy-threshold <N>  Shannon entropy cutoff [default: 3.5]
      --redacted[=BOOL]        Redact secrets in output [default: true]
      --json[=BOOL]            Output findings as NDJSON [default: false]
  -h, --help                   Print help
```

By default, `shg scan` checks both environment variables and history files.
With no `--path` flags, `shg` scans existing paths from `paths.*.shg` plus the
history file named by `HISTFILE`, when set. Use `--env false` or `--hist false`
to disable a source.

**Examples:**

```sh
# Scan environment variables and all auto-detected history files
shg scan

# Scan only environment variables
shg scan --hist false

# Scan a specific file
shg scan --env false --path ~/.bash_history

# Scan multiple files
shg scan --path ~/.zsh_history --path ~/.bash_history

# Scan history from stdin
cat ~/.zsh_history | shg scan --env false

# Include low and medium findings
shg scan --level low

# Output as NDJSON (one JSON object per finding)
shg scan --json

# NDJSON piped to jq
shg scan --json | jq 'select(.severity == "high")'
```

Zsh may keep recent commands in memory before writing them to `$HISTFILE`.
Use a shell helper if you want scans to include the latest interactive history
without forcing zsh to write the history file:

```sh
shg-scan() {
  fc -l -n 1 | shg scan "$@"
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--level` |
| 1 | One or more findings detected |
| 2 | Error (bad arguments, unreadable file) |

This makes `shg` scriptable:

```sh
shg scan --level high && echo "clean"
```

## Detection

`shg` combines pattern matching, Shannon entropy analysis, and heuristic
scoring. Each candidate is scored on several signals; low-scoring results
are silently dropped to reduce false positives.

```
$ shg patterns

  inline_assign     VAR=value with sensitive keywords
  auth_header       Authorization: Bearer <token>, --password <val>
  credential_url    scheme://user:pass@host
  config_check      compiled match.*.shg pattern match
  private_key       -----BEGIN * KEY----- markers
  age_secret_key    AGE-SECRET-KEY-1... markers
  ssh_key           ssh-rsa AAAA... public keys
```

### Default history paths

The default `paths.default.shg` created by `shg-config defaults` includes:

| Shell / tool | Path |
|---|---|
| Zsh | `~/.zsh_history` |
| Bash | `~/.bash_history` |
| Fish | `~/.local/share/fish/fish_history` |
| Fish | `~/.config/fish/fish_history` |
| Python REPL | `~/.python_history` |
| psql | `~/.psql_history` |
| MySQL | `~/.mysql_history` |
| SQLite | `~/.sqlite_history` |
| Redis CLI | `~/.rediscli_history` |
| Node.js REPL | `~/.node_repl_history` |
| Ruby IRB | `~/.irb_history` |
| Ruby Pry | `~/.pry_history` |
| R | `~/.Rhistory` |

### Redaction format

Secrets are shown as the first character, `*` for each interior character, and
the last character — preserving the original token length up to 32 characters.
Tokens longer than 32 characters are capped with `...` in the middle:

```
s3cr3tpassword            →  s************d     (14 chars, preserved)
sk-abcdefghijklmnopqrstu  →  s*************...**************u  (capped at 32)
```

If the detected secret appears before the end of the command, the rest of the
line is replaced with `...` to avoid exposing any second secret that may follow:

```
curl -H "Authorization: Bearer g*************...**************5...
```

Use `--redacted=false` to disable redaction (not recommended for shared output).

When writing to a terminal, `shg` colours the severity badge. Set `NO_COLOR`
in the environment to disable terminal styling.

### Severity badges

| Badge | Severity |
|---|---|
| `[!!!]` | High |
| `[!! ]` | Medium |
| `[!  ]` | Low |

## Scoring

Each detection candidate is scored against a set of signals:

| Signal | Score |
|---|---|
| Sensitive keyword in variable name | +3 |
| High Shannon entropy (≥ 3.5 bits/char) | +3 |
| Token length ≥ 20 chars | +2 |
| Authorization header | +2 |
| Credential URL | +2 |
| Known provider token format | +4 |
| Private key marker | +6 |
| Placeholder / test value | −3 |
| Search command (grep, echo, …) | −2 |

| Score | Severity |
|---|---|
| 0–2 | Ignored |
| 3–4 | Low |
| 5–6 | Medium |
| 7+ | High |

The entropy threshold is configurable with `--entropy-threshold`.

## Configuration

Configuration files live in `shg`'s config directory:

- `$XDG_CONFIG_HOME/shg` when `XDG_CONFIG_HOME` is set
- `$HOME/.config/shg` otherwise

The config directory contains editable `.shg` files:

- `ignore.*.shg` — patterns that suppress findings
- `match.*.shg` — additional patterns to flag
- `paths.*.shg` — history paths to scan when `--path` is not used

Default config templates are maintained as plain text files in `src/defaults/`
and embedded into `shg-config` at build time.

Put local changes in separate files such as `ignore.my.shg`, `match.work.shg`,
or `paths.local.shg`. Avoid editing `*.default.shg` directly; future default
updates may overwrite those files.

Run `shg-config compile` to write `rules.bin`, the binary cache loaded by
`shg scan`. Rules are line-based; blank lines and `#` comments are ignored.
Use `exact:`, `prefix:`, or `substr:` prefixes to choose the match type. Lines
without a prefix are substring matches. `paths.*.shg` files are one path per
line, and a leading `~/` expands to the user's home directory.

Ignore rules take precedence over match rules. If the same text appears in both
`match.default.shg` and `ignore.my.shg`, the matching command is suppressed and
does not produce a finding.

> [!NOTE]
> `match.default.shg` is based on https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

### shg-config commands

```
shg-config compile
```
Compile all `*.shg` files in the config directory into `rules.bin`. Must be
re-run after any config change.

```
shg-config defaults [-y]
```
Write the three default `.shg` files (`ignore.default.shg`, `match.default.shg`,
`paths.default.shg`). Existing files prompt before overwrite; use `-y` to
overwrite without prompting.

```
shg-config discover
```
Scan your home directory for `.*history` files not yet in your configuration
and offer to append them to `paths.local.shg`. Run `shg-config compile`
afterwards to apply the changes.

## Security

- **No network access.** `shg` never connects to the internet.
- **No telemetry.** Nothing is collected or sent.
- **Redaction on by default.** Secrets are never printed in full unless
  `--redacted=false` is explicitly passed.
- **Read-only.** The current release only scans; it does not modify history
  files. A `fix` subcommand (with atomic writes and automatic backups) is
  planned for a future release.

## License

MIT
