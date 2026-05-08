# shg — Shell Guard

Scan shell history files for accidentally persisted secrets.

`shg` reads your shell history and flags entries that look like API keys,
passwords, bearer tokens, credential URLs, and private keys. Secrets are
**redacted in all output by default** — the full value is never printed.

```
$ shg scan

[HIGH] ~/.zsh_history:148
  type:    inline_assign
  command: export OPENAI_API_KEY=sk-...UA
  action:  Remove this history entry and rotate the credential

[HIGH] ~/.zsh_history:576
  type:    config_check
  command: export GITHUB_TOKEN="ghp...P3"
  action:  Review this configured pattern match

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
zig build -Doptimize=ReleaseSafe
# binary at zig-out/bin/shg
```

## Usage

```
shg <command> [options]

Commands:
  scan      Scan history files for secrets (default)
  patterns  List all detection patterns and examples
```

### scan

```
shg scan [options]

Options:
  -p, --path <FILE>            History file to scan [repeatable]
      --env[=BOOL]             Scan environment variables [default: true]
      --hist[=BOOL]            Scan history files [default: true]
      --min-severity <LEVEL>   low|medium|high [default: high]
      --entropy-threshold <N>  Shannon entropy cutoff [default: 3.5]
      --redacted[=BOOL]        Redact secrets in output [default: true]
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
shg scan --min-severity low
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
| 0 | No findings at or above `--min-severity` |
| 1 | One or more findings detected |
| 2 | Error (bad arguments, unreadable file) |

This makes `shg` scriptable:

```sh
shg scan --min-severity high && echo "clean"
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

### Redaction format

Secrets are shown as the first 3 characters, `...`, and the last 2:

```
sk-abcdefghijklmnopqrstuvwxyz  →  sk-...yz
```

Tokens shorter than 8 characters are replaced entirely with `[REDACTED]`.
Use `--redacted=false` to disable redaction (not recommended for shared output).

## Scoring

Each detection candidate is scored against a set of signals:

| Signal | Score |
|---|---|
| Sensitive keyword in variable name | +3 |
| High Shannon entropy (≥ 3.5 bits/char) | +3 |
| Token length ≥ 20 chars | +2 |
| Authorization header | +2 |
| Credential URL | +2 |
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

- `ignore.*.shg` for patterns that should suppress findings
- `match.*.shg` for additional patterns that should be scanned
- `paths.*.shg` for default history paths to scan when `--path` is not used

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

Run `shg-config defaults` to write the three default `.shg` files. Existing
files prompt before overwrite; answer `yes` to replace or `no` to keep that
file and continue. Use `shg-config defaults -y` to overwrite defaults without
prompting.

## Security

- **No network access.** `shg` never connects to the internet.
- **No telemetry.** Nothing is collected or sent.
- **Redaction on by default.** Secrets are never printed in full unless
  `--redacted=false` is explicitly passed.
- **Read-only.** The current release only scans; it does not modify history
  files. A `fix` subcommand (with atomic writes and automatic backups) is
  planned for a future release.
- JSON output is intentionally deferred until a later release.

## License

MIT
