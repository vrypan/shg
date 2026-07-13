# shg — Shell Guard

Scan shell history files for accidentally persisted secrets.

![](screenshot.png)

> [!IMPORTANT]
> `shg` will not make you 100% safe.  
> But it will make you **safer**, and help you build some good shell habits.

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

**Homebrew:**

```sh
brew install vrypan/tap/shg
```

**Pre-built binaries:**

Download the latest release for your platform from the
[Releases page](https://github.com/vrypan/shg/releases), extract, and place
both `shg` and `shg-config` somewhere on your `$PATH`.

```sh
tar xzf shg-v*.tar.gz
sudo mv shg shg-config /usr/local/bin/
```

**Build from source** (requires Zig 0.16):

```sh
git clone https://github.com/vrypan/shg
cd shg
zig build
# binaries at zig-out/bin/shg and zig-out/bin/shg-config
```

To run the deterministic scan benchmark:

```sh
zig build bench
SHG_BENCH_LINES=500000 zig build bench
```

The benchmark generates a temporary history of unique, non-sensitive commands
and reports wall, user, and system time. `SHG_BENCH_LINES` defaults to 100000.

## Usage

```
shg <command> [options]

Commands:
  scan      Scan histories + environment (the everyday check)
  history   Scan command histories (shell, REPLs, agents)
  env       Scan environment variables
  deep      Scan AI agent transcripts (per session)
  fix       Remove confirmed secrets from history files
  version   Print version
```

shg groups secret leaks by the *kind* of data, because each has a different
report format and detection posture:

| Command | Scans | Report | Posture |
|---|---|---|---|
| `history` | shell/REPL histories + Codex `history.jsonl` | per line | loose — you typed it |
| `env` | environment variables | per variable | — |
| `deep` | AI agent transcripts (concentration files) | per session file, deduplicated | strict — a haystack of code |
| `scan` | `history` + `env` together | per line | loose |
| `fix` | history files only | edits confirmed entries | remediation |

### scan

```
shg scan [options]

Options:
  -p, --path <PATH>            History file or directory to scan [repeatable]
      --stdin[=BOOL]           Also scan history piped on stdin [default: false]
      --env[=BOOL]             Scan environment variables [default: true]
      --hist[=BOOL]            Scan history files [default: true]
      --level <LEVEL>          low|medium|high [default: high]
      --entropy-threshold <N>  Shannon entropy cutoff [default: 3.5]
      --redacted[=BOOL]        Redact secrets in output [default: true]
      --json[=BOOL]            Output findings as NDJSON [default: false]
      --summary[=BOOL]         Print H M L counts and exit [default: false]
      --one-line[=BOOL]        One line per finding [default: false]
  -h, --help                   Print help
```

`shg scan` is the everyday check: it runs `history` and `env` together.
`shg history` is `scan` with only histories; `shg env` is `scan` with only the
environment. All three share the per-line report format below.

By default, `shg scan` checks both environment variables and history files.
With no `--path` flags, `shg` scans existing paths from `paths.*.shg` plus the
history file named by `HISTFILE`, when set. Use `--env false` or `--hist false`
to disable a source.

A `--path` argument may be a file or a directory. Directories are walked
recursively and every file inside is scanned, which is handy for one-off scans
of a tree such as AI agent session logs:

```sh
shg scan --env=false --path ~/.claude/projects
```

Explicit paths are strict: a missing or unreadable `--path` is an error and
exits with code 2. Auto-discovered paths remain best-effort because configured
history files may legitimately not exist on every machine.

To scan history piped on stdin, pass `--stdin` explicitly — there is no
auto-detection, so a stray pipe never silently suppresses the normal scan. To
scan *only* the piped input, disable the other sources:

```sh
history | shg scan --stdin --hist=false --env=false
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

> [!TIP]
> Zsh may keep recent commands in memory before writing them to `$HISTFILE`.  
> Use a shell helper if you want scans to include the latest interactive history
> without forcing zsh to write the history file:  
>
> `shg-scan() { fc -l 1 | shg scan --stdin --hist=false --env=false "$@" }`
>
> [INTEGRATIONS.md](INTEGRATIONS.md) also provides a snippet that will prevent
> sensitive info from being written to history in the first place.

For shell startup scans and pre-history hooks see [INTEGRATIONS.md](INTEGRATIONS.md).

### history / env

`shg history` scans command histories only, and `shg env` scans the
environment only — the two halves of `scan`, each with the scan flags that
apply. `history` covers shell (bash/zsh/fish), REPLs (psql/mysql/…), and
**agent command history** — the list of prompts you typed into a coding agent:
Codex (`~/.codex/history.jsonl`), Claude Code (`~/.claude/history.jsonl`),
Ollama (`~/.ollama/history`), and Aider (`~/.aider.input.history`). These are
scanned per line, like shell history. Full agent *transcripts* (tool output,
etc.) are the concern of `deep`, not `history`.

### fix

```
shg fix [options]

Options:
  -p, --path <PATH>      History file or directory to fix [repeatable]
      --level <LEVEL>    low|medium|high [default: high]
  -y, --yes              Remove all flagged entries without prompting
      --dry-run          List what would be removed; change nothing
      --redacted         Redact the shown secret
```

`shg fix` re-scans history files and removes confirmed entries from those
files. It is interactive by default: each candidate is shown in full so you can
judge it before deleting; pass `--redacted` when screen-sharing or recording.
Use `--dry-run` to preview without changing files. At the prompt, answer `y` to
remove the entry, Enter or `n` to keep it, or `q` to apply already confirmed
removals and stop.

When an entry is removed, `shg fix` rewrites the file through a synchronized
temporary file and atomic rename, preserving the original permissions. It
removes complete fish blocks and backslash-continued zsh entries. If the shell
changes the history file while you are confirming removals, `shg fix` aborts
instead of replacing the newer contents. It intentionally creates no backup,
because a backup would be another plaintext copy of the secret. `--yes` skips
prompts and prints only per-file counts, never the entries themselves. `fix` is
history-only; it does not edit environment variables, stdin, or `deep`
transcript files, and it does not rotate credentials.

### deep

```
shg deep [options]

Options:
  -p, --path <PATH>     Transcript file or directory to scan [repeatable]
      --all-content     Also scan assistant messages and reasoning
      --thorough        Run all detectors, not just high-confidence ones
      --level <LEVEL>   low|medium|high [default: high]
      --json            Output findings as NDJSON
```

AI coding agents (Claude Code, Codex) keep full session transcripts on disk.
Those transcripts are a **secret-concentration point**: as the agent reads
`.env` files, runs `env`, and prints connection strings, every tool result is
stored verbatim. A single transcript can end up holding secrets from many
files that were individually locked down — in a file that is usually not
gitignored, not permission-hardened, often cloud-synced, and casually shared
in bug reports.

`shg deep` scans those transcripts for that exposure. It reads the content
that concentrates secrets — user prompts, tool calls, and tool output — and
skips assistant prose and reasoning unless you pass `--all-content`. Findings
are grouped **per session file**, and within each file every distinct secret
is listed **once** with an occurrence count and a redacted context snippet:

```
$ shg deep

~/.claude/projects/myapp/3f2c….jsonl
  [!!!] known_token   ghp_****…****2345   (3×, tool_output)
        …export GITHUB_TOKEN=ghp_****…****2345…

1 secret(s) across 1 session file(s).
Rotate each credential, delete the affected session files, and make sure
this directory is not synced, committed, or world-readable.
```

Because a transcript is a haystack of code, `deep` is **strict by default**:
only the high-confidence detectors (known provider tokens, private/SSH keys,
and your own `match` patterns) fire. Pass `--thorough` to run every detector
(much noisier on code). `--all-content` and `--thorough` are independent:
one widens *what text* is scanned, the other *which detectors* count.

Malformed JSONL records are reported as warnings and make the command exit with
code 2. Other valid records are still scanned, but the result is not presented
as a complete clean scan.

With no `--path`, `shg deep` scans the locations listed in `paths.deep.*.shg`
(by default `~/.claude/projects` and `~/.codex/sessions`). It never crawls the
disk. It parses `*.jsonl` as structured transcripts and scans `.md`, `.txt`, and
other file types as line-based plain text. This includes Claude memory and
detached tool-result files. See [Configuration](#configuration) for the
deep-scoped `ignore.deep.shg`, `match.deep.shg`, and `paths.deep.shg` files.

On an interactive terminal, `deep` shows one progress line per configured or
explicit path, including the file currently being scanned. Completed lines
remain above the findings with their scanned file and distinct flag counts.
Progress is written to standard error and is disabled for `--json`, pipes, and
other non-TTY output.

Remediation differs from history: you can't cleanly edit one line of a
transcript, so the advice is to rotate the credential and delete the session
file.

> The older `shg agents` command still works as a deprecated alias for
> `shg deep`.

## Detection

`shg` combines pattern matching, Shannon entropy analysis, and heuristic
scoring. Each candidate is scored on several signals; low-scoring results
are silently dropped to reduce false positives.

| Detector | What it matches |
|---|---|
| `inline_assign` | `VAR=value` and `?api_key=value` query params with sensitive keywords |
| `auth_header` | `Authorization: Bearer <token>`, `--password <val>` |
| `credential_url` | `scheme://user:pass@host` |
| `known_token` | known provider token prefixes (`ghp_`, `sk-ant-`, `AKIA`, …) |
| `config_check` | compiled `match.*.shg` pattern match |
| `private_key` | `-----BEGIN * KEY-----` and `AGE-SECRET-KEY-1` markers |
| `ssh_key` | `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`, FIDO2/sk public keys |

The `known_token` prefix list is shared with the rotation hints, so a match
also tells you where to rotate the credential.

Run `shg-config status` to list active detection patterns and rules.

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

The number of plaintext characters shown depends on token length; at least
half of the token is always hidden:

| Token length | Visible chars | Example |
|---|---|---|
| ≤ 8 chars | 1 each side | `ghp_*bcde` |
| 9–15 chars | length/4 each side | `zK*****Lw` |
| 16–32 chars | 4 each side | `ghp_********ghij` |
| > 32 chars | 4 each side, capped at 32 with `...` in the middle | `ghp_**********...***********2345` |

If the detected secret appears before the end of the command, the rest of the
line is replaced with `...` to avoid exposing any second secret that may follow:

```
curl -H "Authorization: Bearer ghp_**********...***********2345...
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
| Search command (grep, sed, …) | −2 |

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

Files in the reserved `deep` group are scoped to `shg deep` only:

- `ignore.deep.shg` — suppress findings in transcripts (does not affect
  `shg scan`/`history`)
- `match.deep.shg` — extra patterns to flag in transcripts only
- `paths.deep.shg` — transcript locations `shg deep` scans when `--path` is
  not used (one path per line, same format as `paths.*.shg`; directories are
  walked recursively)

General `ignore.*` and `match.*` rules apply to both `scan`/`history` and
`deep`; general `paths.*` rules drive `history`/`scan` only and are never
scanned by `deep`.

Prefix a configured path with `!` to exclude that exact path and everything
beneath it. Exclusions are independent of rule order and also apply to
`HISTFILE`; explicit `--path` arguments are never filtered by configuration.
Keep local exclusions separate from the default files:

```text
# paths.deep.local.shg
!~/.claude/projects/-Users-vrypan-Devel-histguard/memory
```

Default config templates are maintained as plain text files in `src/defaults/`
and embedded into `shg-config` at build time.

Put local changes in separate files such as `ignore.my.shg`, `match.work.shg`,
or `paths.local.shg`. Avoid editing `*.default.shg` directly; future default
updates may overwrite those files.

Run `shg-config compile` to write `rules.bin`, the binary cache loaded by
`shg scan`. Rules are line-based; blank lines and `#` comments are ignored.
Use `exact:`, `prefix:`, or `substr:` prefixes to choose the match type. Lines
without a prefix are substring matches. `paths.*.shg` files are one path per
line, and a leading `~/` expands to the user's home directory. A leading `!`
marks a path exclusion rather than a path to scan.

Ignore rules take precedence over match rules. If the same text appears in both
`match.default.shg` and `ignore.my.shg`, the matching command is suppressed and
does not produce a finding.

Known provider token prefixes (`ghp_`, `sk-ant-`, `AKIA`, …) are detected
natively by the `known_token` detector, which applies token-boundary and
length checks that plain substring rules cannot. `match.*.shg` is therefore
for additional custom patterns of your own.

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
Write the four default `.shg` files (`ignore.default.shg`, `match.default.shg`,
`paths.default.shg`, and `paths.deep.default.shg`). Existing files prompt before
overwrite; use `-y` to overwrite without prompting.

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
- **Careful writes.** `shg fix` preserves file permissions, synchronizes the
  replacement, detects concurrent changes, and removes only complete confirmed
  entries through an atomic temp-file rewrite. It creates no backups because a
  backup would replicate the secret.

## License

MIT
