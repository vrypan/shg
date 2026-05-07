# shg — Shell Guard

Scan shell history files for accidentally persisted secrets.

`shg` reads your shell history and flags entries that look like API keys,
passwords, bearer tokens, credential URLs, and private keys. Secrets are
**redacted in all output by default** — the full value is never printed.

```
$ shg scan

[HIGH] ~/.zsh_history:148
  type:    openai_api_key
  command: export OPENAI_API_KEY=sk-...UA
  action:  Rotate at platform.openai.com/api-keys

[HIGH] ~/.zsh_history:576
  type:    github_token
  command: export GITHUB_TOKEN="ghp...P3"
  action:  Rotate at github.com/settings/tokens

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
      --min-severity <LEVEL>   low|medium|high [default: low]
      --entropy-threshold <N>  Shannon entropy cutoff [default: 3.5]
      --show-full              Disable redaction
  -h, --help                   Print help
```

With no `--path` flags, `shg` auto-detects all supported history files
present on the system.

**Examples:**

```sh
# Scan all auto-detected history files
shg scan

# Scan a specific file
shg scan --path ~/.bash_history

# Scan multiple files
shg scan --path ~/.zsh_history --path ~/.bash_history

# Only report high-severity findings
shg scan --min-severity high
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
  openai_api_key    sk-... (OpenAI)
  anthropic_api_key sk-ant-... (Anthropic)
  github_token      ghp_... (GitHub)
  github_oauth      gho_... (GitHub OAuth)
  github_pat        github_pat_... (GitHub fine-grained PAT)
  github_app_token  ghs_... (GitHub App)
  slack_bot_token   xoxb-... (Slack)
  slack_user_token  xoxp-... (Slack)
  slack_app_token   xapp-... (Slack)
  aws_access_key    AKIA... / ASIA... (AWS)
  stripe_key        sk_live_... (Stripe)
  stripe_webhook    whsec_... (Stripe)
  private_key       -----BEGIN * KEY----- markers
  age_secret_key    AGE-SECRET-KEY-1... markers
  ssh_key           ssh-rsa AAAA... public keys
```

### Supported history files

Auto-detected when present:

| Shell / tool | Path |
|---|---|
| Zsh | `~/.zsh_history` |
| Bash | `~/.bash_history` |
| Fish | `~/.local/share/fish/fish_history` |
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
Use `--show-full` to disable redaction (not recommended for shared output).

## Scoring

Each detection candidate is scored against a set of signals:

| Signal | Score |
|---|---|
| Sensitive keyword in variable name | +3 |
| High Shannon entropy (≥ 3.5 bits/char) | +3 |
| Token length ≥ 20 chars | +2 |
| Authorization header | +2 |
| Credential URL | +2 |
| Known provider format | +4 |
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

## Security

- **No network access.** `shg` never connects to the internet.
- **No telemetry.** Nothing is collected or sent.
- **Redaction on by default.** Secrets are never printed in full unless
  `--show-full` is explicitly passed.
- **Read-only.** The current release only scans; it does not modify history
  files. A `fix` subcommand (with atomic writes and automatic backups) is
  planned for a future release.
- JSON output is intentionally deferred until a later release.

## License

MIT
