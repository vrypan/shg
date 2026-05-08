const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const sources = @import("sources.zig");
const entry_mod = @import("entry.zig");
const finding_mod = @import("finding.zig");
const scorer = @import("scorer.zig");
const redact = @import("redact.zig");
const report = @import("report.zig");

const zsh_parser = @import("parsers/zsh.zig");
const fish_parser = @import("parsers/fish.zig");

const detect_known = @import("detect/known_tokens.zig");
const detect_keys = @import("detect/private_keys.zig");
const detect_assign = @import("detect/inline_assign.zig");
const detect_auth = @import("detect/auth_header.zig");
const detect_url = @import("detect/credential_url.zig");

const Entry = entry_mod.Entry;
const Candidate = finding_mod.Candidate;
const Finding = finding_mod.Finding;
const Severity = finding_mod.Severity;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena_alloc = init.arena.allocator();

    var out_buf: [32768]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    defer stdout.flush() catch {};

    const raw_args = try init.minimal.args.toSlice(arena_alloc);
    const args = cli.parse(raw_args, &stdout.interface, arena_alloc) catch |err| {
        if (err == error.ReportedCliError) {
            stdout.flush() catch {};
            std.process.exit(2);
        }
        return err;
    };

    if (args.subcommand == .help or args.subcommand == .version) return;
    if (args.subcommand == .patterns) {
        try printPatterns(&stdout);
        return;
    }

    const report_opts = report.Options{
        .min_severity = args.min_severity,
        .show_full = args.show_full,
    };

    var counts = [4]usize{ 0, 0, 0, 0 };
    var has_findings = false;

    if (args.scan_hist) {
        const paths: []const []const u8 = if (args.paths.len > 0)
            args.paths
        else
            try sources.discover(io, arena_alloc, init.environ_map);

        for (paths) |path| {
            const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
                if (err == error.FileNotFound or err == error.AccessDenied) continue;
                var err_buf: [4096]u8 = undefined;
                var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
                stderr.interface.print("shg: cannot open {s}: {t}\n", .{ path, err }) catch {};
                stderr.flush() catch {};
                continue;
            };
            defer file.close(io);

            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const a = arena.allocator();

            var read_buf: [65536]u8 = undefined;
            var reader = file.reader(io, &read_buf);
            const entries = try parseFile(&reader.interface, path, a);
            try scanEntries(entries, a, args.entropy_threshold, args.min_severity, report_opts, &stdout, &counts, &has_findings);
        }
    }

    if (args.scan_env) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const entries = try parseEnv(init.environ_map, a);
        try scanEntries(entries, a, args.entropy_threshold, args.min_severity, report_opts, &stdout, &counts, &has_findings);
    }

    try report.printSummary(&stdout, counts);
    try stdout.flush();

    if (has_findings) std.process.exit(1);
}

fn parseFile(reader: *Io.Reader, path: []const u8, alloc: std.mem.Allocator) ![]Entry {
    if (std.mem.indexOf(u8, path, "fish_history") != null)
        return fish_parser.parse(reader, path, alloc);
    // The zsh parser also accepts plain one-command-per-line histories. Using it
    // as the default preserves zsh extended metadata for explicit --path scans.
    return zsh_parser.parse(reader, path, alloc);
}

fn parseEnv(environ: *const std.process.Environ.Map, alloc: std.mem.Allocator) ![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    const keys = environ.keys();
    const values = environ.values();
    for (keys, values, 0..) |key, value, i| {
        if (key.len == 0 or value.len == 0) continue;
        if (isAllowedEnvKey(key)) continue;
        const cmd = try std.mem.concat(alloc, u8, &.{ key, "=", value });
        try entries.append(alloc, .{
            .file = "<env>",
            .line = i + 1,
            .timestamp = null,
            .raw = cmd,
            .command = cmd,
        });
    }
    return entries.toOwnedSlice(alloc);
}

fn isAllowedEnvKey(key: []const u8) bool {
    const allowlist = [_][]const u8{
        "SSH_AUTH_SOCK",
        "STARSHIP_SESSION_KEY",
        "GPG_AGENT_INFO",
        "DBUS_SESSION_BUS_ADDRESS",
        "PWD",
        "OLDPWD",
        "OLD_PWD",
    };
    for (allowlist) |allowed| {
        if (std.ascii.eqlIgnoreCase(key, allowed)) return true;
    }
    return false;
}

fn scanEntries(
    entries: []const Entry,
    alloc: std.mem.Allocator,
    entropy_threshold: f64,
    min_severity: Severity,
    report_opts: report.Options,
    stdout: *Io.File.Writer,
    counts: *[4]usize,
    has_findings: *bool,
) !void {
    for (entries) |e| {
        const findings = try detectEntry(e, alloc, entropy_threshold);
        for (findings) |f| {
            if (f.severity == .ignore) continue;
            if (@intFromEnum(f.severity) < @intFromEnum(min_severity)) continue;
            has_findings.* = true;
            counts[@intFromEnum(f.severity)] += 1;
            try report.printFinding(stdout, f, report_opts);
        }
    }
}

fn detectEntry(e: Entry, alloc: std.mem.Allocator, entropy_threshold: f64) ![]Finding {
    var findings: std.ArrayList(Finding) = .empty;
    var seen_tokens: std.ArrayList([]const u8) = .empty;
    defer seen_tokens.deinit(alloc);

    const DetectFn = *const fn (Entry, std.mem.Allocator) anyerror![]Candidate;
    const detectors = [_]DetectFn{
        detect_known.detect,
        detect_keys.detect,
        detect_assign.detect,
        detect_auth.detect,
        detect_url.detect,
    };

    for (detectors) |det| {
        const candidates = try det(e, alloc);
        defer alloc.free(candidates);
        for (candidates) |c| {
            var seen = false;
            for (seen_tokens.items) |token| {
                if (std.mem.eql(u8, token, c.token)) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;
            try seen_tokens.append(alloc, c.token);

            const s = scorer.score(c.signals, entropy_threshold);
            const sev = scorer.severity(s);
            const redacted = try redact.redactCommand(e.command, c.token, alloc);
            try findings.append(alloc, .{
                .entry = e,
                .det_type = c.det_type,
                .severity = sev,
                .score = s,
                .redacted_cmd = redacted,
                .recommendation = getRecommendation(c.det_type),
            });
        }
    }

    return findings.toOwnedSlice(alloc);
}

fn getRecommendation(det_type: []const u8) []const u8 {
    if (std.mem.eql(u8, det_type, "openai_api_key")) return "Rotate at platform.openai.com/api-keys";
    if (std.mem.eql(u8, det_type, "anthropic_api_key")) return "Rotate at console.anthropic.com";
    if (std.mem.startsWith(u8, det_type, "github_")) return "Rotate at github.com/settings/tokens";
    if (std.mem.eql(u8, det_type, "aws_access_key") or
        std.mem.eql(u8, det_type, "aws_temp_access_key")) return "Rotate via AWS IAM console";
    if (std.mem.startsWith(u8, det_type, "stripe_")) return "Rotate at dashboard.stripe.com/apikeys";
    if (std.mem.startsWith(u8, det_type, "slack_")) return "Rotate in Slack app configuration";
    if (std.mem.eql(u8, det_type, "private_key") or
        std.mem.eql(u8, det_type, "ssh_key")) return "Private key must not appear in shell history";
    if (std.mem.eql(u8, det_type, "credential_url")) return "Avoid embedding credentials in URLs";
    return "Remove this history entry and rotate the credential";
}

fn printPatterns(w: *Io.File.Writer) !void {
    try w.interface.writeAll(
        \\Detection categories:
        \\
        \\  inline_assign     VAR=value with sensitive keywords
        \\  auth_header       Authorization: Bearer <token>, --password <val>
        \\  credential_url    scheme://user:pass@host
        \\  openai_api_key    sk-... (OpenAI)
        \\  anthropic_api_key sk-ant-... (Anthropic)
        \\  github_token      ghp_... (GitHub)
        \\  github_oauth      gho_... (GitHub OAuth)
        \\  github_pat        github_pat_... (GitHub fine-grained PAT)
        \\  github_app_token  ghs_... (GitHub App)
        \\  slack_bot_token   xoxb-... (Slack)
        \\  slack_user_token  xoxp-... (Slack)
        \\  slack_app_token   xapp-... (Slack)
        \\  aws_access_key    AKIA... / ASIA... (AWS)
        \\  stripe_key        sk_live_... (Stripe)
        \\  stripe_webhook    whsec_... (Stripe)
        \\  private_key       -----BEGIN * KEY----- markers
        \\  age_secret_key    AGE-SECRET-KEY-1... markers
        \\  ssh_key           ssh-rsa AAAA... public keys
        \\
    );
}

// Pull in tests from all submodules.
test {
    _ = @import("entropy.zig");
    _ = @import("redact.zig");
    _ = @import("scorer.zig");
    _ = @import("config.zig");
    _ = @import("parsers/bash.zig");
    _ = @import("parsers/zsh.zig");
    _ = @import("parsers/fish.zig");
    _ = @import("detect/known_tokens.zig");
    _ = @import("detect/private_keys.zig");
    _ = @import("detect/inline_assign.zig");
    _ = @import("detect/auth_header.zig");
    _ = @import("detect/credential_url.zig");
}

test "explicit zsh-format fixture path preserves extended commands" {
    const alloc = std.testing.allocator;
    var reader = Io.Reader.fixed(": 1715000000:0;export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");
    const entries = try parseFile(&reader, "zsh_sample.txt", alloc);
    defer {
        for (entries) |e| {
            alloc.free(e.command);
            alloc.free(e.raw);
        }
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", entries[0].command);

    const findings = try detectEntry(entries[0], alloc, scorer.default_entropy_threshold);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expect(findings[0].severity != .ignore);
}

test "duplicate token candidates collapse to one finding" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
        .command = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
    };
    const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("github_token", findings[0].det_type);
}

test "environment entries are converted to assignments" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz012345");

    const entries = try parseEnv(&env, alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("<env>", entries[0].file);
    try std.testing.expectEqualStrings("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345", entries[0].command);

    const findings = try detectEntry(entries[0], alloc, scorer.default_entropy_threshold);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("github_token", findings[0].det_type);
}

test "allowed environment keys are skipped" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("SSH_AUTH_SOCK", "/tmp/ssh-agent/socket");
    try env.put("STARSHIP_SESSION_KEY", "abcdefghijklmnopqrstuvwxyz0123456789");
    try env.put("GPG_AGENT_INFO", "/tmp/gpg-agent:1234:1");
    try env.put("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/dbus-session");
    try env.put("PWD", "/Users/example/project");
    try env.put("OLDPWD", "/Users/example");
    try env.put("OLD_PWD", "/Users/example/old");
    try env.put("GITHUB_PUBLIC_REPOS_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz012345");

    const entries = try parseEnv(&env, alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("GITHUB_PUBLIC_REPOS_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345", entries[0].command);
}

test "corpus true positives produce one visible finding per line" {
    const alloc = std.testing.allocator;
    const input =
        ": 1715000000:0;export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345678901234567\n" ++
        ": 1715000001:0;curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"\n" ++
        ": 1715000002:0;psql postgres://admin:s3cr3tpass@db.internal/prod\n" ++
        ": 1715000003:0;export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" ++
        ": 1715000004:0;mysql --password s3cr3tDatabasePass99\n";
    var reader = Io.Reader.fixed(input);
    const entries = try parseFile(&reader, "zsh_sample.txt", alloc);
    defer {
        for (entries) |e| {
            alloc.free(e.command);
            alloc.free(e.raw);
        }
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 5), entries.len);

    var visible: usize = 0;
    for (entries) |e| {
        const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold);
        defer {
            for (findings) |f| alloc.free(f.redacted_cmd);
            alloc.free(findings);
        }
        for (findings) |f| {
            if (f.severity != .ignore) visible += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 5), visible);
}

test "corpus false positives produce no visible findings" {
    const alloc = std.testing.allocator;
    const input =
        "ls -la\n" ++
        "git status\n" ++
        "echo \"hello world\"\n" ++
        "grep password /etc/passwd\n" ++
        "export PATH=/usr/local/bin:$PATH\n" ++
        "cat README.md\n" ++
        "docker ps\n" ++
        "kubectl get pods\n";
    var reader = Io.Reader.fixed(input);
    const entries = try parseFile(&reader, "bash_safe.txt", alloc);
    defer {
        for (entries) |e| {
            alloc.free(e.command);
            alloc.free(e.raw);
        }
        alloc.free(entries);
    }

    for (entries) |e| {
        const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold);
        defer {
            for (findings) |f| alloc.free(f.redacted_cmd);
            alloc.free(findings);
        }
        for (findings) |f| {
            try std.testing.expect(f.severity == .ignore);
        }
    }
}
