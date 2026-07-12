const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const config = @import("config.zig");
const sources = @import("sources.zig");
const entry_mod = @import("entry.zig");
const finding_mod = @import("finding.zig");
const scorer = @import("scorer.zig");
const report = @import("report.zig");
const rules = @import("rules.zig");
const detect = @import("detect.zig");

const zsh_parser = @import("parsers/zsh.zig");
const fish_parser = @import("parsers/fish.zig");
const jsonl_parser = @import("parsers/jsonl.zig");

const Entry = entry_mod.Entry;
const Severity = finding_mod.Severity;

pub fn main(init: std.process.Init) !void {
    // The documented exit-code contract: 0 clean, 1 findings, 2 error.
    run(init) catch |err| {
        var err_buf: [4096]u8 = undefined;
        var stderr = Io.File.stderr().writerStreaming(init.io, &err_buf);
        stderr.interface.print("shg: {t}\n", .{err}) catch {};
        stderr.flush() catch {};
        std.process.exit(2);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena_alloc = init.arena.allocator();

    var out_buf: [32768]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    defer stdout.flush() catch {};

    var err_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
    defer stderr.flush() catch {};

    const raw_args = try init.minimal.args.toSlice(arena_alloc);
    const args = cli.parse(raw_args, &stdout.interface, arena_alloc) catch |err| {
        if (err == error.ReportedCliError) {
            stdout.flush() catch {};
            std.process.exit(2);
        }
        return err;
    };

    if (args.subcommand == .help or args.subcommand == .version) return;

    const report_opts = report.Options{
        .level = args.level,
        .redacted = args.redacted,
        .color = !args.json and !args.summary and try colorEnabled(io, init.environ_map),
        .json = args.json,
        .summary = args.summary,
        .one_line = args.one_line,
    };

    var counts = [4]usize{ 0, 0, 0, 0 };
    var has_findings = false;
    const rules_cache = try loadRulesCache(io, arena_alloc, init.environ_map);
    if (rules_cache == null) {
        try stderr.interface.writeAll("shg: no compiled rules found; run shg-config compile\n");
        try stderr.flush();
        std.process.exit(2);
    }

    const stdin_is_piped = args.paths.len == 0 and try stdinHasHistory(io);

    if (args.scan_hist and stdin_is_piped) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();

        var read_buf: [65536]u8 = undefined;
        var reader = Io.File.stdin().readerStreaming(io, &read_buf);
        var skipped: usize = 0;
        const entries = try parseFile(&reader.interface, "<stdin>", a, &skipped);
        warnSkippedLines(io, "<stdin>", skipped);
        try scanEntries(entries, a, args.entropy_threshold, args.level, report_opts, rules_cache, &stdout, &counts, &has_findings);
    }

    // Scan history paths when: not piped, OR piped but --hist was explicitly requested.
    if (args.scan_hist and (!stdin_is_piped or args.hist_explicit)) {
        const paths: []const []const u8 = if (args.paths.len > 0)
            try sources.expandExplicitPaths(io, arena_alloc, init.environ_map, args.paths)
        else
            try sources.discover(io, arena_alloc, init.environ_map, rules_cache.?);

        for (paths) |path| {
            const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
                if (err == error.FileNotFound or err == error.AccessDenied) continue;
                var file_err_buf: [4096]u8 = undefined;
                var file_stderr = Io.File.stderr().writerStreaming(io, &file_err_buf);
                file_stderr.interface.print("shg: cannot open {s}: {t}\n", .{ path, err }) catch {};
                file_stderr.flush() catch {};
                continue;
            };
            defer file.close(io);

            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const a = arena.allocator();

            var read_buf: [65536]u8 = undefined;
            var reader = file.reader(io, &read_buf);
            var skipped: usize = 0;
            const entries = try parseFile(&reader.interface, path, a, &skipped);
            warnSkippedLines(io, path, skipped);
            try scanEntries(entries, a, args.entropy_threshold, args.level, report_opts, rules_cache, &stdout, &counts, &has_findings);
        }
    }

    // When piped, skip env unless --env was explicitly passed.
    const do_scan_env = args.scan_env and (!stdin_is_piped or args.env_explicit);
    if (do_scan_env) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const entries = try parseEnv(init.environ_map, a);
        try scanEntries(entries, a, args.entropy_threshold, args.level, report_opts, rules_cache, &stdout, &counts, &has_findings);
    }

    if (args.summary) {
        try stdout.interface.print("{d} {d} {d}\n", .{ counts[3], counts[2], counts[1] });
    } else if (!args.json and !args.one_line) {
        try report.printSummary(&stdout, counts);
    }
    try stdout.flush();

    if (has_findings) std.process.exit(1);
}

fn stdinHasHistory(io: Io) !bool {
    const stdin = Io.File.stdin();
    if (try stdin.isTty(io)) return false;
    const stat = try stdin.stat(io);
    return stat.kind == .file or stat.kind == .named_pipe;
}

fn colorEnabled(io: Io, environ: *const std.process.Environ.Map) !bool {
    if (environ.get("NO_COLOR")) |_| return false;
    return try Io.File.stdout().isTty(io);
}

fn loadRulesCache(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?rules.Cache {
    const path = (try config.compiledFile(alloc, environ)) orelse return null;
    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    const bytes = try reader.interface.readAlloc(alloc, @intCast(stat.size));
    return try rules.Cache.init(bytes);
}

fn parseFile(reader: *Io.Reader, path: []const u8, alloc: std.mem.Allocator, skipped: *usize) ![]Entry {
    if (std.mem.indexOf(u8, path, "fish_history") != null)
        return fish_parser.parse(reader, path, alloc, skipped);
    if (std.mem.endsWith(u8, path, ".jsonl"))
        return jsonl_parser.parse(reader, path, alloc);
    // The zsh parser also accepts plain one-command-per-line histories. Using it
    // as the default preserves zsh extended metadata for explicit --path scans.
    return zsh_parser.parse(reader, path, alloc, skipped);
}

fn warnSkippedLines(io: Io, path: []const u8, skipped: usize) void {
    if (skipped == 0) return;
    var err_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
    stderr.interface.print("shg: warning: {s}: skipped {d} oversized line(s)\n", .{ path, skipped }) catch {};
    stderr.flush() catch {};
}

fn parseEnv(environ: *const std.process.Environ.Map, alloc: std.mem.Allocator) ![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    const keys = environ.keys();
    const values = environ.values();
    for (keys, values, 0..) |key, value, i| {
        if (key.len == 0 or value.len == 0) continue;
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

fn scanEntries(
    entries: []const Entry,
    alloc: std.mem.Allocator,
    entropy_threshold: f64,
    level: Severity,
    report_opts: report.Options,
    rules_cache: ?rules.Cache,
    stdout: *Io.File.Writer,
    counts: *[4]usize,
    has_findings: *bool,
) !void {
    for (entries) |e| {
        const findings = try detect.detectEntry(e, alloc, entropy_threshold, rules_cache);
        for (findings) |f| {
            if (f.severity == .ignore) continue;
            if (@intFromEnum(f.severity) < @intFromEnum(level)) continue;
            has_findings.* = true;
            counts[@intFromEnum(f.severity)] += 1;
            try report.printFinding(stdout, f, report_opts);
        }
    }
}

// Pull in tests from all submodules.
test {
    _ = @import("entropy.zig");
    _ = @import("hints.zig");
    _ = @import("redact.zig");
    _ = @import("scorer.zig");
    _ = @import("config.zig");
    _ = @import("rules.zig");
    _ = @import("sources.zig");
    _ = @import("detect.zig");
    _ = @import("agent_formats.zig");
    _ = @import("parsers/bash.zig");
    _ = @import("parsers/zsh.zig");
    _ = @import("parsers/fish.zig");
    _ = @import("parsers/jsonl.zig");
    _ = @import("detect/private_keys.zig");
    _ = @import("detect/inline_assign.zig");
    _ = @import("detect/auth_header.zig");
    _ = @import("detect/credential_url.zig");
    _ = @import("detect/known_tokens.zig");
}

test "explicit zsh-format fixture path preserves extended commands" {
    const alloc = std.testing.allocator;
    var reader = Io.Reader.fixed(": 1715000000:0;export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");
    var skipped: usize = 0;
    const entries = try parseFile(&reader, "zsh_sample.txt", alloc, &skipped);
    defer {
        for (entries) |e| {
            alloc.free(e.command);
            alloc.free(e.raw);
        }
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", entries[0].command);

    const findings = try detect.detectEntry(entries[0], alloc, scorer.default_entropy_threshold, null);
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
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
        .command = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
    };
    const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, null);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("auth_header", findings[0].det_type);
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

    const findings = try detect.detectEntry(entries[0], alloc, scorer.default_entropy_threshold, null);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("inline_assign", findings[0].det_type);
}

test "compiled ignore rules suppress environment assignments" {
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

    const cache_bytes = try rules.compile(
        alloc,
        \\prefix:SSH_AUTH_SOCK=
        \\prefix:STARSHIP_SESSION_KEY=
        \\prefix:GPG_AGENT_INFO=
        \\prefix:DBUS_SESSION_BUS_ADDRESS=
        \\prefix:PWD=
        \\prefix:OLDPWD=
        \\prefix:OLD_PWD=
    ,
        "",
        "",
    );
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    const entries = try parseEnv(&env, alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }

    var visible: usize = 0;
    for (entries) |e| {
        const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
        defer {
            for (findings) |f| alloc.free(f.redacted_cmd);
            alloc.free(findings);
        }
        for (findings) |f| {
            if (f.severity != .ignore) visible += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 1), visible);
}

test "compiled match rules redact full token-like match" {
    const alloc = std.testing.allocator;
    // "zz9_" is not a known provider prefix, so the config rule does the work.
    const cache_bytes = try rules.compile(alloc, "", "zz9_", "");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "CUSTOM_VALUE=zz9_abcdefghijklmnopqrstuvwxyz012345",
        .command = "CUSTOM_VALUE=zz9_abcdefghijklmnopqrstuvwxyz012345",
    };

    const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }

    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("config_check", findings[0].det_type);
    try std.testing.expect(std.mem.indexOf(u8, findings[0].redacted_cmd, "abcdefghijklmnopqrstuvwxyz012345") == null);
}

test "known provider token takes precedence over config_check" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compile(alloc, "", "ghp_", "");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "echo ghp_abcdefghijklmnopqrstuvwxyz012345",
        .command = "echo ghp_abcdefghijklmnopqrstuvwxyz012345",
    };

    const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }

    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("known_token", findings[0].det_type);
    try std.testing.expectEqual(Severity.high, findings[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, findings[0].redacted_cmd, "abcdefghijklmnopqrstuvwxyz012345") == null);
}

test "compiled match rules still report when inline assignment also matches" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compile(alloc, "", "password=", "");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "echo password=sdkjfhskjfhaskfhsakhfkshfkasjkb347",
        .command = "echo password=sdkjfhskjfhaskfhsakhfkshfkasjkb347",
    };

    const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }

    var saw_inline = false;
    var saw_config = false;
    for (findings) |f| {
        if (std.mem.eql(u8, f.det_type, "inline_assign")) saw_inline = true;
        if (std.mem.eql(u8, f.det_type, "config_check")) saw_config = true;
    }
    try std.testing.expect(saw_inline);
    try std.testing.expect(saw_config);
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
    var skipped: usize = 0;
    const entries = try parseFile(&reader, "zsh_sample.txt", alloc, &skipped);
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
        const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, null);
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
    var skipped: usize = 0;
    const entries = try parseFile(&reader, "bash_safe.txt", alloc, &skipped);
    defer {
        for (entries) |e| {
            alloc.free(e.command);
            alloc.free(e.raw);
        }
        alloc.free(entries);
    }

    for (entries) |e| {
        const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, null);
        defer {
            for (findings) |f| alloc.free(f.redacted_cmd);
            alloc.free(findings);
        }
        for (findings) |f| {
            try std.testing.expect(f.severity == .ignore);
        }
    }
}
