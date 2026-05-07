const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const sources = @import("sources.zig");
const entry_mod = @import("entry.zig");
const finding_mod = @import("finding.zig");
const scorer = @import("scorer.zig");
const redact = @import("redact.zig");
const report = @import("report.zig");

const bash_parser = @import("parsers/bash.zig");
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

    if (args.subcommand == .help) return;
    if (args.subcommand == .patterns) {
        try printPatterns(&stdout);
        return;
    }

    const report_opts = report.Options{
        .json = args.json,
        .min_severity = args.min_severity,
        .show_full = args.show_full,
    };

    const paths: []const []const u8 = if (args.paths.len > 0)
        args.paths
    else
        try sources.discover(io, arena_alloc, init.environ_map);

    var counts = [4]usize{ 0, 0, 0, 0 };
    var has_findings = false;

    for (paths) |path| {
        const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
            if (err == error.FileNotFound or err == error.AccessDenied) continue;
            var err_buf: [4096]u8 = undefined;
            var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
            stderr.interface.print("histguard: cannot open {s}: {t}\n", .{ path, err }) catch {};
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

        for (entries) |e| {
            const findings = try detectEntry(e, a, args.entropy_threshold);
            for (findings) |f| {
                if (f.severity == .ignore) continue;
                if (@intFromEnum(f.severity) < @intFromEnum(args.min_severity)) continue;
                has_findings = true;
                counts[@intFromEnum(f.severity)] += 1;
                try report.printFinding(&stdout, f, report_opts);
            }
        }
    }

    if (!args.json) try report.printSummary(&stdout, counts);
    try stdout.flush();

    if (has_findings) std.process.exit(1);
}

fn parseFile(reader: *Io.Reader, path: []const u8, alloc: std.mem.Allocator) ![]Entry {
    if (std.mem.indexOf(u8, path, "zsh_history") != null)
        return zsh_parser.parse(reader, path, alloc);
    if (std.mem.indexOf(u8, path, "fish_history") != null)
        return fish_parser.parse(reader, path, alloc);
    return bash_parser.parse(reader, path, alloc);
}

fn detectEntry(e: Entry, alloc: std.mem.Allocator, entropy_threshold: f64) ![]Finding {
    var findings: std.ArrayList(Finding) = .empty;

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
        for (candidates) |c| {
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
    if (std.mem.eql(u8, det_type, "github_token") or
        std.mem.eql(u8, det_type, "github_app_token")) return "Rotate at github.com/settings/tokens";
    if (std.mem.eql(u8, det_type, "aws_access_key")) return "Rotate via AWS IAM console";
    if (std.mem.eql(u8, det_type, "stripe_key") or
        std.mem.eql(u8, det_type, "stripe_test_key")) return "Rotate at dashboard.stripe.com/apikeys";
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
        \\  github_app_token  ghs_... (GitHub App)
        \\  slack_bot_token   xoxb-... (Slack)
        \\  slack_user_token  xoxp-... (Slack)
        \\  aws_access_key    AKIA... (AWS)
        \\  stripe_key        sk_live_... (Stripe)
        \\  private_key       -----BEGIN * KEY----- markers
        \\  ssh_key           ssh-rsa AAAA... public keys
        \\
    );
}

// Pull in tests from all submodules.
test {
    _ = @import("entropy.zig");
    _ = @import("redact.zig");
    _ = @import("scorer.zig");
    _ = @import("parsers/bash.zig");
    _ = @import("parsers/zsh.zig");
    _ = @import("parsers/fish.zig");
    _ = @import("detect/known_tokens.zig");
    _ = @import("detect/inline_assign.zig");
    _ = @import("detect/auth_header.zig");
    _ = @import("detect/credential_url.zig");
}
