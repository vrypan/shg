const std = @import("std");
const scorer = @import("scorer.zig");
const redact = @import("redact.zig");
const rules = @import("rules.zig");
const hints = @import("hints.zig");

const entry_mod = @import("entry.zig");
const finding_mod = @import("finding.zig");

const detect_keys = @import("detect/private_keys.zig");
const detect_assign = @import("detect/inline_assign.zig");
const detect_auth = @import("detect/auth_header.zig");
const detect_url = @import("detect/credential_url.zig");
const detect_known = @import("detect/known_tokens.zig");

const Entry = entry_mod.Entry;
const Candidate = finding_mod.Candidate;
const Finding = finding_mod.Finding;
const Severity = finding_mod.Severity;

pub fn detectEntry(e: Entry, alloc: std.mem.Allocator, entropy_threshold: f64, rules_cache: ?rules.Cache) ![]Finding {
    var findings: std.ArrayList(Finding) = .empty;
    var seen_tokens: std.ArrayList([]const u8) = .empty;
    defer seen_tokens.deinit(alloc);
    // The token behind each finding, aligned with `findings`. Every finding's
    // command is redacted against the whole set so a command carrying more than
    // one secret never leaks any of them.
    var finding_tokens: std.ArrayList([]const u8) = .empty;
    defer finding_tokens.deinit(alloc);

    if (rules_cache) |cache| {
        if (try cache.matchesAny(.ignore, e.command)) return findings.toOwnedSlice(alloc);
    }

    const DetectFn = *const fn (Entry, std.mem.Allocator) anyerror![]Candidate;
    // known_tokens runs last so that, when several detectors find the same
    // token, the more specific det_type (auth_header, inline_assign, …) wins.
    const detectors = [_]DetectFn{
        detect_keys.detect,
        detect_assign.detect,
        detect_auth.detect,
        detect_url.detect,
        detect_known.detect,
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
            const full_match = commandMatchSpan(e.command, c.token);
            try findings.append(alloc, .{
                .entry = e,
                .det_type = c.det_type,
                .severity = sev,
                .score = s,
                .redacted_cmd = "",
                .full_match_start = full_match.start,
                .full_match_len = full_match.len,
                .recommendation = hints.lookup(c.det_type, c.token),
            });
            try finding_tokens.append(alloc, c.token);
        }
    }

    if (rules_cache) |cache| {
        var i: usize = 0;
        while (i < cache.ruleCount()) : (i += 1) {
            const rule = try cache.rule(i);
            if (rule.kind != .check or !rules.matches(rule, e.command)) continue;
            const token = configCheckToken(rule, e.command) orelse rule.pattern;
            if (hasHighSeverityToken(findings.items, seen_tokens.items, token)) continue;
            const full_match = commandMatchSpan(e.command, token);
            try findings.append(alloc, .{
                .entry = e,
                .det_type = "config_check",
                .severity = .high,
                .score = 7,
                .redacted_cmd = "",
                .full_match_start = full_match.start,
                .full_match_len = full_match.len,
                .recommendation = hints.lookup("config_check", token),
            });
            try finding_tokens.append(alloc, token);
        }
    }

    // Second pass: redact every command against the full token set.
    for (findings.items, finding_tokens.items) |*f, token| {
        const redacted = try redact.redactCommand(e.command, finding_tokens.items, token, alloc);
        f.redacted_cmd = redacted.text;
        f.redacted_match_start = redacted.match_start;
        f.redacted_match_len = redacted.match_len;
    }

    return findings.toOwnedSlice(alloc);
}

pub const MatchSpan = struct {
    start: usize,
    len: usize,
};

pub fn commandMatchSpan(command: []const u8, token: []const u8) MatchSpan {
    if (token.len == 0) return .{ .start = 0, .len = 0 };
    const start = std.mem.indexOf(u8, command, token) orelse return .{ .start = 0, .len = 0 };
    return .{ .start = start, .len = token.len };
}

fn hasHighSeverityToken(findings: []const Finding, tokens: []const []const u8, token: []const u8) bool {
    for (tokens, 0..) |seen, i| {
        if (i >= findings.len) return false;
        if (std.mem.eql(u8, seen, token) and findings[i].severity == .high) return true;
    }
    return false;
}

pub fn configCheckToken(rule: rules.Rule, text: []const u8) ?[]const u8 {
    const idx = switch (rule.match_kind) {
        .substring => std.mem.indexOf(u8, text, rule.pattern),
        .exact => if (std.mem.eql(u8, text, rule.pattern)) @as(?usize, 0) else null,
        .prefix => if (std.mem.startsWith(u8, text, rule.pattern)) @as(?usize, 0) else null,
    } orelse return null;

    var start = idx;
    while (start > 0 and isConfigTokenChar(text[start - 1])) start -= 1;

    var end = idx + rule.pattern.len;
    while (end < text.len and isConfigTokenChar(text[end])) end += 1;

    if (end <= start) return null;
    return text[start..end];
}

fn isConfigTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '/';
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
    const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold, null);
    defer {
        for (findings) |f| alloc.free(f.redacted_cmd);
        alloc.free(findings);
    }
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("auth_header", findings[0].det_type);
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

    const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
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

    const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
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

    const findings = try detectEntry(e, alloc, scorer.default_entropy_threshold, cache);
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
