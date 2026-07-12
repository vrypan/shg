const std = @import("std");

pub const RedactedCommand = struct {
    text: []const u8,
    match_start: usize,
    match_len: usize,
};

const max_redacted_len = 32;
// Number of plaintext chars shown at each end for tokens long enough to afford it.
const show_chars = 4;

pub fn redactToken(token: []const u8, alloc: std.mem.Allocator) ![]u8 {
    // Show at most len/4 per side so at least half of the token stays hidden;
    // short tokens fall back to 1 char each side.
    const each: usize = if (token.len > show_chars * 2) @min(show_chars, token.len / 4) else 1;

    if (token.len <= each * 2) {
        const out = try alloc.alloc(u8, token.len);
        @memset(out, '*');
        return out;
    }
    if (token.len <= max_redacted_len) {
        const out = try alloc.alloc(u8, token.len);
        @memcpy(out[0..each], token[0..each]);
        @memset(out[each .. token.len - each], '*');
        @memcpy(out[token.len - each ..], token[token.len - each ..]);
        return out;
    }
    // Cap at max_redacted_len: each + stars + "..." + stars + each = 32
    const out = try alloc.alloc(u8, max_redacted_len);
    const star_count = max_redacted_len - each * 2 - 3;
    const left = star_count / 2;
    const right = star_count - left;
    @memcpy(out[0..each], token[0..each]);
    @memset(out[each..][0..left], '*');
    @memcpy(out[each + left ..][0..3], "...");
    @memset(out[each + left + 3 ..][0..right], '*');
    @memcpy(out[max_redacted_len - each ..], token[token.len - each ..]);
    return out;
}

const Span = struct { start: usize, end: usize };

/// Redact every occurrence of every token in `tokens` from `cmd`, so a command
/// that carries more than one secret never exposes any of them. `primary` is the
/// token whose redacted span is returned in `match_start`/`match_len` (used to
/// center the display window). Content after the last redacted secret is
/// truncated with "..." as defense-in-depth against an undetected trailing value.
pub fn redactCommand(cmd: []const u8, tokens: []const []const u8, primary: []const u8, alloc: std.mem.Allocator) !RedactedCommand {
    var spans: std.ArrayList(Span) = .empty;
    defer spans.deinit(alloc);
    for (tokens) |token| {
        if (token.len == 0) continue;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, cmd, pos, token)) |idx| {
            try spans.append(alloc, .{ .start = idx, .end = idx + token.len });
            pos = idx + token.len;
        }
    }
    if (spans.items.len == 0) {
        return .{ .text = try alloc.dupe(u8, cmd), .match_start = 0, .match_len = 0 };
    }

    std.mem.sort(Span, spans.items, {}, lessThanSpan);
    // Merge overlapping/touching spans so a byte is never emitted twice.
    var merged: std.ArrayList(Span) = .empty;
    defer merged.deinit(alloc);
    for (spans.items) |s| {
        if (merged.items.len > 0 and s.start <= merged.items[merged.items.len - 1].end) {
            if (s.end > merged.items[merged.items.len - 1].end) merged.items[merged.items.len - 1].end = s.end;
        } else {
            try merged.append(alloc, s);
        }
    }

    const primary_idx: ?usize = if (primary.len > 0) std.mem.indexOf(u8, cmd, primary) else null;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    var match_start: usize = 0;
    var match_len: usize = 0;
    var cursor: usize = 0;
    var last_end: usize = 0;
    for (merged.items) |s| {
        try out.appendSlice(alloc, cmd[cursor..s.start]);
        const red = try redactToken(cmd[s.start..s.end], alloc);
        defer alloc.free(red);
        if (primary_idx) |pi| {
            if (pi >= s.start and pi < s.end) {
                match_start = out.items.len;
                match_len = red.len;
            }
        }
        try out.appendSlice(alloc, red);
        cursor = s.end;
        last_end = s.end;
    }
    // Truncate anything after the last secret so an undetected trailing value is not shown.
    if (last_end < cmd.len) try out.appendSlice(alloc, "...");
    return .{ .text = try out.toOwnedSlice(alloc), .match_start = match_start, .match_len = match_len };
}

fn lessThanSpan(_: void, a: Span, b: Span) bool {
    return a.start < b.start;
}

test "redact long token shows 4 chars each side" {
    const alloc = std.testing.allocator;
    // 16 chars, len/4 = 4: shows first 4 + stars + last 4
    const r = try redactToken("sk-abc123def4567", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("sk-a********4567", r);
}

test "redact medium token hides at least half" {
    const alloc = std.testing.allocator;
    // 9 chars, len/4 = 2: shows first 2 + 5 stars + last 2
    const r = try redactToken("zK9mQx2Lw", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("zK*****Lw", r);
}

test "redact short token falls back to 1 char each side" {
    const alloc = std.testing.allocator;
    // 6 chars, <= show_chars*2=8: falls back to 1+1
    const r = try redactToken("secret", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("s****t", r);
}

test "redact two-char token" {
    const alloc = std.testing.allocator;
    const r = try redactToken("ab", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("**", r);
}

test "redact command token at end" {
    const alloc = std.testing.allocator;
    const r = try redactCommand("export API_KEY=sk-abc123def4567", &.{"sk-abc123def4567"}, "sk-abc123def4567", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("export API_KEY=sk-a********4567", r.text);
    try std.testing.expectEqual(@as(usize, 15), r.match_start);
    try std.testing.expectEqual(@as(usize, 16), r.match_len);
}

test "redact token longer than max capped at 32" {
    const alloc = std.testing.allocator;
    // 38-char token: first 4 + 10 stars + "..." + 11 stars + last 4 = 32
    const r = try redactToken("sk-abcdefghijklmnopqrstuvwxyz012345678", alloc);
    defer alloc.free(r);
    try std.testing.expectEqual(@as(usize, 32), r.len);
    try std.testing.expectEqualStrings("sk-a", r[0..4]);
    try std.testing.expectEqualStrings("5678", r[28..32]);
    try std.testing.expectEqualStrings("...", r[14..17]);
}

test "redact command truncates trailing content" {
    const alloc = std.testing.allocator;
    // "s3cr3tpassword" is 14 chars, len/4 = 3: shows first 3 + stars + last 3
    const r = try redactCommand("curl -u admin:s3cr3tpassword --verbose", &.{"s3cr3tpassword"}, "s3cr3tpassword", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("curl -u admin:s3c********ord...", r.text);
}

test "redact command hides every secret in a multi-secret command" {
    const alloc = std.testing.allocator;
    // Two secrets on one line: both must be redacted, neither shown in full,
    // even though only the first is the primary/matched token.
    const cmd = "export A_KEY=sk-abcdefghijklmnop and B_KEY=tok-zyxwvutsrqponml done";
    const tokens = [_][]const u8{ "sk-abcdefghijklmnop", "tok-zyxwvutsrqponml" };
    const r = try redactCommand(cmd, &tokens, "sk-abcdefghijklmnop", alloc);
    defer alloc.free(r.text);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "sk-abcdefghijklmnop") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "tok-zyxwvutsrqponml") == null);
    // The primary token's span is reported for windowing.
    try std.testing.expectEqualStrings("sk-a", r.text[r.match_start .. r.match_start + 4]);
}

test "redact command leaves a leading secret redacted when a later token is primary" {
    const alloc = std.testing.allocator;
    // Regression: the earlier secret must not be shown verbatim just because the
    // primary/matched token comes after it.
    const cmd = "PM_KEY=0xdeadbeefdeadbeefcafe then TOKEN=ghp_abcdefghijklmnopqrst";
    const tokens = [_][]const u8{ "0xdeadbeefdeadbeefcafe", "ghp_abcdefghijklmnopqrst" };
    const r = try redactCommand(cmd, &tokens, "ghp_abcdefghijklmnopqrst", alloc);
    defer alloc.free(r.text);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "0xdeadbeefdeadbeefcafe") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "ghp_abcdefghijklmnopqrst") == null);
}
