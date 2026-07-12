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

pub fn redactCommand(cmd: []const u8, token: []const u8, alloc: std.mem.Allocator) !RedactedCommand {
    if (token.len == 0) {
        return .{ .text = try alloc.dupe(u8, cmd), .match_start = 0, .match_len = 0 };
    }
    const idx = std.mem.indexOf(u8, cmd, token) orelse {
        return .{ .text = try alloc.dupe(u8, cmd), .match_start = 0, .match_len = 0 };
    };
    const redacted = try redactToken(token, alloc);
    defer alloc.free(redacted);
    // Truncate after the redacted token so any subsequent sensitive values are not shown.
    const has_more = idx + token.len < cmd.len;
    const suffix = if (has_more) "..." else "";
    const out = try alloc.alloc(u8, idx + redacted.len + suffix.len);
    @memcpy(out[0..idx], cmd[0..idx]);
    @memcpy(out[idx..][0..redacted.len], redacted);
    if (has_more) @memcpy(out[idx + redacted.len ..], "...");
    return .{ .text = out, .match_start = idx, .match_len = redacted.len };
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
    const r = try redactCommand("export API_KEY=sk-abc123def4567", "sk-abc123def4567", alloc);
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
    const r = try redactCommand("curl -u admin:s3cr3tpassword --verbose", "s3cr3tpassword", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("curl -u admin:s3c********ord...", r.text);
}
