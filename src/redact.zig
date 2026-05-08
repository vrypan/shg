const std = @import("std");

pub const RedactedCommand = struct {
    text: []const u8,
    match_start: usize,
    match_len: usize,
};

const max_redacted_len = 32;

pub fn redactToken(token: []const u8, alloc: std.mem.Allocator) ![]u8 {
    if (token.len <= 2) {
        const out = try alloc.alloc(u8, token.len);
        @memset(out, '*');
        return out;
    }
    if (token.len <= max_redacted_len) {
        const out = try alloc.alloc(u8, token.len);
        out[0] = token[0];
        @memset(out[1 .. token.len - 1], '*');
        out[token.len - 1] = token[token.len - 1];
        return out;
    }
    // Cap at max_redacted_len with "..." in the middle: first + stars + ... + stars + last
    const out = try alloc.alloc(u8, max_redacted_len);
    const star_count = max_redacted_len - 5; // subtract first, last, and "..."
    const left = star_count / 2;
    const right = star_count - left;
    out[0] = token[0];
    @memset(out[1..][0..left], '*');
    @memcpy(out[1 + left ..][0..3], "...");
    @memset(out[1 + left + 3 ..][0..right], '*');
    out[max_redacted_len - 1] = token[token.len - 1];
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

test "redact long token" {
    const alloc = std.testing.allocator;
    const r = try redactToken("sk-abc123def456", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("s*************6", r);
}

test "redact short token" {
    const alloc = std.testing.allocator;
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
    const r = try redactCommand("export API_KEY=sk-abc123def456", "sk-abc123def456", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("export API_KEY=s*************6", r.text);
    try std.testing.expectEqual(@as(usize, 15), r.match_start);
    try std.testing.expectEqual(@as(usize, 15), r.match_len);
}

test "redact token longer than max capped at 32" {
    const alloc = std.testing.allocator;
    // 40-char token
    const r = try redactToken("sk-abcdefghijklmnopqrstuvwxyz012345678", alloc);
    defer alloc.free(r);
    try std.testing.expectEqual(@as(usize, 32), r.len);
    try std.testing.expectEqual('s', r[0]);
    try std.testing.expectEqual('8', r[31]);
    try std.testing.expectEqualStrings("...", r[14..17]);
}

test "redact command truncates trailing content" {
    const alloc = std.testing.allocator;
    const r = try redactCommand("curl -u admin:s3cr3tpassword --verbose", "s3cr3tpassword", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("curl -u admin:s************d...", r.text);
}
