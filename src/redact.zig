const std = @import("std");

pub const RedactedCommand = struct {
    text: []const u8,
    match_start: usize,
    match_len: usize,
};

pub fn redactToken(token: []const u8, alloc: std.mem.Allocator) ![]u8 {
    if (token.len < 8) return alloc.dupe(u8, "[REDACTED]");
    const out = try alloc.alloc(u8, 8); // "abc...XY"
    @memcpy(out[0..3], token[0..3]);
    @memcpy(out[3..6], "...");
    @memcpy(out[6..8], token[token.len - 2 ..]);
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
    const out = try alloc.alloc(u8, cmd.len - token.len + redacted.len);
    @memcpy(out[0..idx], cmd[0..idx]);
    @memcpy(out[idx..][0..redacted.len], redacted);
    @memcpy(out[idx + redacted.len ..], cmd[idx + token.len ..]);
    return .{ .text = out, .match_start = idx, .match_len = redacted.len };
}

test "redact long token" {
    const alloc = std.testing.allocator;
    const r = try redactToken("sk-abc123def456", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("sk-...56", r);
}

test "redact short token" {
    const alloc = std.testing.allocator;
    const r = try redactToken("secret", alloc);
    defer alloc.free(r);
    try std.testing.expectEqualStrings("[REDACTED]", r);
}

test "redact command" {
    const alloc = std.testing.allocator;
    const r = try redactCommand("export API_KEY=sk-abc123def456", "sk-abc123def456", alloc);
    defer alloc.free(r.text);
    try std.testing.expectEqualStrings("export API_KEY=sk-...56", r.text);
    try std.testing.expectEqual(@as(usize, 15), r.match_start);
    try std.testing.expectEqual(@as(usize, 8), r.match_len);
}
