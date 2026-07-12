const std = @import("std");

const hints_text = @embedFile("defaults/hints.shg");
const default_hint = "Remove this entry from history and rotate the credential";

/// Iterate the known provider token prefixes (the prefix: keys in hints.shg).
/// Shared with the known_tokens detector so detection and rotation hints stay
/// in sync from a single list.
pub const PrefixIter = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    pub fn next(self: *PrefixIter) ?[]const u8 {
        while (self.lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            const key = line[0..tab];
            if (std.mem.startsWith(u8, key, "prefix:")) return key[7..];
        }
        return null;
    }
};

pub fn prefixIter() PrefixIter {
    return .{ .lines = std.mem.splitScalar(u8, hints_text, '\n') };
}

/// Return the best rotation hint for a finding.
/// Token-prefix rules take priority over det_type rules; among prefix rules the
/// longest matching prefix wins (so "sk-ant-" beats "sk-").
pub fn lookup(det_type: []const u8, token: []const u8) []const u8 {
    var best_prefix_len: usize = 0;
    var best_prefix_hint: ?[]const u8 = null;
    var det_type_hint: ?[]const u8 = null;

    var lines = std.mem.splitScalar(u8, hints_text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        const key  = line[0..tab];
        const hint = std.mem.trim(u8, line[tab + 1 ..], " \t");
        if (hint.len == 0) continue;

        if (std.mem.startsWith(u8, key, "prefix:")) {
            const prefix = key[7..];
            if (prefix.len > best_prefix_len and std.mem.startsWith(u8, token, prefix)) {
                best_prefix_len = prefix.len;
                best_prefix_hint = hint;
            }
        } else if (std.mem.eql(u8, key, det_type)) {
            det_type_hint = hint;
        }
    }

    if (best_prefix_hint) |h| return h;
    if (det_type_hint) |h| return h;
    return default_hint;
}

test "prefix match beats det_type" {
    const h = lookup("inline_assign", "ghp_abcdefghijklmnopqrstuvwxyz012345");
    try std.testing.expect(std.mem.indexOf(u8, h, "github.com") != null);
}

test "longer prefix wins" {
    const h = lookup("inline_assign", "sk-ant-api03-abcdef");
    try std.testing.expect(std.mem.indexOf(u8, h, "Anthropic") != null);
}

test "det_type fallback" {
    const h = lookup("credential_url", "hunter2");
    try std.testing.expect(std.mem.indexOf(u8, h, "URL") != null);
}

test "unknown falls back to default" {
    const h = lookup("unknown_type", "randomtoken");
    try std.testing.expectEqualStrings(default_hint, h);
}
