const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");

const schemes = [_][]const u8{
    "postgres://", "postgresql://", "mysql://", "mongodb://",
    "redis://", "amqp://", "http://", "https://",
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    for (schemes) |scheme| {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, cmd, pos, scheme)) |idx| {
            const after_scheme = cmd[idx + scheme.len ..];
            if (extractPassword(after_scheme)) |pass| {
                if (pass.len > 0) {
                    try results.append(alloc, .{
                        .token = pass,
                        .det_type = "credential_url",
                        .signals = .{
                            .has_sensitive_keyword = true,
                            .is_credential_url = true,
                            .token_len = pass.len,
                            .entropy = entropy.shannon(pass),
                        },
                    });
                }
            }
            pos = idx + scheme.len;
        }
    }

    return results.toOwnedSlice(alloc);
}

fn extractPassword(s: []const u8) ?[]const u8 {
    var auth_end = s.len;
    for (s, 0..) |c, i| {
        if (c == ' ' or c == '"' or c == '\'' or c == '\\') { auth_end = i; break; }
    }
    const authority = s[0..auth_end];
    const at = std.mem.indexOfScalar(u8, authority, '@') orelse return null;
    const userinfo = authority[0..at];
    const colon = std.mem.indexOfScalar(u8, userinfo, ':') orelse return null;
    const pass = userinfo[colon + 1 ..];
    if (pass.len == 0) return null;
    return pass;
}

test "detect credential url" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "psql postgres://admin:s3cr3tpass@db.internal/prod",
        .command = "psql postgres://admin:s3cr3tpass@db.internal/prod",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("s3cr3tpass", cs[0].token);
}
