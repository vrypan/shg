const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");

const auth_prefixes = [_][]const u8{
    "Authorization: Bearer ",
    "authorization: bearer ",
    "Authorization: Token ",
    "authorization: token ",
    "Authorization: Basic ",
    "authorization: basic ",
};

const secret_flags = [_][]const u8{
    "--password ", "--token ", "--secret ", "--api-key ",
    "--access-key ",
};

const short_secret_flags = [_][]const u8{
    "-p",
};

const userinfo_flags = [_][]const u8{
    "-u ", "--user ", "--auth ",
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    for (auth_prefixes) |prefix| {
        if (std.mem.indexOf(u8, cmd, prefix)) |idx| {
            const tok_start = idx + prefix.len;
            var tok_end = tok_start;
            while (tok_end < cmd.len) : (tok_end += 1) {
                const c = cmd[tok_end];
                if (c == '"' or c == '\'' or c == ' ' or c == '\\') break;
            }
            const token = cmd[tok_start..tok_end];
            if (token.len > 0 and !isReference(token)) {
                try results.append(alloc, .{
                    .token = token,
                    .det_type = "auth_header",
                    .signals = .{
                        .is_auth_header = true,
                        .has_sensitive_keyword = true,
                        .token_len = token.len,
                        .entropy = entropy.shannon(token),
                    },
                });
            }
        }
    }

    for (userinfo_flags) |flag| {
        if (std.mem.indexOf(u8, cmd, flag)) |idx| {
            const val_start = idx + flag.len;
            var val_end = val_start;
            while (val_end < cmd.len) : (val_end += 1) {
                const c = cmd[val_end];
                if (c == ' ' or c == '"' or c == '\'') break;
            }
            if (extractUserinfoPassword(cmd[val_start..val_end])) |token| {
                if (isReference(token)) continue;
                try results.append(alloc, .{
                    .token = token,
                    .det_type = "auth_userinfo",
                    .signals = .{
                        .is_auth_header = true,
                        .has_sensitive_keyword = true,
                        .token_len = token.len,
                        .entropy = entropy.shannon(token),
                    },
                });
            }
        }
    }

    for (secret_flags) |flag| {
        if (std.mem.indexOf(u8, cmd, flag)) |idx| {
            const val_start = idx + flag.len;
            var val_end = val_start;
            while (val_end < cmd.len) : (val_end += 1) {
                const c = cmd[val_end];
                if (c == ' ' or c == '"' or c == '\'') break;
            }
            const token = cmd[val_start..val_end];
            if (token.len > 0 and !isReference(token)) {
                try results.append(alloc, .{
                    .token = token,
                    .det_type = "cli_flag_secret",
                    .signals = .{
                        .has_sensitive_keyword = true,
                        .token_len = token.len,
                        .entropy = entropy.shannon(token),
                    },
                });
            }
        }
    }

    for (short_secret_flags) |flag| {
        if (std.mem.indexOf(u8, cmd, flag)) |idx| {
            if (idx > 0 and cmd[idx - 1] != ' ') continue;
            const val_start = idx + flag.len;
            if (val_start >= cmd.len) continue;
            const next = cmd[val_start];
            if (next == ' ' or next == '"' or next == '\'') continue;
            var val_end = val_start;
            while (val_end < cmd.len) : (val_end += 1) {
                const c = cmd[val_end];
                if (c == ' ' or c == '"' or c == '\'') break;
            }
            const token = cmd[val_start..val_end];
            if (token.len > 0 and !isReference(token)) {
                try results.append(alloc, .{
                    .token = token,
                    .det_type = "cli_flag_secret",
                    .signals = .{
                        .has_sensitive_keyword = true,
                        .token_len = token.len,
                        .entropy = entropy.shannon(token),
                    },
                });
            }
        }
    }

    return results.toOwnedSlice(alloc);
}

// Values like $VAR, ${VAR} and <placeholder> are references, not secrets.
fn isReference(token: []const u8) bool {
    return token.len > 0 and (token[0] == '$' or token[0] == '<');
}

fn extractUserinfoPassword(s: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const pass = s[colon + 1 ..];
    if (pass.len == 0) return null;
    return pass;
}

test "bearer placeholder in angle brackets is not a secret" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -H \"Authorization: Bearer <admin_token>\"",
        .command = "curl -H \"Authorization: Bearer <admin_token>\"",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "userinfo shell-variable password is not a secret" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -u admin:$API_PASS https://example.com",
        .command = "curl -u admin:$API_PASS https://example.com",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "cli flag shell-variable password is not a secret" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "mysql --password $DB_PASS",
        .command = "mysql --password $DB_PASS",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "real bearer value is still detected" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -H \"Authorization: Bearer zK9mQx2LwPq44XyTr7Vn\"",
        .command = "curl -H \"Authorization: Bearer zK9mQx2LwPq44XyTr7Vn\"",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("zK9mQx2LwPq44XyTr7Vn", cs[0].token);
}

test "detect bearer token" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
        .command = "curl -H \"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\"",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len > 0);
    try std.testing.expect(cs[0].signals.is_auth_header);
}

test "detect mysql short password flag" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "mysql -ps3cr3tDatabasePass99",
        .command = "mysql -ps3cr3tDatabasePass99",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("s3cr3tDatabasePass99", cs[0].token);
}

test "long password flag is not also treated as short flag" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "mysql --password s3cr3tDatabasePass99",
        .command = "mysql --password s3cr3tDatabasePass99",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("s3cr3tDatabasePass99", cs[0].token);
}

test "detect curl userinfo password" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "curl -u admin:s3cr3tDatabasePass99 https://example.com",
        .command = "curl -u admin:s3cr3tDatabasePass99 https://example.com",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("s3cr3tDatabasePass99", cs[0].token);
}

test "detect httpie auth password" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "http --auth admin:s3cr3tDatabasePass99 example.com",
        .command = "http --auth admin:s3cr3tDatabasePass99 example.com",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("s3cr3tDatabasePass99", cs[0].token);
}
