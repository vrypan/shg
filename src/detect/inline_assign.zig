const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");

const sensitive_keywords = [_][]const u8{
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "session", "credential", "passphrase",
};

const placeholder_values = [_][]const u8{
    "example", "placeholder", "changeme", "your_", "xxxx", "****",
    "test123", "password123", "secret123", "dummy", "<", "todo",
};

const search_commands = [_][]const u8{
    "grep ", "sed ", "awk ", "echo ", "cat ", "less ", "more ", "head ", "tail ",
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    const stripped = stripLeadingKeyword(cmd);
    const eq = std.mem.indexOfScalar(u8, stripped, '=') orelse return results.toOwnedSlice(alloc);
    const var_name = stripped[0..eq];
    const value_raw = stripped[eq + 1 ..];
    if (value_raw.len == 0) return results.toOwnedSlice(alloc);
    if (std.mem.indexOfScalar(u8, var_name, ' ') != null) return results.toOwnedSlice(alloc);

    const var_lower = try std.ascii.allocLowerString(alloc, var_name);
    defer alloc.free(var_lower);

    var keyword_match = false;
    for (sensitive_keywords) |kw| {
        if (std.mem.indexOf(u8, var_lower, kw) != null) { keyword_match = true; break; }
    }
    if (!keyword_match) return results.toOwnedSlice(alloc);

    const token = stripQuotes(value_raw);

    const is_search = blk: {
        for (search_commands) |sc| { if (std.mem.startsWith(u8, cmd, sc)) break :blk true; }
        break :blk false;
    };

    const is_placeholder = blk: {
        if (token.len == 0) break :blk true;
        const tok_lower = try std.ascii.allocLowerString(alloc, token);
        defer alloc.free(tok_lower);
        for (placeholder_values) |pv| { if (std.mem.startsWith(u8, tok_lower, pv)) break :blk true; }
        break :blk false;
    };

    try results.append(alloc, .{
        .token = token,
        .det_type = "inline_assign",
        .signals = .{
            .has_sensitive_keyword = true,
            .is_search_command = is_search,
            .is_placeholder = is_placeholder,
            .token_len = token.len,
            .entropy = entropy.shannon(token),
        },
    });
    return results.toOwnedSlice(alloc);
}

fn stripLeadingKeyword(cmd: []const u8) []const u8 {
    const prefixes = [_][]const u8{ "export ", "declare -x ", "declare " };
    for (prefixes) |p| { if (std.mem.startsWith(u8, cmd, p)) return cmd[p.len..]; }
    return cmd;
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and
        ((s[0] == '"' and s[s.len - 1] == '"') or
        (s[0] == '\'' and s[s.len - 1] == '\'')))
    {
        return s[1 .. s.len - 1];
    }
    return s;
}

test "inline assign detects password" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "export PASSWORD=s3cr3tV4lue99X", .command = "export PASSWORD=s3cr3tV4lue99X" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expect(cs[0].signals.has_sensitive_keyword);
}

test "inline assign ignores placeholder" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "export PASSWORD=changeme", .command = "export PASSWORD=changeme" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expect(cs[0].signals.is_placeholder);
}
