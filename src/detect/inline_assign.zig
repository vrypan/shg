const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");

const sensitive_keywords = [_][]const u8{
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "session", "session_token", "credential", "passphrase",
    "auth", "authorization", "bearer", "cookie", "client_secret",
    "refresh_token", "id_token", "webhook_secret",
};

const placeholder_values = [_][]const u8{
    "example", "placeholder", "changeme", "your_", "xxxx", "****",
    "test123", "password123", "secret123", "dummy", "<", "todo", "$",
};

const search_commands = [_][]const u8{
    "grep ", "sed ", "awk ", "cat ", "less ", "more ", "head ", "tail ",
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;
    const stripped = stripLeadingKeyword(cmd);

    const is_search = blk: {
        for (search_commands) |sc| { if (std.mem.startsWith(u8, cmd, sc)) break :blk true; }
        break :blk false;
    };

    // A single command can carry several assignments (FOO=bar API_KEY=... cmd);
    // examine every one, not just the first.
    var search_start: usize = 0;
    while (findAssignment(stripped, search_start)) |assignment| {
        search_start = assignment.end;

        const var_lower = try std.ascii.allocLowerString(alloc, assignment.name);
        defer alloc.free(var_lower);

        var keyword_match = false;
        for (sensitive_keywords) |kw| {
            if (std.mem.indexOf(u8, var_lower, kw) != null) { keyword_match = true; break; }
        }
        if (!keyword_match) continue;

        const token = stripQuotes(assignment.value);

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
    }
    return results.toOwnedSlice(alloc);
}

const Assignment = struct {
    name: []const u8,
    value: []const u8,
    end: usize,
};

fn findAssignment(stripped: []const u8, from: usize) ?Assignment {
    var search_start = from;
    while (std.mem.indexOfScalarPos(u8, stripped, search_start, '=')) |eq| {
        const name = assignmentName(stripped, eq) orelse {
            search_start = eq + 1;
            continue;
        };
        const value = assignmentValue(stripped, eq + 1) orelse {
            search_start = eq + 1;
            continue;
        };
        const value_end = @intFromPtr(value.ptr) - @intFromPtr(stripped.ptr) + value.len;
        return .{ .name = name, .value = value, .end = value_end };
    }
    return null;
}

fn assignmentName(s: []const u8, eq: usize) ?[]const u8 {
    var start = eq;
    while (start > 0 and isNameChar(s[start - 1])) start -= 1;
    if (start == eq) return null;
    if (start > 0 and !isBoundary(s[start - 1])) return null;
    return s[start..eq];
}

fn assignmentValue(s: []const u8, start: usize) ?[]const u8 {
    if (start >= s.len) return null;
    if (s[start] == '"' or s[start] == '\'') {
        const quote = s[start];
        var end = start + 1;
        while (end < s.len and s[end] != quote) end += 1;
        return s[start..end];
    }

    var end = start;
    while (end < s.len and !std.ascii.isWhitespace(s[end]) and
        s[end] != '"' and s[end] != '\'' and s[end] != '&' and s[end] != '#') end += 1;
    if (end == start) return null;
    return s[start..end];
}

fn isNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

fn isBoundary(c: u8) bool {
    return std.ascii.isWhitespace(c) or c == '"' or c == '\'' or
        c == '(' or c == '[' or c == '{' or c == '?' or c == '&' or c == ';';
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

test "inline assign detects secret after a non-sensitive assignment" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "FOO=bar DB_PASSWORD=zK9mQx2LwPq44XyTr7Vn ./run", .command = "FOO=bar DB_PASSWORD=zK9mQx2LwPq44XyTr7Vn ./run" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("zK9mQx2LwPq44XyTr7Vn", cs[0].token);
}

test "inline assign detects multiple secrets on one line" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "API_TOKEN=aX3fKm92LqR7 DB_PASSWORD=zK9mQx2LwPq4 ./run", .command = "API_TOKEN=aX3fKm92LqR7 DB_PASSWORD=zK9mQx2LwPq4 ./run" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 2), cs.len);
    try std.testing.expectEqualStrings("aX3fKm92LqR7", cs[0].token);
    try std.testing.expectEqualStrings("zK9mQx2LwPq4", cs[1].token);
}

test "inline assign detects secret in quoted URL query param" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "curl \"https://api.example.com/v1?api_key=zK9mQx2LwPq44XyTr7Vn&user=bob\"", .command = "curl \"https://api.example.com/v1?api_key=zK9mQx2LwPq44XyTr7Vn&user=bob\"" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("zK9mQx2LwPq44XyTr7Vn", cs[0].token);
}

test "inline assign detects secret in non-first unquoted URL query param" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "curl https://api.example.com/v1?user=bob&token=zK9mQx2LwPq44XyTr7Vn", .command = "curl https://api.example.com/v1?user=bob&token=zK9mQx2LwPq44XyTr7Vn" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("zK9mQx2LwPq44XyTr7Vn", cs[0].token);
}

test "inline assign ignores plain URL query params without secrets" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "curl https://api.example.com/v1?user=bob&page=2", .command = "curl https://api.example.com/v1?user=bob&page=2" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "inline assign flags shell-variable value as placeholder" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "export GITHUB_TOKEN=$GH_TOKEN", .command = "export GITHUB_TOKEN=$GH_TOKEN" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expect(cs[0].signals.is_placeholder);
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

test "inline assign detects expanded sensitive keywords" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "export CLIENT_SECRET=s3cr3tV4lue99X", .command = "export CLIENT_SECRET=s3cr3tV4lue99X" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expect(cs[0].signals.has_sensitive_keyword);
}

test "inline assign detects echo assignment without search penalty" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "echo password=sdkjfhskjfhaskfhsakhfkshfkasjkb347", .command = "echo password=sdkjfhskjfhaskfhsakhfkshfkasjkb347" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expectEqualStrings("sdkjfhskjfhaskfhsakhfkshfkasjkb347", cs[0].token);
    try std.testing.expect(!cs[0].signals.is_search_command);
}

test "inline assign applies search penalty for grep" {
    const alloc = std.testing.allocator;
    const e = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = "grep password=sdkjfhskjfhaskfhsakhfkshfkasjkb347 /etc/config", .command = "grep password=sdkjfhskjfhaskfhsakhfkshfkasjkb347 /etc/config" };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expect(cs.len == 1);
    try std.testing.expect(cs[0].signals.is_search_command);
}
