const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");
const hints = @import("../hints.zig");

// Minimum token chars required after the provider prefix; rejects prose that
// merely starts with a short prefix (e.g. "sk-learn").
const min_tail = 8;

const placeholder_values = [_][]const u8{
    "example", "placeholder", "changeme",  "your_", "xxxx", "****",
    "test123", "password123", "secret123", "dummy", "<",    "todo",
    "$",
};

pub const PrefixIndex = struct {
    flat: []const []const u8,
    buckets: [256][]const []const u8,

    pub fn init(alloc: std.mem.Allocator) !PrefixIndex {
        var prefixes: std.ArrayList([]const u8) = .empty;
        defer prefixes.deinit(alloc);

        var counts = [_]usize{0} ** 256;
        var it = hints.prefixIter();
        while (it.next()) |prefix| {
            if (prefix.len == 0) continue;
            try prefixes.append(alloc, prefix);
            counts[prefix[0]] += 1;
        }

        const flat = try alloc.alloc([]const u8, prefixes.items.len);
        errdefer alloc.free(flat);

        var offsets = [_]usize{0} ** 256;
        var total: usize = 0;
        for (counts, 0..) |count, i| {
            offsets[i] = total;
            total += count;
        }
        var cursors = offsets;
        for (prefixes.items) |prefix| {
            flat[cursors[prefix[0]]] = prefix;
            cursors[prefix[0]] += 1;
        }

        var buckets: [256][]const []const u8 = undefined;
        for (counts, offsets, 0..) |count, offset, i| {
            buckets[i] = flat[offset..][0..count];
        }
        return .{ .flat = flat, .buckets = buckets };
    }

    pub fn deinit(self: PrefixIndex, alloc: std.mem.Allocator) void {
        alloc.free(self.flat);
    }
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    var it = hints.prefixIter();
    while (it.next()) |prefix| {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, cmd, pos, prefix)) |idx| {
            pos = idx + 1;
            // The prefix must start at a token boundary.
            if (idx > 0 and isTokenChar(cmd[idx - 1])) continue;
            var end = idx + prefix.len;
            while (end < cmd.len and isTokenChar(cmd[end])) end += 1;
            const token = cmd[idx..end];
            if (token.len < prefix.len + min_tail) continue;

            const is_placeholder = blk: {
                const tail_lower = try std.ascii.allocLowerString(alloc, token[prefix.len..]);
                defer alloc.free(tail_lower);
                for (placeholder_values) |pv| {
                    if (std.mem.startsWith(u8, tail_lower, pv)) break :blk true;
                }
                break :blk false;
            };

            try results.append(alloc, .{
                .token = token,
                .det_type = "known_token",
                .signals = .{
                    .is_known_format = true,
                    .is_placeholder = is_placeholder,
                    .token_len = token.len,
                    .entropy = entropy.shannon(token),
                },
            });
        }
    }

    return results.toOwnedSlice(alloc);
}

pub fn detectIndexed(e: Entry, alloc: std.mem.Allocator, index: *const PrefixIndex) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    for (cmd, 0..) |first, idx| {
        if (idx > 0 and isTokenChar(cmd[idx - 1])) continue;
        for (index.buckets[first]) |prefix| {
            if (!std.mem.startsWith(u8, cmd[idx..], prefix)) continue;
            var end = idx + prefix.len;
            while (end < cmd.len and isTokenChar(cmd[end])) end += 1;
            const token = cmd[idx..end];
            if (token.len < prefix.len + min_tail) continue;

            const is_placeholder = blk: {
                const tail_lower = try std.ascii.allocLowerString(alloc, token[prefix.len..]);
                defer alloc.free(tail_lower);
                for (placeholder_values) |pv| {
                    if (std.mem.startsWith(u8, tail_lower, pv)) break :blk true;
                }
                break :blk false;
            };

            try results.append(alloc, .{
                .token = token,
                .det_type = "known_token",
                .signals = .{
                    .is_known_format = true,
                    .is_placeholder = is_placeholder,
                    .token_len = token.len,
                    .entropy = entropy.shannon(token),
                },
            });
        }
    }
    return results.toOwnedSlice(alloc);
}

fn isTokenChar(c: u8) bool {
    // '.' is deliberately excluded so filenames ("sk-notes.txt") don't extend
    // into token candidates; dotted prefixes like "hvb." still match literally.
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_';
}

test "detect bare github token" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "echo ghp_abcdefghijklmnopqrstuvwxyz012345",
        .command = "echo ghp_abcdefghijklmnopqrstuvwxyz012345",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("ghp_abcdefghijklmnopqrstuvwxyz012345", cs[0].token);
    try std.testing.expect(cs[0].signals.is_known_format);
}

test "prefix inside a word is not a token" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "pip install scikit-learn risk-free-analysis",
        .command = "pip install scikit-learn risk-free-analysis",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "short tail after prefix is rejected" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "cat sk-notes.txt",
        .command = "cat sk-notes.txt",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 0), cs.len);
}

test "placeholder tail is flagged as placeholder" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "export GITHUB_TOKEN=ghp_your_token_here",
        .command = "export GITHUB_TOKEN=ghp_your_token_here",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expect(cs[0].signals.is_placeholder);
}

test "known token scores high" {
    const scorer = @import("../scorer.zig");
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test",
        .line = 1,
        .timestamp = null,
        .raw = "echo AKIAIOSFODNN7EXAMPLE99",
        .command = "echo AKIAIOSFODNN7EXAMPLE99",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    const s = scorer.score(cs[0].signals, scorer.default_entropy_threshold);
    try std.testing.expectEqual(@import("../finding.zig").Severity.high, scorer.severity(s));
}

test "indexed detector matches the legacy detector" {
    const alloc = std.testing.allocator;
    const index = try PrefixIndex.init(alloc);
    defer index.deinit(alloc);
    const commands = [_][]const u8{
        "git status --short",
        "echo ghp_abcdefghijklmnopqrstuvwxyz012345",
        "export API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "echo AKIAIOSFODNN7EXAMPLE99 and npm_abcdefghijklmnopqrstuvwxyz",
        "cat sk-notes.txt",
    };
    for (commands) |command| {
        const entry = Entry{ .file = "test", .line = 1, .timestamp = null, .raw = command, .command = command };
        const legacy = try detect(entry, alloc);
        defer alloc.free(legacy);
        const indexed = try detectIndexed(entry, alloc, &index);
        defer alloc.free(indexed);
        try std.testing.expectEqual(legacy.len, indexed.len);
        for (legacy, indexed) |a, b| {
            try std.testing.expectEqualStrings(a.token, b.token);
            try std.testing.expectEqual(a.signals.is_placeholder, b.signals.is_placeholder);
        }
    }
}

test "prefix index contains every configured provider prefix" {
    const alloc = std.testing.allocator;
    const index = try PrefixIndex.init(alloc);
    defer index.deinit(alloc);

    var expected: usize = 0;
    var it = hints.prefixIter();
    while (it.next()) |prefix| {
        expected += 1;
        var found = false;
        for (index.buckets[prefix[0]]) |indexed| {
            if (std.mem.eql(u8, indexed, prefix)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
    try std.testing.expectEqual(expected, index.flat.len);
}
