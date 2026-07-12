const std = @import("std");

const magic = "SHGRULES";
const version: u16 = 1;
const header_len: usize = 20;
const record_len: usize = 12;

pub const RuleKind = enum(u8) {
    ignore = 1,
    check = 2,
    path = 3,
    // Deep-scoped variants, compiled from `*.deep.shg` and read only by
    // `shg deep`. Adding these is backward-compatible: older caches never
    // contain them, and `enumValue` simply gains valid byte values.
    deep_ignore = 4,
    deep_check = 5,
    deep_path = 6,
};

pub const MatchKind = enum(u8) {
    substring = 1,
    exact = 2,
    prefix = 3,
};

pub const Rule = struct {
    kind: RuleKind,
    match_kind: MatchKind,
    pattern: []const u8,
};

pub const Cache = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) !Cache {
        const cache = Cache{ .bytes = bytes };
        try cache.validate();
        return cache;
    }

    pub fn ruleCount(self: Cache) usize {
        return readU32(self.bytes[12..16]);
    }

    pub fn rule(self: Cache, index: usize) !Rule {
        if (index >= self.ruleCount()) return error.InvalidRulesCache;
        const record_start = header_len + index * record_len;
        const record = self.bytes[record_start..][0..record_len];
        const string_len = readU32(self.bytes[16..20]);
        const blob = self.bytes[header_len + self.ruleCount() * record_len ..][0..string_len];
        const offset = readU32(record[4..8]);
        const len = readU32(record[8..12]);
        if (@as(usize, offset) + @as(usize, len) > blob.len) return error.InvalidRulesCache;
        return .{
            .kind = try enumValue(RuleKind, record[0]),
            .match_kind = try enumValue(MatchKind, record[1]),
            .pattern = blob[offset..][0..len],
        };
    }

    pub fn matchesAny(self: Cache, kind: RuleKind, text: []const u8) !bool {
        var i: usize = 0;
        while (i < self.ruleCount()) : (i += 1) {
            const r = try self.rule(i);
            if (r.kind == kind and matches(r, text)) return true;
        }
        return false;
    }

    fn validate(self: Cache) !void {
        if (self.bytes.len < header_len) return error.InvalidRulesCache;
        if (!std.mem.eql(u8, self.bytes[0..8], magic)) return error.InvalidRulesCache;
        if (readU16(self.bytes[8..10]) != version) return error.UnsupportedRulesCache;
        if (readU16(self.bytes[10..12]) != record_len) return error.InvalidRulesCache;
        const count = readU32(self.bytes[12..16]);
        const string_len = readU32(self.bytes[16..20]);
        const records_len = @as(usize, count) * record_len;
        if (self.bytes.len != header_len + records_len + @as(usize, string_len)) return error.InvalidRulesCache;
        var i: usize = 0;
        while (i < count) : (i += 1) _ = try self.rule(i);
    }
};

pub fn matches(rule: Rule, text: []const u8) bool {
    return switch (rule.match_kind) {
        .substring => std.mem.indexOf(u8, text, rule.pattern) != null,
        .exact => std.mem.eql(u8, text, rule.pattern),
        .prefix => std.mem.startsWith(u8, text, rule.pattern),
    };
}

pub fn compile(alloc: std.mem.Allocator, ignore_text: []const u8, check_text: []const u8, paths_text: []const u8) ![]u8 {
    return compileFull(alloc, ignore_text, check_text, paths_text, "", "", "");
}

/// Compile general and deep-scoped rules into one cache. Deep-scoped buffers
/// (from `*.deep.shg`) become `deep_*` rule kinds that `scan` ignores.
pub fn compileFull(
    alloc: std.mem.Allocator,
    ignore_text: []const u8,
    check_text: []const u8,
    paths_text: []const u8,
    deep_ignore_text: []const u8,
    deep_check_text: []const u8,
    deep_paths_text: []const u8,
) ![]u8 {
    var parsed: std.ArrayList(Rule) = .empty;
    defer parsed.deinit(alloc);
    try appendRules(alloc, &parsed, .ignore, ignore_text);
    try appendRules(alloc, &parsed, .check, check_text);
    try appendPaths(alloc, &parsed, .path, paths_text);
    try appendRules(alloc, &parsed, .deep_ignore, deep_ignore_text);
    try appendRules(alloc, &parsed, .deep_check, deep_check_text);
    try appendPaths(alloc, &parsed, .deep_path, deep_paths_text);

    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(alloc, magic);
    try appendU16(alloc, &out, version);
    try appendU16(alloc, &out, record_len);
    try appendU32(alloc, &out, @intCast(parsed.items.len));
    const string_len_pos = out.items.len;
    try appendU32(alloc, &out, 0);

    for (parsed.items) |r| {
        const offset: u32 = @intCast(blob.items.len);
        try blob.appendSlice(alloc, r.pattern);
        try out.append(alloc, @intFromEnum(r.kind));
        try out.append(alloc, @intFromEnum(r.match_kind));
        try out.append(alloc, 0);
        try out.append(alloc, 0);
        try appendU32(alloc, &out, offset);
        try appendU32(alloc, &out, @intCast(r.pattern.len));
    }

    writeU32(out.items[string_len_pos..][0..4], @intCast(blob.items.len));
    try out.appendSlice(alloc, blob.items);
    return out.toOwnedSlice(alloc);
}

fn appendRules(alloc: std.mem.Allocator, rules: *std.ArrayList(Rule), kind: RuleKind, text: []const u8) !void {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r\n");
        if (line.len == 0 or line[0] == '#') continue;
        const parsed = parseLine(kind, line) orelse continue;
        try rules.append(alloc, parsed);
    }
}

fn appendPaths(alloc: std.mem.Allocator, rules: *std.ArrayList(Rule), kind: RuleKind, text: []const u8) !void {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r\n");
        if (line.len == 0 or line[0] == '#') continue;
        try rules.append(alloc, .{ .kind = kind, .match_kind = .exact, .pattern = line });
    }
}

fn parseLine(kind: RuleKind, line: []const u8) ?Rule {
    const prefixes = [_]struct { prefix: []const u8, match_kind: MatchKind }{
        .{ .prefix = "exact:", .match_kind = .exact },
        .{ .prefix = "prefix:", .match_kind = .prefix },
        .{ .prefix = "substr:", .match_kind = .substring },
    };
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, line, p.prefix)) {
            const pattern = std.mem.trim(u8, line[p.prefix.len..], " \t\r\n");
            if (pattern.len == 0) return null;
            return .{ .kind = kind, .match_kind = p.match_kind, .pattern = pattern };
        }
    }
    return .{ .kind = kind, .match_kind = .substring, .pattern = line };
}

fn enumValue(comptime T: type, value: u8) !T {
    inline for (@typeInfo(T).@"enum".fields) |field| {
        if (field.value == value) return @enumFromInt(value);
    }
    return error.InvalidRulesCache;
}

fn appendU16(alloc: std.mem.Allocator, out: *std.ArrayList(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    writeU16(&buf, value);
    try out.appendSlice(alloc, &buf);
}

fn appendU32(alloc: std.mem.Allocator, out: *std.ArrayList(u8), value: u32) !void {
    var buf: [4]u8 = undefined;
    writeU32(&buf, value);
    try out.appendSlice(alloc, &buf);
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn writeU16(bytes: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, bytes, value, .little);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

test "compile and read rules cache" {
    const alloc = std.testing.allocator;
    const bytes = try compile(alloc,
        \\# ignored
        \\exact:SAFE_TOKEN
        \\prefix:TMP_
    ,
        \\substr:ghp_
        \\custom-secret
    ,
        \\~/.zsh_history
    );
    defer alloc.free(bytes);
    const cache = try Cache.init(bytes);
    try std.testing.expectEqual(@as(usize, 5), cache.ruleCount());
    try std.testing.expect(try cache.matchesAny(.ignore, "SAFE_TOKEN"));
    try std.testing.expect(try cache.matchesAny(.ignore, "TMP_VALUE"));
    try std.testing.expect(try cache.matchesAny(.check, "token=ghp_abc"));
    try std.testing.expect(try cache.matchesAny(.check, "has custom-secret inside"));
    try std.testing.expectEqualStrings("~/.zsh_history", (try cache.rule(4)).pattern);
    try std.testing.expect(!try cache.matchesAny(.ignore, "other"));
}

test "compileFull emits deep-scoped kinds distinct from general kinds" {
    const alloc = std.testing.allocator;
    const bytes = try compileFull(
        alloc,
        "general-ignore",
        "general-check",
        "~/.zsh_history",
        "agent-only-ignore",
        "agent-only-check",
        "~/.claude/projects",
    );
    defer alloc.free(bytes);
    const cache = try Cache.init(bytes);

    // General kinds see only general rules; agent kinds see only agent rules.
    try std.testing.expect(try cache.matchesAny(.ignore, "has general-ignore here"));
    try std.testing.expect(!try cache.matchesAny(.ignore, "has agent-only-ignore here"));
    try std.testing.expect(try cache.matchesAny(.deep_ignore, "has agent-only-ignore here"));
    try std.testing.expect(!try cache.matchesAny(.deep_ignore, "has general-ignore here"));
    try std.testing.expect(try cache.matchesAny(.check, "has general-check here"));
    try std.testing.expect(try cache.matchesAny(.deep_check, "has agent-only-check here"));

    // Path rules stay separate: general `path` vs `deep_path`.
    var general_path: ?[]const u8 = null;
    var deep_path: ?[]const u8 = null;
    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const r = try cache.rule(i);
        if (r.kind == .path) general_path = r.pattern;
        if (r.kind == .deep_path) deep_path = r.pattern;
    }
    try std.testing.expectEqualStrings("~/.zsh_history", general_path.?);
    try std.testing.expectEqualStrings("~/.claude/projects", deep_path.?);
}
