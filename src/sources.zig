const std = @import("std");
const Io = std.Io;
const rules = @import("rules.zig");

pub fn discover(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, cache: rules.Cache) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;

    try appendEnvHistoryPaths(io, alloc, environ, &results);

    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const rule = try cache.rule(i);
        if (rule.kind != .path) continue;

        const path = try expandPath(alloc, environ, rule.pattern);
        if (path) |resolved| {
            try appendExistingPath(io, alloc, &results, resolved);
        }
    }

    return results.toOwnedSlice(alloc);
}

fn appendEnvHistoryPaths(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, results: *std.ArrayList([]const u8)) !void {
    const env_vars = [_][]const u8{
        "HISTFILE",
    };
    for (env_vars) |name| {
        const value = environ.get(name) orelse continue;
        if (value.len == 0) continue;
        const path = try expandPath(alloc, environ, value);
        if (path) |resolved| try appendExistingPath(io, alloc, results, resolved);
    }
}

fn expandPath(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, path: []const u8) !?[]const u8 {
    if (std.mem.startsWith(u8, path, "~/")) {
        const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return null;
        if (home.len == 0) return null;
        return try std.fs.path.join(alloc, &.{ home, path[2..] });
    }
    if (!std.fs.path.isAbsolute(path)) return try std.fs.path.resolve(alloc, &.{path});
    return try alloc.dupe(u8, path);
}

fn appendExistingPath(io: Io, alloc: std.mem.Allocator, results: *std.ArrayList([]const u8), path: []const u8) !void {
    if (!fileExists(io, path)) {
        alloc.free(path);
        return;
    }
    for (results.items) |existing| {
        if (std.mem.eql(u8, existing, path)) {
            alloc.free(path);
            return;
        }
    }
    try results.append(alloc, path);
}

test "discover expands configured home paths" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("HOME", "/tmp/shg-home");

    const cache_bytes = try rules.compile(alloc, "", "", "~/.zsh_history");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    const paths = try discover(.blocking, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 0), paths.len);
}

test "discover keeps existing configured paths" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compile(alloc, "", "", "/dev/null");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    const paths = try discover(.blocking, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(.blocking, "/dev/null")) {
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/dev/null", paths[0]);
    } else {
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

test "discover includes HISTFILE" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compile(alloc, "", "", "");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("HISTFILE", "/dev/null");

    const paths = try discover(.blocking, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(.blocking, "/dev/null")) {
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/dev/null", paths[0]);
    } else {
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

test "discover deduplicates HISTFILE and configured paths" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compile(alloc, "", "", "/dev/null");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("HISTFILE", "/dev/null");

    const paths = try discover(.blocking, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(.blocking, "/dev/null")) {
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/dev/null", paths[0]);
    } else {
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

fn fileExists(io: Io, path: []const u8) bool {
    const f = Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
    f.close(io);
    return true;
}
