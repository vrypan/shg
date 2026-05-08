const std = @import("std");
const Io = std.Io;
const rules = @import("rules.zig");

pub fn discover(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, cache: rules.Cache) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;

    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const rule = try cache.rule(i);
        if (rule.kind != .path) continue;

        const path = try expandPath(alloc, environ, rule.pattern);
        if (path) |resolved| {
            if (fileExists(io, resolved)) {
                try results.append(alloc, resolved);
            } else {
                alloc.free(resolved);
            }
        }
    }

    return results.toOwnedSlice(alloc);
}

fn expandPath(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, path: []const u8) !?[]const u8 {
    if (std.mem.startsWith(u8, path, "~/")) {
        const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return null;
        if (home.len == 0) return null;
        return try std.fs.path.join(alloc, &.{ home, path[2..] });
    }
    return try alloc.dupe(u8, path);
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

fn fileExists(io: Io, path: []const u8) bool {
    const f = Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
    f.close(io);
    return true;
}
