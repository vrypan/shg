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
            if (isDirectory(io, resolved)) {
                try appendDirectoryFiles(io, alloc, &results, resolved);
                alloc.free(resolved);
            } else {
                try appendExistingPath(io, alloc, &results, resolved);
            }
        }
    }

    return results.toOwnedSlice(alloc);
}

/// Expand explicit --path arguments: a directory is walked recursively into
/// its files, a plain file is kept as-is. A leading ~/ is expanded. Missing
/// paths are dropped, mirroring the scan loop which skips unreadable files.
pub fn expandExplicitPaths(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, paths: []const []const u8) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;
    for (paths) |raw| {
        const resolved = (try expandPath(alloc, environ, raw)) orelse continue;
        if (isDirectory(io, resolved)) {
            try appendDirectoryFiles(io, alloc, &results, resolved);
            alloc.free(resolved);
        } else {
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

// Recursively collect all files under dir_path. Does not take ownership of dir_path.
fn appendDirectoryFiles(io: Io, alloc: std.mem.Allocator, results: *std.ArrayList([]const u8), dir_path: []const u8) !void {
    var dir = Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const child = try std.fs.path.join(alloc, &.{ dir_path, entry.name });
        switch (entry.kind) {
            .file, .unknown => try appendExistingPath(io, alloc, results, child),
            .directory => {
                try appendDirectoryFiles(io, alloc, results, child);
                alloc.free(child);
            },
            else => alloc.free(child),
        }
    }
}

test "expandExplicitPaths keeps existing files and drops missing ones" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    const input = [_][]const u8{ "/dev/null", "/nonexistent/shg/path/xyz" };
    const paths = try expandExplicitPaths(std.testing.io, alloc, &env, &input);
    defer {
        for (paths) |p| alloc.free(p);
        alloc.free(paths);
    }

    if (fileExists(std.testing.io, "/dev/null")) {
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/dev/null", paths[0]);
    } else {
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

test "discover expands configured home paths" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("HOME", "/tmp/shg-home");

    const cache_bytes = try rules.compile(alloc, "", "", "~/.zsh_history");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    const paths = try discover(std.testing.io, alloc, &env, cache);
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

    const paths = try discover(std.testing.io, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(std.testing.io, "/dev/null")) {
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

    const paths = try discover(std.testing.io, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(std.testing.io, "/dev/null")) {
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

    const paths = try discover(std.testing.io, alloc, &env, cache);
    defer {
        for (paths) |path| alloc.free(path);
        alloc.free(paths);
    }

    if (fileExists(std.testing.io, "/dev/null")) {
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

fn isDirectory(io: Io, path: []const u8) bool {
    const d = Io.Dir.openDirAbsolute(io, path, .{ .iterate = false }) catch return false;
    d.close(io);
    return true;
}
