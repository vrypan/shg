const std = @import("std");
const Io = std.Io;
const rules = @import("rules.zig");

pub fn discover(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, cache: rules.Cache) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;
    const exclusions = try pathExclusions(alloc, environ, cache, .path);
    defer freePaths(alloc, exclusions);

    try appendEnvHistoryPaths(io, alloc, environ, &results, exclusions);

    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const rule = try cache.rule(i);
        if (rule.kind != .path) continue;
        if (isExclusion(rule.pattern)) continue;

        const path = try expandPath(alloc, environ, rule.pattern);
        if (path) |resolved| {
            if (isExcluded(resolved, exclusions)) {
                alloc.free(resolved);
                continue;
            }
            if (isDirectory(io, resolved)) {
                try appendDirectoryFiles(io, alloc, &results, resolved, exclusions);
                alloc.free(resolved);
            } else {
                try appendExistingPath(io, alloc, &results, resolved);
            }
        }
    }

    return results.toOwnedSlice(alloc);
}

pub const DeepFile = struct {
    path: []const u8,
    root_index: usize,
};

pub const DeepDiscovery = struct {
    roots: []const []const u8,
    files: []const DeepFile,
};

/// Expand compiled deep paths while retaining the root associated with each
/// file. This lets `shg deep` report progress once per configured path.
pub fn discoverDeep(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, cache: rules.Cache) !DeepDiscovery {
    var roots: std.ArrayList([]const u8) = .empty;
    var paths: std.ArrayList([]const u8) = .empty;
    const exclusions = try pathExclusions(alloc, environ, cache, .deep_path);
    defer freePaths(alloc, exclusions);

    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const rule = try cache.rule(i);
        if (rule.kind != .deep_path) continue;
        if (isExclusion(rule.pattern)) continue;

        const path = try expandPath(alloc, environ, rule.pattern);
        if (path) |resolved| {
            if (isExcluded(resolved, exclusions)) {
                alloc.free(resolved);
                continue;
            }
            const root_index = try appendDeepRoot(alloc, &roots, resolved);
            const root = roots.items[root_index];
            if (isDirectory(io, root)) {
                try appendDirectoryFiles(io, alloc, &paths, root, exclusions);
            } else {
                try appendExistingPath(io, alloc, &paths, try alloc.dupe(u8, root));
            }
        }
    }

    const root_slice = try roots.toOwnedSlice(alloc);
    return .{
        .roots = root_slice,
        .files = try groupDeepFiles(alloc, root_slice, &paths),
    };
}

/// Strict grouped discovery for explicitly named deep paths.
pub fn expandExplicitDeepPaths(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, paths: []const []const u8) !DeepDiscovery {
    var roots: std.ArrayList([]const u8) = .empty;
    var files: std.ArrayList([]const u8) = .empty;

    for (paths) |raw| {
        const resolved = (try expandPath(alloc, environ, raw)) orelse return error.InvalidPath;
        const root_index = try appendDeepRoot(alloc, &roots, resolved);
        const root = roots.items[root_index];
        if (isDirectory(io, root)) {
            try appendDirectoryFilesStrict(io, alloc, &files, root);
        } else {
            try appendExplicitFile(io, alloc, &files, try alloc.dupe(u8, root));
        }
    }

    const root_slice = try roots.toOwnedSlice(alloc);
    return .{
        .roots = root_slice,
        .files = try groupDeepFiles(alloc, root_slice, &files),
    };
}

/// Expand explicit --path arguments: a directory is walked recursively into
/// its files, a plain file is kept as-is. A leading ~/ is expanded. Missing
/// paths are dropped, mirroring the scan loop which skips unreadable files.
pub fn expandExplicitPaths(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, paths: []const []const u8) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;
    for (paths) |raw| {
        const resolved = (try expandPath(alloc, environ, raw)) orelse return error.InvalidPath;
        if (isDirectory(io, resolved)) {
            try appendDirectoryFilesStrict(io, alloc, &results, resolved);
            alloc.free(resolved);
        } else {
            try appendExplicitFile(io, alloc, &results, resolved);
        }
    }
    return results.toOwnedSlice(alloc);
}

fn appendEnvHistoryPaths(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, results: *std.ArrayList([]const u8), exclusions: []const []const u8) !void {
    const env_vars = [_][]const u8{
        "HISTFILE",
    };
    for (env_vars) |name| {
        const value = environ.get(name) orelse continue;
        if (value.len == 0) continue;
        const path = try expandPath(alloc, environ, value);
        if (path) |resolved| {
            if (isExcluded(resolved, exclusions)) {
                alloc.free(resolved);
            } else {
                try appendExistingPath(io, alloc, results, resolved);
            }
        }
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
    // A directory can be opened but not read as a stream; scanning one aborts
    // the whole run. Skip directories here (e.g. a HISTFILE pointing at a dir);
    // configured directory paths are walked separately by appendDirectoryFiles.
    if (!fileExists(io, path) or isDirectory(io, path)) {
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

fn appendExplicitFile(io: Io, alloc: std.mem.Allocator, results: *std.ArrayList([]const u8), path: []const u8) !void {
    errdefer alloc.free(path);
    const file = try Io.Dir.openFileAbsolute(io, path, .{ .allow_directory = false });
    file.close(io);
    for (results.items) |existing| {
        if (std.mem.eql(u8, existing, path)) {
            alloc.free(path);
            return;
        }
    }
    try results.append(alloc, path);
}

// Recursively collect non-excluded files under dir_path. Does not take
// ownership of dir_path.
fn appendDirectoryFiles(io: Io, alloc: std.mem.Allocator, results: *std.ArrayList([]const u8), dir_path: []const u8, exclusions: []const []const u8) !void {
    var dir = Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const child = try std.fs.path.join(alloc, &.{ dir_path, entry.name });
        if (isExcluded(child, exclusions)) {
            alloc.free(child);
            continue;
        }
        switch (entry.kind) {
            .file, .unknown => try appendExistingPath(io, alloc, results, child),
            .directory => {
                try appendDirectoryFiles(io, alloc, results, child, exclusions);
                alloc.free(child);
            },
            else => alloc.free(child),
        }
    }
}

// Explicit directories are strict: a path the user named must not produce a
// clean result when it cannot be opened or one of its files cannot be read.
fn appendDirectoryFilesStrict(io: Io, alloc: std.mem.Allocator, results: *std.ArrayList([]const u8), dir_path: []const u8) !void {
    var dir = try Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const child = try std.fs.path.join(alloc, &.{ dir_path, entry.name });
        switch (entry.kind) {
            .file, .unknown => try appendExplicitFile(io, alloc, results, child),
            .directory => {
                try appendDirectoryFilesStrict(io, alloc, results, child);
                alloc.free(child);
            },
            else => alloc.free(child),
        }
    }
}

fn appendDeepRoot(alloc: std.mem.Allocator, roots: *std.ArrayList([]const u8), path: []const u8) !usize {
    for (roots.items, 0..) |existing, index| {
        if (std.mem.eql(u8, existing, path)) {
            alloc.free(path);
            return index;
        }
    }
    try roots.append(alloc, path);
    return roots.items.len - 1;
}

fn pathExclusions(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, cache: rules.Cache, kind: rules.RuleKind) ![][]const u8 {
    var exclusions: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < cache.ruleCount()) : (i += 1) {
        const rule = try cache.rule(i);
        if (rule.kind != kind or !isExclusion(rule.pattern)) continue;
        const raw = std.mem.trim(u8, rule.pattern[1..], " \t");
        if (raw.len == 0) continue;
        if (try expandPath(alloc, environ, raw)) |path| try exclusions.append(alloc, path);
    }
    return exclusions.toOwnedSlice(alloc);
}

fn isExclusion(pattern: []const u8) bool {
    return pattern.len > 0 and pattern[0] == '!';
}

fn isExcluded(path: []const u8, exclusions: []const []const u8) bool {
    for (exclusions) |excluded| {
        if (pathWithinRoot(path, excluded)) return true;
    }
    return false;
}

fn freePaths(alloc: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |path| alloc.free(path);
    alloc.free(paths);
}

fn groupDeepFiles(alloc: std.mem.Allocator, roots: []const []const u8, paths: *std.ArrayList([]const u8)) ![]DeepFile {
    var files: std.ArrayList(DeepFile) = .empty;
    for (paths.items) |path| {
        const root_index = deepRootIndex(roots, path);
        try files.append(alloc, .{ .path = path, .root_index = root_index });
    }
    paths.deinit(alloc);
    return files.toOwnedSlice(alloc);
}

fn deepRootIndex(roots: []const []const u8, path: []const u8) usize {
    var best: ?usize = null;
    for (roots, 0..) |root, index| {
        if (!pathWithinRoot(path, root)) continue;
        if (best == null or root.len > roots[best.?].len) best = index;
    }
    return best orelse 0;
}

fn pathWithinRoot(path: []const u8, root: []const u8) bool {
    if (std.mem.eql(u8, path, root)) return true;
    return path.len > root.len and std.mem.startsWith(u8, path, root) and std.fs.path.isSep(path[root.len]);
}

test "deep root selection handles equal-length and nested roots" {
    const equal_roots = [_][]const u8{ "/tmp/one", "/tmp/two" };
    try std.testing.expectEqual(@as(usize, 1), deepRootIndex(&equal_roots, "/tmp/two/file"));

    const nested_roots = [_][]const u8{ "/tmp/project", "/tmp/project/nested" };
    try std.testing.expectEqual(@as(usize, 1), deepRootIndex(&nested_roots, "/tmp/project/nested/file"));
}

test "path exclusions match exact paths and descendants only" {
    const exclusions = [_][]const u8{"/tmp/project/memory"};
    try std.testing.expect(isExcluded("/tmp/project/memory", &exclusions));
    try std.testing.expect(isExcluded("/tmp/project/memory/MEMORY.md", &exclusions));
    try std.testing.expect(!isExcluded("/tmp/project/memory-other", &exclusions));
    try std.testing.expect(!isExcluded("/tmp/project/session.jsonl", &exclusions));
}

test "expandExplicitPaths keeps existing files" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    const input = [_][]const u8{"/dev/null"};
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

test "expandExplicitPaths rejects missing paths" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    const input = [_][]const u8{"/nonexistent/shg/path/xyz"};
    try std.testing.expectError(error.FileNotFound, expandExplicitPaths(std.testing.io, alloc, &env, &input));
}

test "discoverDeep retains configured roots for files" {
    const alloc = std.testing.allocator;
    const cache_bytes = try rules.compileFull(alloc, "", "", "", "", "", "/dev/null");
    defer alloc.free(cache_bytes);
    const cache = try rules.Cache.init(cache_bytes);

    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    const discovery = try discoverDeep(std.testing.io, alloc, &env, cache);
    defer {
        for (discovery.roots) |root| alloc.free(root);
        for (discovery.files) |file| alloc.free(file.path);
        alloc.free(discovery.roots);
        alloc.free(discovery.files);
    }

    try std.testing.expectEqual(@as(usize, 1), discovery.roots.len);
    try std.testing.expectEqualStrings("/dev/null", discovery.roots[0]);
    if (fileExists(std.testing.io, "/dev/null")) {
        try std.testing.expectEqual(@as(usize, 1), discovery.files.len);
        try std.testing.expectEqual(@as(usize, 0), discovery.files[0].root_index);
        try std.testing.expectEqualStrings("/dev/null", discovery.files[0].path);
    } else {
        try std.testing.expectEqual(@as(usize, 0), discovery.files.len);
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
