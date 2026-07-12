const std = @import("std");

pub const ignore_default_filename = "ignore.default.shg";
pub const match_default_filename = "match.default.shg";
pub const paths_default_filename = "paths.default.shg";
pub const deep_paths_default_filename = "paths.deep.default.shg";
pub const compiled_filename = "rules.bin";

pub fn configDir(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    if (environ.get("XDG_CONFIG_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{ xdg, "shg" });
    }

    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return null;
    if (home.len == 0) return null;
    return try std.fs.path.join(alloc, &.{ home, ".config", "shg" });
}

pub fn ignoreDefaultFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, ignore_default_filename);
}

pub fn matchDefaultFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, match_default_filename);
}

pub fn pathsDefaultFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, paths_default_filename);
}

pub fn deepPathsDefaultFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, deep_paths_default_filename);
}

pub fn compiledFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, compiled_filename);
}

pub fn systemConfigDir(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    const prefix = environ.get("HOMEBREW_PREFIX") orelse return null;
    if (prefix.len == 0) return null;
    return try std.fs.path.join(alloc, &.{ prefix, "share", "shg", "defaults" });
}

fn configFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, filename: []const u8) !?[]const u8 {
    const dir = (try configDir(alloc, environ)) orelse return null;
    defer alloc.free(dir);
    return try std.fs.path.join(alloc, &.{ dir, filename });
}

test "config dir uses XDG_CONFIG_HOME" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("XDG_CONFIG_HOME", "/tmp/xdg");
    try env.put("HOME", "/home/user");

    const dir = (try configDir(alloc, &env)).?;
    defer alloc.free(dir);
    try std.testing.expectEqualStrings("/tmp/xdg/shg", dir);
}

test "config dir falls back to HOME config" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("HOME", "/home/user");

    const dir = (try configDir(alloc, &env)).?;
    defer alloc.free(dir);
    try std.testing.expectEqualStrings("/home/user/.config/shg", dir);
}

test "config dir ignores empty XDG_CONFIG_HOME" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("XDG_CONFIG_HOME", "");
    try env.put("HOME", "/home/user");

    const dir = (try configDir(alloc, &env)).?;
    defer alloc.free(dir);
    try std.testing.expectEqualStrings("/home/user/.config/shg", dir);
}

test "config dir is absent without config roots" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    try std.testing.expect((try configDir(alloc, &env)) == null);
}

test "config files are under config dir" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();
    try env.put("XDG_CONFIG_HOME", "/tmp/xdg");

    const ignore = (try ignoreDefaultFile(alloc, &env)).?;
    defer alloc.free(ignore);
    const match = (try matchDefaultFile(alloc, &env)).?;
    defer alloc.free(match);
    const paths = (try pathsDefaultFile(alloc, &env)).?;
    defer alloc.free(paths);

    const compiled = (try compiledFile(alloc, &env)).?;
    defer alloc.free(compiled);

    try std.testing.expectEqualStrings("/tmp/xdg/shg/ignore.default.shg", ignore);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/match.default.shg", match);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/paths.default.shg", paths);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/rules.bin", compiled);
}

test "config files are absent without config roots" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    try std.testing.expect((try ignoreDefaultFile(alloc, &env)) == null);
    try std.testing.expect((try matchDefaultFile(alloc, &env)) == null);
    try std.testing.expect((try pathsDefaultFile(alloc, &env)) == null);
    try std.testing.expect((try compiledFile(alloc, &env)) == null);
}
