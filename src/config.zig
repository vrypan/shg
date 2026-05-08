const std = @import("std");

pub const ignore_filename = "ignore.rules";
pub const check_filename = "check.rules";
pub const paths_filename = "paths.rules";
pub const compiled_filename = "rules.bin";

pub fn configDir(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    if (environ.get("XDG_CONFIG_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{ xdg, "shg" });
    }

    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return null;
    if (home.len == 0) return null;
    return try std.fs.path.join(alloc, &.{ home, ".config", "shg" });
}

pub fn ignoreFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, ignore_filename);
}

pub fn checkFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, check_filename);
}

pub fn pathsFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, paths_filename);
}

pub fn compiledFile(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    return configFile(alloc, environ, compiled_filename);
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

    const ignore = (try ignoreFile(alloc, &env)).?;
    defer alloc.free(ignore);
    const check = (try checkFile(alloc, &env)).?;
    defer alloc.free(check);
    const paths = (try pathsFile(alloc, &env)).?;
    defer alloc.free(paths);

    const compiled = (try compiledFile(alloc, &env)).?;
    defer alloc.free(compiled);

    try std.testing.expectEqualStrings("/tmp/xdg/shg/ignore.rules", ignore);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/check.rules", check);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/paths.rules", paths);
    try std.testing.expectEqualStrings("/tmp/xdg/shg/rules.bin", compiled);
}

test "config files are absent without config roots" {
    const alloc = std.testing.allocator;
    var env = std.process.Environ.Map.init(alloc);
    defer env.deinit();

    try std.testing.expect((try ignoreFile(alloc, &env)) == null);
    try std.testing.expect((try checkFile(alloc, &env)) == null);
    try std.testing.expect((try pathsFile(alloc, &env)) == null);
    try std.testing.expect((try compiledFile(alloc, &env)) == null);
}
