const std = @import("std");

pub fn configDir(alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    if (environ.get("XDG_CONFIG_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{ xdg, "shg" });
    }

    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return null;
    if (home.len == 0) return null;
    return try std.fs.path.join(alloc, &.{ home, ".config", "shg" });
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
