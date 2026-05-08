const std = @import("std");
const Io = std.Io;
const config = @import("config.zig");
const rules = @import("rules.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const alloc = init.arena.allocator();

    var out_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    defer stdout.flush() catch {};

    var err_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
    defer stderr.flush() catch {};

    const raw_args = try init.minimal.args.toSlice(alloc);
    if (raw_args.len < 2 or std.mem.eql(u8, raw_args[1], "help") or
        std.mem.eql(u8, raw_args[1], "--help") or std.mem.eql(u8, raw_args[1], "-h"))
    {
        try stdout.interface.writeAll("Usage: shg-config compile\n");
        return;
    }

    if (!std.mem.eql(u8, raw_args[1], "compile") or raw_args.len != 2) {
        try stderr.interface.writeAll("error: expected command 'compile'\n\nUsage: shg-config compile\n");
        try stderr.flush();
        std.process.exit(2);
    }

    const dir = (try config.configDir(alloc, init.environ_map)) orelse {
        try stderr.interface.writeAll("error: cannot determine config directory; set XDG_CONFIG_HOME or HOME\n");
        try stderr.flush();
        std.process.exit(2);
    };
    Io.Dir.createDirPath(.cwd(), io, dir) catch |err| {
        try stderr.interface.print("error: cannot create config directory {s}: {t}\n", .{ dir, err });
        try stderr.flush();
        std.process.exit(2);
    };

    const ignore_default_path = (try config.ignoreDefaultFile(alloc, init.environ_map)).?;
    const match_default_path = (try config.matchDefaultFile(alloc, init.environ_map)).?;
    const paths_default_path = (try config.pathsDefaultFile(alloc, init.environ_map)).?;
    const compiled_path = (try config.compiledFile(alloc, init.environ_map)).?;

    var ignore_group = try readConfigGroup(io, alloc, dir, "ignore.", ".shg");
    var match_group = try readConfigGroup(io, alloc, dir, "match.", ".shg");
    var paths_group = try readConfigGroup(io, alloc, dir, "paths.", ".shg");

    if (ignore_group.count == 0 or match_group.count == 0 or paths_group.count == 0) {
        try stdout.interface.print("Config files are missing in {s}. Create default ignore.default.shg, match.default.shg, and paths.default.shg? [y/N] ", .{dir});
        try stdout.flush();
        if (try promptYes(io)) {
            if (ignore_group.count == 0 and !fileExists(io, ignore_default_path)) try writeFile(io, ignore_default_path, default_ignore_rules);
            if (match_group.count == 0 and !fileExists(io, match_default_path)) try writeFile(io, match_default_path, default_match_rules);
            if (paths_group.count == 0 and !fileExists(io, paths_default_path)) try writeFile(io, paths_default_path, default_paths_rules);
            try stdout.interface.writeAll("created default config files\n");
            ignore_group = try readConfigGroup(io, alloc, dir, "ignore.", ".shg");
            match_group = try readConfigGroup(io, alloc, dir, "match.", ".shg");
            paths_group = try readConfigGroup(io, alloc, dir, "paths.", ".shg");
        } else {
            try stderr.interface.writeAll("error: config files are missing; create them or rerun and answer yes\n");
            try stderr.flush();
            std.process.exit(2);
        }
    }

    const compiled = try rules.compile(alloc, ignore_group.text, match_group.text, paths_group.text);
    try writeFile(io, compiled_path, compiled);

    try stdout.interface.print("compiled rules: {s}\n", .{compiled_path});
}

const default_ignore_rules =
    \\# shg ignore rules
    \\# Lines are substring matches by default. Use exact:, prefix:, or substr:.
    \\prefix:SSH_AUTH_SOCK=
    \\prefix:STARSHIP_SESSION_KEY=
    \\prefix:GPG_AGENT_INFO=
    \\prefix:DBUS_SESSION_BUS_ADDRESS=
    \\prefix:PWD=
    \\prefix:OLDPWD=
    \\prefix:OLD_PWD=
    \\
;

const default_match_rules =
    \\# shg match rules
    \\# Lines are substring matches by default. Use exact:, prefix:, or substr:.
    \\sk-ant-
    \\sk-
    \\github_pat_
    \\ghp_
    \\gho_
    \\ghu_
    \\ghs_
    \\ghr_
    \\xoxb-
    \\xoxp-
    \\xapp-
    \\xwfp-
    \\AKIA
    \\ASIA
    \\sk_live_
    \\sk_test_
    \\rk_live_
    \\rk_test_
    \\whsec_
    \\sk_org_
    \\-----BEGIN PRIVATE KEY-----
    \\-----BEGIN ENCRYPTED PRIVATE KEY-----
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\-----BEGIN EC PRIVATE KEY-----
    \\-----BEGIN RSA PRIVATE KEY-----
    \\-----BEGIN DSA PRIVATE KEY-----
    \\-----BEGIN PGP PRIVATE KEY BLOCK-----
    \\AGE-SECRET-KEY-1
    \\ssh-rsa AAAA
    \\
;

const default_paths_rules =
    \\# shg history paths
    \\# One path per line. A leading ~/ expands to your home directory.
    \\~/.zsh_history
    \\~/.bash_history
    \\~/.local/share/fish/fish_history
    \\~/.config/fish/fish_history
    \\~/.python_history
    \\~/.psql_history
    \\~/.mysql_history
    \\~/.sqlite_history
    \\~/.rediscli_history
    \\
;

fn promptYes(io: Io) !bool {
    var stdin_buf: [128]u8 = undefined;
    var stdin = Io.File.stdin().readerStreaming(io, &stdin_buf);
    const line = stdin.interface.takeDelimiter('\n') catch |err| switch (err) {
        error.StreamTooLong => return false,
        else => return err,
    } orelse return false;
    const answer = std.mem.trim(u8, line, " \t\r\n");
    return std.ascii.eqlIgnoreCase(answer, "y") or std.ascii.eqlIgnoreCase(answer, "yes");
}

fn fileExists(io: Io, path: []const u8) bool {
    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
    file.close(io);
    return true;
}

const ConfigGroup = struct {
    text: []const u8,
    count: usize,
};

fn readConfigGroup(io: Io, alloc: std.mem.Allocator, dir_path: []const u8, prefix: []const u8, suffix: []const u8) !ConfigGroup {
    var dir = try Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |name| alloc.free(name);
        names.deinit(alloc);
    }

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .unknown) continue;
        if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
        if (!std.mem.endsWith(u8, entry.name, suffix)) continue;
        try names.append(alloc, try alloc.dupe(u8, entry.name));
    }

    std.mem.sort([]const u8, names.items, {}, lessThanString);

    var out: std.ArrayList(u8) = .empty;
    for (names.items) |name| {
        const path = try std.fs.path.join(alloc, &.{ dir_path, name });
        defer alloc.free(path);
        const text = try readFile(io, alloc, path);
        defer alloc.free(text);
        try out.appendSlice(alloc, text);
        if (text.len > 0 and text[text.len - 1] != '\n') try out.append(alloc, '\n');
    }
    return .{ .text = try out.toOwnedSlice(alloc), .count = names.items.len };
}

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn readFile(io: Io, alloc: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return try reader.interface.readAlloc(alloc, @intCast(stat.size));
}

fn writeFile(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    var write_buf: [8192]u8 = undefined;
    var writer = file.writerStreaming(io, &write_buf);
    try writer.interface.writeAll(bytes);
    try writer.flush();
}
