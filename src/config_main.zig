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
        try stdout.interface.writeAll(
            \\Usage:
            \\  shg-config compile
            \\  shg-config defaults [-y]
            \\  shg-config discover
            \\  shg-config status
            \\
        );
        return;
    }

    const command = raw_args[1];
    if (!std.mem.eql(u8, command, "compile") and
        !std.mem.eql(u8, command, "defaults") and
        !std.mem.eql(u8, command, "discover") and
        !std.mem.eql(u8, command, "status"))
    {
        try stderr.interface.writeAll("error: expected command 'compile', 'defaults', 'discover', or 'status'\n");
        try stderr.flush();
        std.process.exit(2);
    }

    if (std.mem.eql(u8, command, "discover")) {
        try runDiscover(io, alloc, init.environ_map, &stdout, &stderr);
        return;
    }

    if (std.mem.eql(u8, command, "status")) {
        try runStatus(io, alloc, init.environ_map, &stdout);
        return;
    }

    const force_yes = if (std.mem.eql(u8, command, "defaults"))
        try parseDefaultsArgs(raw_args[2..], &stderr)
    else blk: {
        if (raw_args.len != 2) {
            try stderr.interface.writeAll("error: compile takes no options\n");
            try stderr.flush();
            std.process.exit(2);
        }
        break :blk false;
    };

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
    const default_files = [_]DefaultFile{
        .{ .path = ignore_default_path, .bytes = default_ignore_rules },
        .{ .path = match_default_path, .bytes = default_match_rules },
        .{ .path = paths_default_path, .bytes = default_paths_rules },
    };

    if (std.mem.eql(u8, command, "defaults")) {
        try writeDefaults(io, &stdout, default_files[0..], force_yes, true);
        return;
    }

    const compiled_path = (try config.compiledFile(alloc, init.environ_map)).?;

    var ignore_group = try readConfigGroup(io, alloc, dir, "ignore.", ".shg");
    var match_group = try readConfigGroup(io, alloc, dir, "match.", ".shg");
    var paths_group = try readConfigGroup(io, alloc, dir, "paths.", ".shg");

    if (ignore_group.count == 0 or match_group.count == 0 or paths_group.count == 0) {
        try stdout.interface.print("Config files are missing in {s}. \nCreate default ignore.default.shg, match.default.shg, and paths.default.shg? \n[y/N] ", .{dir});
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

const default_ignore_rules = @embedFile("defaults/ignore.default.shg");
const default_match_rules = @embedFile("defaults/match.default.shg");
const default_paths_rules = @embedFile("defaults/paths.default.shg");

const DefaultFile = struct {
    path: []const u8,
    bytes: []const u8,
};

fn parseDefaultsArgs(args: []const []const u8, stderr: *Io.File.Writer) !bool {
    if (args.len == 0) return false;
    if (args.len == 1 and std.mem.eql(u8, args[0], "-y")) return true;
    try stderr.interface.writeAll("error: expected defaults option '-y'\n");
    try stderr.flush();
    std.process.exit(2);
}

fn writeDefaults(io: Io, stdout: *Io.File.Writer, files: []const DefaultFile, force_yes: bool, prompt_existing: bool) !void {
    for (files) |file| {
        if (fileExists(io, file.path) and !force_yes) {
            if (prompt_existing) {
                try stdout.interface.print("{s} exists. Overwrite? [yes/no] ", .{file.path});
                try stdout.flush();
                if (!try promptYes(io)) {
                    try stdout.interface.print("kept {s}\n", .{file.path});
                    continue;
                }
            } else {
                continue;
            }
        }
        try writeFile(io, file.path, file.bytes);
        try stdout.interface.print("wrote {s}\n", .{file.path});
    }
}

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

fn runDiscover(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, stdout: *Io.File.Writer, stderr: *Io.File.Writer) !void {
    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse {
        try stderr.interface.writeAll("error: cannot determine home directory\n");
        try stderr.flush();
        std.process.exit(2);
    };

    // Collect all .*history files in HOME.
    var home_dir = Io.Dir.openDirAbsolute(io, home, .{ .iterate = true }) catch |err| {
        try stderr.interface.print("error: cannot open home directory: {t}\n", .{err});
        try stderr.flush();
        std.process.exit(2);
    };
    defer home_dir.close(io);

    var found: std.ArrayList([]const u8) = .empty;
    defer {
        for (found.items) |p| alloc.free(p);
        found.deinit(alloc);
    }
    var it = home_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .unknown) continue;
        if (!std.mem.startsWith(u8, entry.name, ".")) continue;
        if (!std.mem.endsWith(u8, entry.name, "history")) continue;
        try found.append(alloc, try std.fs.path.join(alloc, &.{ home, entry.name }));
    }

    if (found.items.len == 0) {
        try stdout.interface.writeAll("No .*history files found in home directory.\n");
        return;
    }

    // Collect paths already known from compiled rules.
    var known: std.ArrayList([]const u8) = .empty;
    defer {
        for (known.items) |p| alloc.free(p);
        known.deinit(alloc);
    }
    if (try config.compiledFile(alloc, environ)) |cp| {
        defer alloc.free(cp);
        if (Io.Dir.openFileAbsolute(io, cp, .{})) |f| {
            defer f.close(io);
            if (f.stat(io)) |stat| {
                var read_buf: [8192]u8 = undefined;
                var reader = f.reader(io, &read_buf);
                if (reader.interface.readAlloc(alloc, @intCast(stat.size))) |bytes| {
                    if (rules.Cache.init(bytes)) |cache| {
                        var i: usize = 0;
                        while (i < cache.ruleCount()) : (i += 1) {
                            const r = cache.rule(i) catch continue;
                            if (r.kind != .path) continue;
                            const expanded = if (std.mem.startsWith(u8, r.pattern, "~/"))
                                try std.fs.path.join(alloc, &.{ home, r.pattern[2..] })
                            else
                                try alloc.dupe(u8, r.pattern);
                            try known.append(alloc, expanded);
                        }
                    } else |_| {}
                } else |_| {}
            } else |_| {}
        } else |_| {}
    }

    // Filter to paths not already configured.
    var novel: std.ArrayList([]const u8) = .empty;
    defer novel.deinit(alloc);
    for (found.items) |path| {
        var already = false;
        for (known.items) |k| {
            if (std.mem.eql(u8, path, k)) {
                already = true;
                break;
            }
        }
        if (!already) try novel.append(alloc, path);
    }

    if (novel.items.len == 0) {
        try stdout.interface.writeAll("All discovered history files are already configured.\n");
        return;
    }

    try stdout.interface.writeAll("Found history files not in your current configuration:\n");
    for (novel.items) |path| {
        try stdout.interface.print("  {s}\n", .{path});
    }

    const dir = (try config.configDir(alloc, environ)) orelse {
        try stderr.interface.writeAll("error: cannot determine config directory\n");
        try stderr.flush();
        std.process.exit(2);
    };
    const local_path = try std.fs.path.join(alloc, &.{ dir, "paths.local.shg" });

    try stdout.interface.print("\nAdd to {s}? [y/N] ", .{local_path});
    try stdout.flush();
    if (!try promptYes(io)) return;

    // Build the text to append (using ~/... paths for portability).
    var append_buf: std.ArrayList(u8) = .empty;
    defer append_buf.deinit(alloc);
    for (novel.items) |path| {
        const rel = if (std.mem.startsWith(u8, path, home))
            try std.mem.concat(alloc, u8, &.{ "~/", path[home.len + 1 ..] })
        else
            try alloc.dupe(u8, path);
        defer alloc.free(rel);
        try append_buf.appendSlice(alloc, rel);
        try append_buf.append(alloc, '\n');
    }

    // Append new paths to paths.local.shg.
    const f = try Io.Dir.createFileAbsolute(io, local_path, .{ .truncate = false });
    defer f.close(io);
    const offset = try f.length(io);
    try f.writePositionalAll(io, append_buf.items, offset);

    try stdout.interface.print("wrote {s}\n", .{local_path});
    try stdout.interface.writeAll("Run 'shg-config compile' to apply changes.\n");
}

fn runStatus(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map, stdout: *Io.File.Writer) !void {
    const dir = (try config.configDir(alloc, environ)) orelse "(not found)";
    const compiled_path = try config.compiledFile(alloc, environ);
    try stdout.interface.print("Config directory: {s}\n", .{dir});
    try stdout.interface.print("Compiled rules:   {s}\n\n", .{compiled_path orelse "(none)"});

    try stdout.interface.writeAll(
        \\Detection categories:
        \\
        \\  inline_assign     VAR=value with sensitive keywords
        \\  auth_header       Authorization: Bearer <token>, --password <val>
        \\  credential_url    scheme://user:pass@host
        \\  config_check      compiled match.*.shg pattern match
        \\  private_key       -----BEGIN * KEY----- markers
        \\  age_secret_key    AGE-SECRET-KEY-1... markers
        \\  ssh_key           ssh-rsa / ssh-ed25519 / ecdsa public keys
        \\
    );

    const cache = blk: {
        const path = compiled_path orelse break :blk null;
        const f = Io.Dir.openFileAbsolute(io, path, .{}) catch break :blk null;
        defer f.close(io);
        const stat = f.stat(io) catch break :blk null;
        var read_buf: [8192]u8 = undefined;
        var reader = f.reader(io, &read_buf);
        const bytes = reader.interface.readAlloc(alloc, @intCast(stat.size)) catch break :blk null;
        break :blk rules.Cache.init(bytes) catch null;
    };

    const c = cache orelse {
        try stdout.interface.writeAll("Compiled rules: none — run shg-config compile\n");
        return;
    };

    const sections = [_]struct { kind: rules.RuleKind, label: []const u8 }{
        .{ .kind = .check,  .label = "Match rules:"   },
        .{ .kind = .ignore, .label = "Ignore rules:"  },
        .{ .kind = .path,   .label = "History paths:" },
    };

    for (sections) |section| {
        var found = false;
        var i: usize = 0;
        while (i < c.ruleCount()) : (i += 1) {
            const rule = try c.rule(i);
            if (rule.kind != section.kind) continue;
            if (!found) {
                try stdout.interface.print("\n{s}\n\n", .{section.label});
                found = true;
            }
            if (section.kind == .path) {
                try stdout.interface.print("  {s}\n", .{rule.pattern});
            } else {
                const kind_str = switch (rule.match_kind) {
                    .prefix    => "prefix",
                    .exact     => "exact ",
                    .substring => "substr",
                };
                try stdout.interface.print("  {s}  {s}\n", .{ kind_str, rule.pattern });
            }
        }
        if (found) try stdout.interface.writeByte('\n');
    }
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
