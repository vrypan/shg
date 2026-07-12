const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const config = @import("config.zig");
const rules = @import("rules.zig");
const sources = @import("sources.zig");
const detect = @import("detect.zig");
const scorer = @import("scorer.zig");
const history_parse = @import("history_parse.zig");

const Entry = @import("entry.zig").Entry;
const Severity = @import("finding.zig").Severity;

// One flagged history entry: the physical line span to remove and both display
// forms (full and redacted).
const Candidate = struct {
    start: usize, // 1-based first physical line
    end: usize, // 1-based last physical line (inclusive)
    full: []const u8,
    redacted: []const u8,
};

pub fn run(init: std.process.Init, args: cli.Args) !void {
    const io = init.io;
    const alloc = init.arena.allocator();
    const environ = init.environ_map;

    var out_buf: [32768]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    defer stdout.flush() catch {};

    var err_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
    defer stderr.flush() catch {};

    const cache = (try loadRules(io, alloc, environ)) orelse {
        try stderr.interface.writeAll("shg: no compiled rules found; run shg-config compile\n");
        try stderr.flush();
        std.process.exit(2);
    };

    const files = if (args.paths.len > 0)
        try sources.expandExplicitPaths(io, alloc, environ, args.paths)
    else
        try sources.discover(io, alloc, environ, cache);

    var total: usize = 0;
    var files_with: usize = 0;
    for (files) |path| {
        const bytes = readFile(io, alloc, path) catch continue;
        const cands = try collectCandidates(bytes, path, alloc, cache, args.level);
        if (cands.len == 0) continue;
        files_with += 1;

        // Read-only until Phase 3: list the candidates. Interactive removal and
        // the atomic rewrite are added next.
        for (cands) |c| {
            const shown = if (args.redacted) c.redacted else c.full;
            try stdout.interface.print("{s}:{d}  {s}\n", .{ path, c.start, shown });
        }
        total += cands.len;
    }

    if (total == 0) {
        try stdout.interface.writeAll("No secrets found in history files.\n");
        return;
    }
    const noun = if (total == 1) "entry" else "entries";
    try stdout.interface.print("\n{d} {s} would be removed across {d} file(s).\n", .{ total, noun, files_with });
    try stdout.flush();
    std.process.exit(1);
}

fn collectCandidates(bytes: []const u8, path: []const u8, alloc: std.mem.Allocator, cache: rules.Cache, level: Severity) ![]Candidate {
    const is_fish = std.mem.indexOf(u8, path, "fish_history") != null;

    // Physical lines, 1-based: line L is `lines[L-1]`.
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |l| try lines.append(alloc, l);

    var reader = Io.Reader.fixed(bytes);
    var skipped: usize = 0;
    const entries = try history_parse.parseFile(&reader, path, alloc, &skipped);

    var cands: std.ArrayList(Candidate) = .empty;
    var seen_start: std.ArrayList(usize) = .empty;

    for (entries) |e| {
        const findings = try detect.detectEntry(e, alloc, scorer.default_entropy_threshold, cache, false);
        var flagged = false;
        var red: []const u8 = e.command;
        for (findings) |f| {
            if (f.severity == .ignore) continue;
            if (@intFromEnum(f.severity) < @intFromEnum(level)) continue;
            flagged = true;
            red = f.redacted_cmd;
            break;
        }
        if (!flagged) continue;

        // Dedup entries that map to the same physical start line (e.g. two JSON
        // string leaves on one line): the whole line is removed once.
        var dup = false;
        for (seen_start.items) |s| {
            if (s == e.line) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        try seen_start.append(alloc, e.line);

        // Span: one line, or a fish `- cmd:` block plus its indented
        // continuation lines.
        var end = e.line;
        if (is_fish) {
            var pl = e.line + 1;
            while (pl <= lines.items.len and lines.items[pl - 1].len > 0 and lines.items[pl - 1][0] == ' ') : (pl += 1) end = pl;
        }

        try cands.append(alloc, .{
            .start = e.line,
            .end = end,
            .full = try singleLine(alloc, e.command),
            .redacted = try singleLine(alloc, red),
        });
    }

    return cands.toOwnedSlice(alloc);
}

// Collapse a command to one line for display (embedded newlines/tabs → spaces).
fn singleLine(alloc: std.mem.Allocator, text: []const u8) ![]const u8 {
    const out = try alloc.alloc(u8, text.len);
    for (text, 0..) |c, i| out[i] = if (c == '\n' or c == '\r' or c == '\t') ' ' else c;
    return out;
}

fn readFile(io: Io, alloc: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return try reader.interface.readAlloc(alloc, @intCast(stat.size));
}

fn loadRules(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?rules.Cache {
    const path = (try config.compiledFile(alloc, environ)) orelse return null;
    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    const bytes = try reader.interface.readAlloc(alloc, @intCast(stat.size));
    return try rules.Cache.init(bytes);
}
