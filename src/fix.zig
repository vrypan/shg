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

    const is_tty = Io.File.stdout().isTty(io) catch false;
    var stdin_buf: [256]u8 = undefined;
    var stdin_reader = Io.File.stdin().readerStreaming(io, &stdin_buf);

    var any_candidate = false;
    var total: usize = 0;
    var files_with: usize = 0;

    for (files) |path| {
        const bytes = readFile(io, alloc, path) catch continue;
        const cands = try collectCandidates(bytes, path, alloc, cache, args.level);
        if (cands.len == 0) continue;
        any_candidate = true;
        files_with += 1;
        total += cands.len;

        if (args.dry_run) {
            for (cands) |c| {
                const shown = if (args.redacted) c.redacted else c.full;
                try stdout.interface.print("{s}:{d}  {s}\n", .{ path, c.start, shown });
            }
            continue;
        }

        // Decide per candidate (prompt, or confirm all with --yes), collect the
        // confirmed line spans, then rewrite the file once.
        var spans: std.ArrayList([2]usize) = .empty;
        for (cands) |c| {
            const confirm = if (args.yes)
                true
            else
                try promptRemove(alloc, &stdout, &stdin_reader.interface, path, c, args.redacted, is_tty);
            if (confirm) try spans.append(alloc, .{ c.start, c.end });
        }
        if (spans.items.len == 0) continue;
        try rewriteFile(io, alloc, path, bytes, spans.items);
        const noun = if (spans.items.len == 1) "entry" else "entries";
        try stdout.interface.print("Removed {d} {s} from {s}.\n", .{ spans.items.len, noun, path });
    }

    if (!any_candidate) {
        try stdout.interface.writeAll("No secrets found in history files.\n");
        return;
    }
    if (args.dry_run) {
        const noun = if (total == 1) "entry" else "entries";
        try stdout.interface.print("\n{d} {s} would be removed across {d} file(s).\n", .{ total, noun, files_with });
    }
    try stdout.flush();
    std.process.exit(1);
}

// Show a candidate and ask whether to remove it. After the answer, on a TTY and
// when the value was shown in full, redraw the entry line in place with the
// secret redacted so scrollback never accumulates full secrets.
fn promptRemove(alloc: std.mem.Allocator, stdout: *Io.File.Writer, stdin: *Io.Reader, path: []const u8, c: Candidate, redacted: bool, is_tty: bool) !bool {
    const w = &stdout.interface;
    const shown = if (redacted) c.redacted else c.full;
    try w.print("{s}:{d}  {s}\n", .{ path, c.start, shown });
    try w.writeAll("Remove this entry? [y/N] ");
    try stdout.flush();

    const line = (stdin.takeDelimiter('\n') catch return false) orelse return false;
    const ans = std.mem.trim(u8, line, " \t\r\n");
    const yes = std.ascii.eqlIgnoreCase(ans, "y") or std.ascii.eqlIgnoreCase(ans, "yes");

    if (is_tty and !redacted) {
        // Cursor is one row below the prompt: up 2 to the entry row, clear it,
        // reprint the masked entry + outcome, back down 2.
        const masked = try redrawText(alloc, path, c.start, c.redacted, yes);
        try w.print("\x1b[2A\r\x1b[2K{s}\x1b[2B\r", .{masked});
        try stdout.flush();
    }
    return yes;
}

// The line reprinted in place of a decided entry: the redacted command and the
// outcome, never the full secret.
fn redrawText(alloc: std.mem.Allocator, path: []const u8, start: usize, redacted: []const u8, yes: bool) ![]const u8 {
    const tag = if (yes) "\u{2192} removed" else "\u{2192} kept";
    return std.fmt.allocPrint(alloc, "{s}:{d}  {s}  {s}", .{ path, start, redacted, tag });
}

// The last physical line (1-based, inclusive) of a fish entry starting at
// `start`: the `- cmd:` line plus following indented continuation lines.
fn fishSpanEnd(lines: []const []const u8, start: usize) usize {
    var end = start;
    var pl = start + 1;
    while (pl <= lines.len and lines[pl - 1].len > 0 and lines[pl - 1][0] == ' ') : (pl += 1) end = pl;
    return end;
}

// Rewrite `path` with the given 1-based inclusive line spans removed, via an
// atomic temp-file + rename. No backup is made (it would replicate the secret);
// the temp file is deleted on any error before the rename completes.
fn rewriteFile(io: Io, alloc: std.mem.Allocator, path: []const u8, bytes: []const u8, spans: []const [2]usize) !void {
    const content = try removeLines(alloc, bytes, spans);

    // Temp file in the same directory as the target so the rename is an atomic
    // same-filesystem move. Create it exclusively so concurrent runs do not
    // truncate each other's temp files.
    const stamp = timestampNanos();
    var attempt: usize = 0;
    while (attempt < 100) : (attempt += 1) {
        const tmp = try std.fmt.allocPrint(alloc, "{s}.shg-tmp.{d}.{d}", .{ path, stamp, attempt });
        const f = Io.Dir.createFileAbsolute(io, tmp, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        var close_file = true;
        errdefer if (close_file) f.close(io);
        errdefer Io.Dir.deleteFileAbsolute(io, tmp) catch {};
        var wbuf: [8192]u8 = undefined;
        var writer = f.writerStreaming(io, &wbuf);
        try writer.interface.writeAll(content);
        try writer.flush();
        f.close(io);
        close_file = false;
        try Io.Dir.renameAbsolute(tmp, path, io);
        return;
    }
    return error.PathAlreadyExists;
}

fn timestampNanos() u128 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) == 0) {
        return @as(u128, @intCast(ts.sec)) * std.time.ns_per_s + @as(u128, @intCast(ts.nsec));
    }
    return @as(u128, @intCast(std.c.getpid()));
}

// Rebuild file bytes with the given 1-based inclusive line spans removed,
// preserving the original trailing-newline shape.
fn removeLines(alloc: std.mem.Allocator, bytes: []const u8, spans: []const [2]usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    var line: usize = 0;
    var first = true;
    while (it.next()) |seg| {
        line += 1;
        if (inSpan(line, spans)) continue;
        if (!first) try out.append(alloc, '\n');
        try out.appendSlice(alloc, seg);
        first = false;
    }
    return out.toOwnedSlice(alloc);
}

fn inSpan(line: usize, spans: []const [2]usize) bool {
    for (spans) |s| {
        if (line >= s[0] and line <= s[1]) return true;
    }
    return false;
}

test "removeLines removes a middle line and preserves the trailing newline" {
    const alloc = std.testing.allocator;
    const out = try removeLines(alloc, "a\nb\nc\n", &.{.{ 2, 2 }});
    defer alloc.free(out);
    try std.testing.expectEqualStrings("a\nc\n", out);
}

test "removeLines without a trailing newline" {
    const alloc = std.testing.allocator;
    const out = try removeLines(alloc, "a\nb\nc", &.{.{ 2, 2 }});
    defer alloc.free(out);
    try std.testing.expectEqualStrings("a\nc", out);
}

test "removeLines removes a multi-line span" {
    const alloc = std.testing.allocator;
    // Remove lines 3-4 (a fish block), keep 1-2 and 5-6.
    const out = try removeLines(alloc, "- cmd: a\n  when: 1\n- cmd: b\n  when: 2\n- cmd: c\n  when: 3\n", &.{.{ 3, 4 }});
    defer alloc.free(out);
    try std.testing.expectEqualStrings("- cmd: a\n  when: 1\n- cmd: c\n  when: 3\n", out);
}

test "fishSpanEnd covers the cmd line plus indented continuations" {
    const lines = [_][]const u8{ "- cmd: x", "  when: 1", "- cmd: y", "  when: 2" };
    try std.testing.expectEqual(@as(usize, 2), fishSpanEnd(&lines, 1));
    try std.testing.expectEqual(@as(usize, 4), fishSpanEnd(&lines, 3));
}

test "fishSpanEnd is the start line when there is no continuation" {
    const lines = [_][]const u8{ "- cmd: x", "- cmd: y" };
    try std.testing.expectEqual(@as(usize, 1), fishSpanEnd(&lines, 1));
}

test "singleLine collapses control characters to spaces" {
    const alloc = std.testing.allocator;
    const out = try singleLine(alloc, "a\nb\tc\rd");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("a b c d", out);
}

test "redrawText masks the entry and tags the outcome" {
    const alloc = std.testing.allocator;
    const removed = try redrawText(alloc, "/h", 2, "echo ghp_****", true);
    defer alloc.free(removed);
    try std.testing.expectEqualStrings("/h:2  echo ghp_****  \u{2192} removed", removed);
    const kept = try redrawText(alloc, "/h", 5, "x", false);
    defer alloc.free(kept);
    try std.testing.expect(std.mem.endsWith(u8, kept, "\u{2192} kept"));
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
        const end = if (is_fish) fishSpanEnd(lines.items, e.line) else e.line;

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
