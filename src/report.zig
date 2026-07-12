const std = @import("std");
const Io = std.Io;
const Finding = @import("finding.zig").Finding;
const Severity = @import("finding.zig").Severity;

pub const Options = struct {
    level: Severity = .low,
    redacted: bool = true,
    color: bool = false,
    json: bool = false,
    summary: bool = false,
    one_line: bool = false,
};

pub fn printFinding(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    if (opts.summary) return;
    if (@intFromEnum(f.severity) < @intFromEnum(opts.level)) return;
    if (f.severity == .ignore) return;
    if (opts.json) try printFindingJson(w, f, opts) else if (opts.one_line) try printFindingOneLine(w, f, opts) else try printHuman(w, f, opts);
}

fn printFindingOneLine(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    const cmd = if (opts.redacted) f.redacted_cmd else f.entry.command;
    const ms = if (opts.redacted) f.redacted_match_start else f.full_match_start;
    const ml = if (opts.redacted) f.redacted_match_len else f.full_match_len;
    const source = if (std.mem.eql(u8, f.entry.file, "<env>")) "ENV   " else if (std.mem.eql(u8, f.entry.file, "<stdin>")) "STDIN" else "HIST  ";
    if (opts.color) {
        try w.interface.print("{s}{s}{s} {s} ", .{
            severityStyle(f.severity), severityBadge(f.severity), ansi_reset, source,
        });
    } else {
        try w.interface.print("{s} {s} ", .{ severityBadge(f.severity), source });
    }
    try printCommandWriter(&w.interface, cmd, ms, ml, opts.color);
    try w.interface.writeByte('\n');
}

fn printFindingJson(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    const cmd = if (opts.redacted) f.redacted_cmd else f.entry.command;
    const record = .{
        .severity = f.severity.name(),
        .file = f.entry.file,
        .line = f.entry.line,
        .timestamp = f.entry.timestamp,
        .det_type = f.det_type,
        .command = cmd,
        .score = f.score,
        .recommendation = f.recommendation,
    };
    try std.json.Stringify.value(record, .{}, &w.interface);
    try w.interface.writeByte('\n');
}

fn printHuman(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    const cmd = if (opts.redacted) f.redacted_cmd else f.entry.command;
    const ms = if (opts.redacted) f.redacted_match_start else f.full_match_start;
    const ml = if (opts.redacted) f.redacted_match_len else f.full_match_len;
    try printSeverity(w, f.severity, opts.color);
    try w.interface.writeAll(" ");
    try printCommand(w, cmd, ms, ml, opts.color);
    try w.interface.writeByte('\n');
    try w.interface.print("      {s}:{d} [{s}]\n", .{ f.entry.file, f.entry.line, f.det_type });
    try w.interface.print("      {s}\n", .{f.recommendation});
    try w.interface.writeByte('\n');
}

fn severityBadge(severity: Severity) []const u8 {
    return switch (severity) {
        .high => "[!!!]",
        .medium => "[!! ]",
        .low => "[!  ]",
        .ignore => "[   ]",
    };
}

fn printSeverity(w: *Io.File.Writer, severity: Severity, color: bool) !void {
    if (!color) {
        try w.interface.writeAll(severityBadge(severity));
        return;
    }
    try w.interface.print("{s}{s}{s}", .{ severityStyle(severity), severityBadge(severity), ansi_reset });
}

// Commands longer than this are printed as a window around the match so the
// secret is visible instead of buried behind kilobytes of leading text
// (common in JSONL agent logs).
const max_full_command = 160;
const window_context = 60;

const Window = struct {
    text: []const u8,
    lead: bool,
    trail: bool,
};

fn windowCommand(cmd: []const u8, match_start: usize, match_len: usize) Window {
    if (cmd.len <= max_full_command) return .{ .text = cmd, .lead = false, .trail = false };
    const ms = @min(match_start, cmd.len);
    const start = if (ms > window_context) ms - window_context else 0;
    const end = @min(ms + match_len + window_context, cmd.len);
    return .{ .text = cmd[start..end], .lead = start > 0, .trail = end < cmd.len };
}

fn printCommand(w: *Io.File.Writer, cmd: []const u8, match_start: usize, match_len: usize, color: bool) !void {
    try printCommandWriter(&w.interface, cmd, match_start, match_len, color);
}

fn printCommandWriter(w: anytype, cmd: []const u8, match_start: usize, match_len: usize, color: bool) !void {
    const win = windowCommand(cmd, match_start, match_len);
    if (win.lead) try w.writeAll("…");
    if (color) {
        try w.print("{s}{s}{s}", .{ ansi_bold, win.text, ansi_reset });
    } else {
        try w.writeAll(win.text);
    }
    if (win.trail) try w.writeAll("…");
}

const ansi_reset = "\x1b[0m";
const ansi_bold = "\x1b[1m";
const ansi_bold_red = "\x1b[1;31m";
const ansi_bold_yellow = "\x1b[1;33m";
const ansi_bold_blue = "\x1b[1;34m";

fn severityStyle(severity: Severity) []const u8 {
    return switch (severity) {
        .high => ansi_bold_red,
        .medium => ansi_bold_yellow,
        .low => ansi_bold_blue,
        .ignore => ansi_bold,
    };
}

pub fn printSummary(w: *Io.File.Writer, counts: [4]usize) !void {
    const total = counts[1] + counts[2] + counts[3];
    if (total == 0) {
        try w.interface.writeAll("No findings detected.\n");
        return;
    }
    try w.interface.print("{d} finding(s) detected ({d} high, {d} medium, {d} low).\n", .{
        total, counts[3], counts[2], counts[1],
    });
    try w.interface.writeAll("Remove flagged history entries and rotate affected credentials.\n");
}

test "colored report bolds full command" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    const cmd = "export TOKEN=ghp...et";
    try printCommandWriter(&out.writer, cmd, 0, cmd.len, true);
    try std.testing.expectEqualStrings("\x1b[1mexport TOKEN=ghp...et\x1b[0m", out.written());
}

test "long command is windowed around the match" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    // 200 chars of prefix, then the match, then 200 chars of suffix.
    const prefix = "x" ** 200;
    const match = "sk-SECRET";
    const suffix = "y" ** 200;
    const cmd = prefix ++ match ++ suffix;
    try printCommandWriter(&out.writer, cmd, prefix.len, match.len, false);

    const written = out.written();
    try std.testing.expect(std.mem.indexOf(u8, written, match) != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "…") != null);
    try std.testing.expect(written.len < cmd.len);
}
