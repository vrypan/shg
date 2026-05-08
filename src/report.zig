const std = @import("std");
const Io = std.Io;
const Finding = @import("finding.zig").Finding;
const Severity = @import("finding.zig").Severity;

pub const Options = struct {
    level: Severity = .low,
    redacted: bool = true,
    color: bool = false,
};

pub fn printFinding(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    if (@intFromEnum(f.severity) < @intFromEnum(opts.level)) return;
    if (f.severity == .ignore) return;
    try printHuman(w, f, opts);
}

fn printHuman(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    const cmd = if (opts.redacted) f.redacted_cmd else f.entry.command;
    try printSeverity(w, f.severity, opts.color);
    try w.interface.writeAll(" ");
    try printCommand(w, cmd, opts.color);
    try w.interface.writeByte('\n');
    try w.interface.print("      {s}:{d} [{s}]\n", .{ f.entry.file, f.entry.line, f.det_type });
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

fn printCommand(w: *Io.File.Writer, cmd: []const u8, color: bool) !void {
    try printCommandWriter(&w.interface, cmd, color);
}

fn printCommandWriter(w: anytype, cmd: []const u8, color: bool) !void {
    if (!color) {
        try w.writeAll(cmd);
        return;
    }
    try w.print("{s}{s}{s}", .{ ansi_bold, cmd, ansi_reset });
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

    try printCommandWriter(&out.writer, "export TOKEN=ghp...et", true);
    try std.testing.expectEqualStrings("\x1b[1mexport TOKEN=ghp...et\x1b[0m", out.written());
}
