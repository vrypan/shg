const std = @import("std");
const Io = std.Io;
const Finding = @import("finding.zig").Finding;
const Severity = @import("finding.zig").Severity;

pub const Options = struct {
    json: bool = false,
    min_severity: Severity = .low,
    show_full: bool = false,
};

pub fn printFinding(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    if (@intFromEnum(f.severity) < @intFromEnum(opts.min_severity)) return;
    if (f.severity == .ignore) return;
    if (opts.json) try printJson(w, f) else try printHuman(w, f);
}

fn printHuman(w: *Io.File.Writer, f: Finding) !void {
    try w.interface.print("[{s}] {s}:{d}\n", .{ f.severity.tag(), f.entry.file, f.entry.line });
    try w.interface.print("  type:    {s}\n", .{f.det_type});
    try w.interface.print("  command: {s}\n", .{f.redacted_cmd});
    if (f.recommendation.len > 0)
        try w.interface.print("  action:  {s}\n", .{f.recommendation});
    try w.interface.writeByte('\n');
}

fn printJson(w: *Io.File.Writer, f: Finding) !void {
    try w.interface.writeAll("{\"file\":");
    try writeJsonStr(w, f.entry.file);
    try w.interface.print(",\"line\":{d},\"severity\":", .{f.entry.line});
    try writeJsonStr(w, f.severity.name());
    try w.interface.writeAll(",\"type\":");
    try writeJsonStr(w, f.det_type);
    try w.interface.writeAll(",\"redacted\":");
    try writeJsonStr(w, f.redacted_cmd);
    try w.interface.print(",\"score\":{d}}}\n", .{f.score});
}

fn writeJsonStr(w: *Io.File.Writer, s: []const u8) !void {
    try w.interface.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.interface.writeAll("\\\""),
        '\\' => try w.interface.writeAll("\\\\"),
        '\n' => try w.interface.writeAll("\\n"),
        '\r' => try w.interface.writeAll("\\r"),
        '\t' => try w.interface.writeAll("\\t"),
        else => try w.interface.writeByte(c),
    };
    try w.interface.writeByte('"');
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
    try w.interface.writeAll("Run `histguard fix` to remove flagged entries.\n");
}
