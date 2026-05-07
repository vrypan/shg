const std = @import("std");
const Io = std.Io;
const Finding = @import("finding.zig").Finding;
const Severity = @import("finding.zig").Severity;

pub const Options = struct {
    min_severity: Severity = .low,
    show_full: bool = false,
};

pub fn printFinding(w: *Io.File.Writer, f: Finding, opts: Options) !void {
    if (@intFromEnum(f.severity) < @intFromEnum(opts.min_severity)) return;
    if (f.severity == .ignore) return;
    try printHuman(w, f, opts.show_full);
}

fn printHuman(w: *Io.File.Writer, f: Finding, show_full: bool) !void {
    const cmd = if (show_full) f.entry.command else f.redacted_cmd;
    try w.interface.print("[{s}] {s}:{d}\n", .{ f.severity.tag(), f.entry.file, f.entry.line });
    try w.interface.print("  type:    {s}\n", .{f.det_type});
    try w.interface.print("  command: {s}\n", .{cmd});
    if (f.recommendation.len > 0)
        try w.interface.print("  action:  {s}\n", .{f.recommendation});
    try w.interface.writeByte('\n');
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
