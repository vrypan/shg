const std = @import("std");
const Severity = @import("finding.zig").Severity;

pub const Subcommand = enum { scan, patterns, help };

pub const Args = struct {
    subcommand: Subcommand = .scan,
    paths: []const []const u8 = &.{},
    json: bool = false,
    min_severity: Severity = .low,
    entropy_threshold: f64 = 3.5,
    show_full: bool = false,
};

/// raw[0] is the binary name and is skipped.
pub fn parse(raw: []const [:0]const u8, alloc: std.mem.Allocator) !Args {
    var result = Args{};
    var paths: std.ArrayList([]const u8) = .empty;
    var subcommand_set = false;
    var i: usize = 1;

    while (i < raw.len) : (i += 1) {
        const arg = raw[i];

        if (!subcommand_set and !std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "scan")) {
                result.subcommand = .scan;
            } else if (std.mem.eql(u8, arg, "patterns")) {
                result.subcommand = .patterns;
            } else if (std.mem.eql(u8, arg, "help")) {
                result.subcommand = .help;
            }
            subcommand_set = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            result.subcommand = .help;
        } else if (std.mem.eql(u8, arg, "--json")) {
            result.json = true;
        } else if (std.mem.eql(u8, arg, "--show-full")) {
            result.show_full = true;
        } else if (std.mem.eql(u8, arg, "--path")) {
            i += 1;
            if (i >= raw.len) return error.MissingArgument;
            try paths.append(alloc, try alloc.dupe(u8, raw[i]));
        } else if (std.mem.startsWith(u8, arg, "--path=")) {
            try paths.append(alloc, try alloc.dupe(u8, arg[7..]));
        } else if (std.mem.eql(u8, arg, "--min-severity")) {
            i += 1;
            if (i >= raw.len) return error.MissingArgument;
            result.min_severity = parseSeverity(raw[i]) orelse return error.InvalidSeverity;
        } else if (std.mem.eql(u8, arg, "--entropy-threshold")) {
            i += 1;
            if (i >= raw.len) return error.MissingArgument;
            result.entropy_threshold = std.fmt.parseFloat(f64, raw[i]) catch return error.InvalidFloat;
        }
    }

    result.paths = try paths.toOwnedSlice(alloc);
    return result;
}

fn parseSeverity(s: []const u8) ?Severity {
    if (std.mem.eql(u8, s, "low")) return .low;
    if (std.mem.eql(u8, s, "medium")) return .medium;
    if (std.mem.eql(u8, s, "high")) return .high;
    return null;
}
