const std = @import("std");
const zecli = @import("cli");
const Severity = @import("finding.zig").Severity;
const build_options = @import("build_options");

pub const version = build_options.version;

pub const Subcommand = enum { scan, patterns, help, version };

pub const Args = struct {
    subcommand: Subcommand,
    paths: []const []const u8,
    scan_env: bool,
    scan_hist: bool,
    min_severity: Severity,
    entropy_threshold: f64,
    show_full: bool,
};

const commands = [_]zecli.CommandEntry{
    .{ .name = "scan",     .description = "Scan history files for secrets (default)" },
    .{ .name = "patterns", .description = "List all detection patterns and examples" },
    .{ .name = "version",  .description = "Print version"                            },
};

const scan_flags = [_]zecli.FlagSpec{
    .{ .name = "path",               .short = 'p', .value = .string, .value_name = "FILE",  .description = "History file to scan",  .repeatable = true },
    .{ .name = "env",                              .value = .bool_optional,                  .description = "Scan environment variables", .default_value = "true" },
    .{ .name = "hist",                             .value = .bool_optional,                  .description = "Scan history files",          .default_value = "true" },
    .{ .name = "min-severity",                     .value = .string, .value_name = "LEVEL", .description = "low|medium|high",       .default_value = "low" },
    .{ .name = "entropy-threshold",                .value = .string, .value_name = "N",     .description = "Shannon entropy cutoff", .default_value = "3.5" },
    .{ .name = "show-full",                                                                  .description = "Disable redaction"                          },
};

const scan_spec = zecli.CommandSpec{
    .name        = "scan",
    .description = "Scan shell history files for accidentally persisted secrets.",
    .usage       = "shg scan [options]",
    .flags       = &scan_flags,
};

const patterns_spec = zecli.CommandSpec{
    .name        = "patterns",
    .description = "List all detection categories with examples.",
    .usage       = "shg patterns",
};

const root_spec = zecli.CommandSpec{
    .name        = "shg",
    .description = "Scan shell history files for accidentally persisted secrets.",
    .usage       = "shg <command> [options]",
    .extra_help  =
        \\
        \\Run 'shg <command> --help' for command-specific options.
        \\
    ,
};

/// Parse raw process args (raw[0] is the binary name).
/// `writer` receives error and help output; must support .print() and .writeAll().
pub fn parse(raw: []const [:0]const u8, writer: anytype, alloc: std.mem.Allocator) !Args {
    var subcmd: Subcommand = .scan;
    var subcmd_args: []const [:0]const u8 = if (raw.len > 1) raw[1..] else &.{};

    if (raw.len > 1) {
        const first = raw[1];
        if (std.mem.eql(u8, first, "scan")) {
            subcmd = .scan;
            subcmd_args = if (raw.len > 2) raw[2..] else &.{};
        } else if (std.mem.eql(u8, first, "patterns")) {
            subcmd = .patterns;
            subcmd_args = if (raw.len > 2) raw[2..] else &.{};
        } else if (std.mem.eql(u8, first, "version")) {
            subcmd = .version;
            subcmd_args = &.{};
        } else if (std.mem.eql(u8, first, "help") or
                   std.mem.eql(u8, first, "--help") or
                   std.mem.eql(u8, first, "-h"))
        {
            subcmd = .help;
            subcmd_args = &.{};
        }
        // else: flags with no subcommand → scan
    }

    switch (subcmd) {
        .version => {
            try writer.print("{s}\n", .{build_options.version});
            return defaultArgs(.version);
        },
        .help => {
            try zecli.printCommandHelp(alloc, writer, root_spec);
            try zecli.printCommandList(writer, &commands);
            return defaultArgs(.help);
        },
        .patterns => {
            if (zecli.helpRequested(subcmd_args)) {
                try zecli.printCommandHelp(alloc, writer, patterns_spec);
            } else {
                _ = try zecli.parseCommand(alloc, writer, subcmd_args, patterns_spec);
            }
            return defaultArgs(.patterns);
        },
        .scan => {
            if (zecli.helpRequested(subcmd_args)) {
                try zecli.printCommandHelp(alloc, writer, scan_spec);
                return defaultArgs(.help);
            }
            const parsed = try zecli.parseCommand(alloc, writer, subcmd_args, scan_spec);

            var paths: std.ArrayList([]const u8) = .empty;
            for (parsed.flags.items) |flag| {
                if (std.mem.eql(u8, flag.name, "path")) {
                    if (flag.value) |v| try paths.append(alloc, v);
                }
            }

            const sev_str = parsed.last("min-severity") orelse "low";
            const min_sev = parseSeverity(sev_str) orelse {
                try writer.print("error: invalid --min-severity value '{s}' (use low, medium, or high)\n", .{sev_str});
                return error.ReportedCliError;
            };

            const thr_str = parsed.last("entropy-threshold") orelse "3.5";
            const entropy_threshold = std.fmt.parseFloat(f64, thr_str) catch {
                try writer.print("error: invalid --entropy-threshold value '{s}'\n", .{thr_str});
                return error.ReportedCliError;
            };

            return Args{
                .subcommand = .scan,
                .paths = try paths.toOwnedSlice(alloc),
                .scan_env = zecli.parseBool(parsed.last("env") orelse "true") catch unreachable,
                .scan_hist = zecli.parseBool(parsed.last("hist") orelse "true") catch unreachable,
                .min_severity = min_sev,
                .entropy_threshold = entropy_threshold,
                .show_full = parsed.present("show-full"),
            };
        },
    }
}

fn parseSeverity(s: []const u8) ?Severity {
    if (std.mem.eql(u8, s, "low")) return .low;
    if (std.mem.eql(u8, s, "medium")) return .medium;
    if (std.mem.eql(u8, s, "high")) return .high;
    return null;
}

fn defaultArgs(subcommand: Subcommand) Args {
    return .{
        .subcommand = subcommand,
        .paths = &.{},
        .scan_env = true,
        .scan_hist = true,
        .min_severity = .low,
        .entropy_threshold = 3.5,
        .show_full = false,
    };
}

const TestWriter = struct {
    pub fn print(_: *TestWriter, comptime _: []const u8, _: anytype) !void {}
    pub fn writeAll(_: *TestWriter, _: []const u8) !void {}
};

test "scan parses show full" {
    const alloc = std.testing.allocator;
    var writer = TestWriter{};
    const raw = [_][:0]const u8{ "shg", "scan", "--show-full" };
    const args = try parse(&raw, &writer, alloc);
    try std.testing.expect(args.show_full);
}

test "scan source flags default to enabled" {
    const alloc = std.testing.allocator;
    var writer = TestWriter{};
    const raw = [_][:0]const u8{ "shg", "scan" };
    const args = try parse(&raw, &writer, alloc);
    try std.testing.expect(args.scan_env);
    try std.testing.expect(args.scan_hist);
}

test "scan source flags can be disabled" {
    const alloc = std.testing.allocator;
    var writer = TestWriter{};
    const raw = [_][:0]const u8{ "shg", "scan", "--env", "false", "--hist=false" };
    const args = try parse(&raw, &writer, alloc);
    try std.testing.expect(!args.scan_env);
    try std.testing.expect(!args.scan_hist);
}
