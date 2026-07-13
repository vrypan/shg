const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const config = @import("config.zig");
const rules = @import("rules.zig");
const sources = @import("sources.zig");
const detect = @import("detect.zig");
const hints = @import("hints.zig");
const redact = @import("redact.zig");
const scorer = @import("scorer.zig");
const formats = @import("agent_formats.zig");

const Entry = @import("entry.zig").Entry;
const Severity = @import("finding.zig").Severity;
const Source = formats.Source;

// One distinct secret within a session file, with how often it appears and a
// redacted context snippet from its first occurrence.
const Agg = struct {
    redacted_token: []const u8,
    det_type: []const u8,
    severity: Severity,
    count: usize,
    source: Source,
    context: []const u8,
};

const FileResult = struct {
    path: []const u8,
    aggs: []Agg,
};

const ScanOutcome = struct {
    result: ?FileResult,
    malformed: usize,
};

const MalformedWarning = struct {
    path: []const u8,
    count: usize,
    unit: []const u8,
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
        try stderr.interface.writeAll("shg: no compiled rules found; run shg-config init\n");
        try stderr.flush();
        std.process.exit(2);
    };
    const detector_context = try detect.Context.init(alloc);

    // Discovery is bounded: explicit --path arguments, or the compiled
    // deep_path rules (paths.deep.*.shg). Never a disk crawl.
    const discovery = if (args.paths.len > 0)
        try sources.expandExplicitDeepPaths(io, alloc, environ, args.paths)
    else
        try sources.discoverDeep(io, alloc, environ, cache);

    var progress = try DeepProgress.init(io, alloc, &stderr, discovery, environ, !args.json);

    var results: std.ArrayList(FileResult) = .empty;
    var malformed_warnings: std.ArrayList(MalformedWarning) = .empty;
    var file_count: usize = 0;
    var malformed_total: usize = 0;
    for (discovery.files) |item| {
        try progress.startFile(item.root_index, item.path);
        const outcome = try scanFile(io, alloc, item.path, args, cache, &detector_context);
        const flag_count = if (outcome.result) |res| res.aggs.len else 0;
        try progress.finishFile(item.root_index, flag_count);
        if (outcome.malformed > 0) {
            malformed_total += outcome.malformed;
            try malformed_warnings.append(alloc, .{
                .path = item.path,
                .count = outcome.malformed,
                .unit = formats.malformedUnit(formats.formatForPath(item.path)),
            });
        }
        if (outcome.result) |res| {
            try results.append(alloc, res);
            file_count += 1;
        }
    }
    try progress.complete();

    for (malformed_warnings.items) |warning| {
        try stderr.interface.print("shg: warning: {s}: skipped {d} malformed {s}\n", .{ warning.path, warning.count, warning.unit });
    }
    try stderr.flush();

    const color = !args.json and try colorEnabled(io, environ);

    var total_secrets: usize = 0;
    for (results.items) |r| total_secrets += r.aggs.len;

    if (args.json) {
        try reportJson(&stdout, results.items);
    } else {
        try reportHuman(&stdout, results.items, total_secrets, file_count, color);
    }
    try stdout.flush();
    try stderr.flush();

    if (malformed_total > 0) std.process.exit(2);
    if (total_secrets > 0) std.process.exit(1);
}

const DeepProgress = struct {
    const PathState = struct {
        label: []const u8,
        total: usize = 0,
        scanned: usize = 0,
        flags: usize = 0,
        current: ?[]const u8 = null,
    };

    const spinner = [_][]const u8{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
    const root_width = 24;
    const file_width = 44;

    enabled: bool,
    writer: *Io.File.Writer,
    roots: []const []const u8,
    states: []PathState,
    frame: usize = 0,
    rendered: bool = false,

    fn init(io: Io, alloc: std.mem.Allocator, writer: *Io.File.Writer, discovery: sources.DeepDiscovery, environ: *const std.process.Environ.Map, requested: bool) !DeepProgress {
        var enabled = requested and discovery.roots.len > 0 and
            (Io.File.stderr().isTty(io) catch false) and
            (Io.File.stdout().isTty(io) catch false);
        if (enabled) Io.File.stderr().enableAnsiEscapeCodes(io) catch {
            enabled = false;
        };

        const states = try alloc.alloc(PathState, discovery.roots.len);
        const home = environ.get("HOME") orelse environ.get("USERPROFILE");
        for (states, discovery.roots) |*state, root| {
            state.* = .{ .label = try compactHomePath(alloc, root, home) };
        }
        for (discovery.files) |file| states[file.root_index].total += 1;

        return .{
            .enabled = enabled,
            .writer = writer,
            .roots = discovery.roots,
            .states = states,
        };
    }

    fn startFile(self: *DeepProgress, root_index: usize, path: []const u8) !void {
        if (!self.enabled) return;
        self.states[root_index].current = relativePath(self.roots[root_index], path);
        self.frame = (self.frame + 1) % spinner.len;
        try self.render();
    }

    fn finishFile(self: *DeepProgress, root_index: usize, flag_count: usize) !void {
        if (!self.enabled) return;
        const state = &self.states[root_index];
        state.scanned += 1;
        state.flags += flag_count;
        if (state.scanned == state.total) {
            state.current = null;
            try self.render();
        }
    }

    fn complete(self: *DeepProgress) !void {
        if (!self.enabled) return;
        var changed = !self.rendered;
        for (self.states) |*state| {
            if (state.scanned != state.total or state.current != null) changed = true;
            state.scanned = state.total;
            state.current = null;
        }
        if (changed) try self.render();
    }

    fn render(self: *DeepProgress) !void {
        const w = &self.writer.interface;
        if (self.rendered) try w.print("\x1b[{d}A", .{self.states.len});

        for (self.states) |state| {
            try w.writeAll("\r\x1b[2K");
            if (state.scanned == state.total) {
                try w.writeAll("✓ ");
            } else if (state.current != null) {
                try w.print("{s} ", .{spinner[self.frame]});
            } else {
                try w.writeAll("· ");
            }

            const root_len = try writeMiddleTruncated(w, state.label, root_width);
            try writePadding(w, root_width - root_len + 1);
            if (state.scanned == state.total) {
                try w.print("{d} file{s}  {d} flag{s}", .{
                    state.total,
                    if (state.total == 1) "" else "s",
                    state.flags,
                    if (state.flags == 1) "" else "s",
                });
            } else if (state.current) |current| {
                try writeTailTruncated(w, current, file_width);
            }
            try w.writeByte('\n');
        }
        try self.writer.flush();
        self.rendered = true;
    }
};

fn compactHomePath(alloc: std.mem.Allocator, path: []const u8, home: ?[]const u8) ![]const u8 {
    if (home) |h| {
        if (std.mem.eql(u8, path, h)) return try alloc.dupe(u8, "~");
        if (path.len > h.len and std.mem.startsWith(u8, path, h) and std.fs.path.isSep(path[h.len])) {
            return try std.fmt.allocPrint(alloc, "~{s}", .{path[h.len..]});
        }
    }
    return try alloc.dupe(u8, path);
}

fn relativePath(root: []const u8, path: []const u8) []const u8 {
    if (std.mem.eql(u8, root, path)) return std.fs.path.basename(path);
    if (path.len > root.len and std.mem.startsWith(u8, path, root) and std.fs.path.isSep(path[root.len])) {
        return path[root.len + 1 ..];
    }
    return path;
}

fn writeMiddleTruncated(writer: *Io.Writer, text: []const u8, max: usize) !usize {
    if (text.len <= max) {
        try writer.writeAll(text);
        return text.len;
    }
    const left = (max - 3) / 2;
    const right = max - 3 - left;
    try writer.writeAll(text[0..left]);
    try writer.writeAll("...");
    try writer.writeAll(text[text.len - right ..]);
    return max;
}

fn writeTailTruncated(writer: *Io.Writer, text: []const u8, max: usize) !void {
    if (text.len <= max) return writer.writeAll(text);
    try writer.writeAll("...");
    try writer.writeAll(text[text.len - (max - 3) ..]);
}

fn writePadding(writer: *Io.Writer, count: usize) !void {
    var remaining = count;
    const spaces = " " ** 32;
    while (remaining > 0) {
        const n = @min(remaining, spaces.len);
        try writer.writeAll(spaces[0..n]);
        remaining -= n;
    }
}

fn scanFile(io: Io, alloc: std.mem.Allocator, path: []const u8, args: cli.Args, cache: rules.Cache, detector_context: *const detect.Context) !ScanOutcome {
    const bytes = try readFile(io, alloc, path);
    const format = formats.formatForPath(path);
    var malformed: usize = 0;
    const pieces = try formats.extractCounting(format, bytes, alloc, &malformed);

    var map = std.StringHashMap(Agg).init(alloc);

    for (pieces) |piece| {
        if (!scanned(piece.source, args.all_content)) continue;
        const entry = Entry{
            .file = path,
            .line = piece.line,
            .timestamp = null,
            .raw = piece.text,
            .command = piece.text,
        };
        const findings = try detect.detectEntryIndexed(entry, alloc, args.entropy_threshold, cache, true, detector_context);
        for (findings) |f| {
            if (f.severity == .ignore) continue;
            if (@intFromEnum(f.severity) < @intFromEnum(args.level)) continue;

            const key: []const u8 = if (f.full_match_len > 0)
                piece.text[f.full_match_start..][0..f.full_match_len]
            else
                f.redacted_cmd;

            // Strict by default: transcripts are a haystack of code, so only
            // format-specific / user-defined detectors fire unless
            // --thorough. A known provider prefix remains high-confidence even
            // when a more specific detector labels it inline_assign or
            // auth_header.
            if (!args.thorough and !isHighConfidence(f.det_type) and !hints.hasKnownPrefix(key)) continue;

            const gop = try map.getOrPut(key);
            if (!gop.found_existing) {
                const redacted_token = if (f.full_match_len > 0)
                    try redact.redactToken(key, alloc)
                else
                    try alloc.dupe(u8, "****");
                gop.value_ptr.* = .{
                    .redacted_token = redacted_token,
                    .det_type = f.det_type,
                    .severity = f.severity,
                    .count = 1,
                    .source = piece.source,
                    .context = try windowContext(alloc, f.redacted_cmd, f.redacted_match_start, f.redacted_match_len),
                };
            } else {
                gop.value_ptr.count += 1;
                if (@intFromEnum(f.severity) > @intFromEnum(gop.value_ptr.severity)) {
                    gop.value_ptr.severity = f.severity;
                    gop.value_ptr.det_type = f.det_type;
                }
            }
        }
    }

    if (map.count() == 0) return .{ .result = null, .malformed = malformed };

    var aggs: std.ArrayList(Agg) = .empty;
    var it = map.valueIterator();
    while (it.next()) |v| try aggs.append(alloc, v.*);
    std.mem.sort(Agg, aggs.items, {}, higherSeverityFirst);

    return .{
        .result = .{ .path = path, .aggs = try aggs.toOwnedSlice(alloc) },
        .malformed = malformed,
    };
}

fn higherSeverityFirst(_: void, a: Agg, b: Agg) bool {
    if (a.severity != b.severity) return @intFromEnum(a.severity) > @intFromEnum(b.severity);
    return a.count > b.count;
}

fn scanned(source: Source, all_content: bool) bool {
    return switch (source) {
        .user_input, .tool_call, .tool_output, .stored_context => true,
        .assistant, .reasoning => all_content,
    };
}

// High-confidence detectors: format-specific (known_token, private_key,
// ssh_key) or user-defined (config_check). The loose value/keyword detectors
// are excluded from the strict default because they false-positive on code.
fn isHighConfidence(det_type: []const u8) bool {
    const allow = [_][]const u8{ "known_token", "private_key", "ssh_key", "config_check" };
    for (allow) |a| {
        if (std.mem.eql(u8, det_type, a)) return true;
    }
    return false;
}

test "isHighConfidence allows format-specific and config detectors only" {
    try std.testing.expect(isHighConfidence("known_token"));
    try std.testing.expect(isHighConfidence("private_key"));
    try std.testing.expect(isHighConfidence("ssh_key"));
    try std.testing.expect(isHighConfidence("config_check"));
    try std.testing.expect(!isHighConfidence("inline_assign"));
    try std.testing.expect(!isHighConfidence("auth_header"));
    try std.testing.expect(!isHighConfidence("credential_url"));
    try std.testing.expect(!isHighConfidence("cli_flag_secret"));
}

fn reportHuman(stdout: *Io.File.Writer, results: []const FileResult, total: usize, files: usize, color: bool) !void {
    const w = &stdout.interface;
    if (total == 0) {
        try w.writeAll("No secrets found in agent transcripts.\n");
        return;
    }
    for (results) |r| {
        try w.print("{s}\n", .{r.path});
        for (r.aggs) |a| {
            if (color) {
                try w.print("  {s}{s}{s} {s}  {s}  ({d}\u{00d7}, {s})\n", .{
                    severityStyle(a.severity), severityBadge(a.severity), ansi_reset,
                    a.det_type,                a.redacted_token,          a.count,
                    a.source.label(),
                });
            } else {
                try w.print("  {s} {s}  {s}  ({d}\u{00d7}, {s})\n", .{
                    severityBadge(a.severity), a.det_type, a.redacted_token, a.count, a.source.label(),
                });
            }
            try w.print("        {s}\n", .{a.context});
        }
        try w.writeByte('\n');
    }
    try w.print("{d} secret(s) across {d} session file(s).\n", .{ total, files });
    try w.writeAll("Rotate each credential, delete the affected session files, and make sure\n");
    try w.writeAll("this directory is not synced, committed, or world-readable.\n");
}

fn reportJson(stdout: *Io.File.Writer, results: []const FileResult) !void {
    const w = &stdout.interface;
    for (results) |r| {
        for (r.aggs) |a| {
            const record = .{
                .file = r.path,
                .token = a.redacted_token,
                .det_type = a.det_type,
                .severity = a.severity.name(),
                .count = a.count,
                .source = a.source.label(),
                .context = a.context,
            };
            try std.json.Stringify.value(record, .{}, w);
            try w.writeByte('\n');
        }
    }
}

// Single-line, length-limited snippet of a redacted command centered on the
// match. Newlines/tabs collapse to spaces so a multi-line tool output stays on
// one line.
fn windowContext(alloc: std.mem.Allocator, cmd: []const u8, match_start: usize, match_len: usize) ![]const u8 {
    const max_full = 120;
    const ctx = 40;
    var start: usize = 0;
    var end: usize = cmd.len;
    var lead = false;
    var trail = false;
    if (cmd.len > max_full) {
        const ms = @min(match_start, cmd.len);
        start = if (ms > ctx) ms - ctx else 0;
        end = @min(ms + match_len + ctx, cmd.len);
        lead = start > 0;
        trail = end < cmd.len;
    }

    var out: std.ArrayList(u8) = .empty;
    if (lead) try out.appendSlice(alloc, "\u{2026}");
    for (cmd[start..end]) |c| {
        try out.append(alloc, if (c == '\n' or c == '\r' or c == '\t') ' ' else c);
    }
    if (trail) try out.appendSlice(alloc, "\u{2026}");
    return out.toOwnedSlice(alloc);
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

fn colorEnabled(io: Io, environ: *const std.process.Environ.Map) !bool {
    if (environ.get("NO_COLOR")) |_| return false;
    return try Io.File.stdout().isTty(io);
}

const ansi_reset = "\x1b[0m";
const ansi_bold_red = "\x1b[1;31m";
const ansi_bold_yellow = "\x1b[1;33m";
const ansi_bold_blue = "\x1b[1;34m";

fn severityBadge(severity: Severity) []const u8 {
    return switch (severity) {
        .high => "[!!!]",
        .medium => "[!! ]",
        .low => "[!  ]",
        .ignore => "[   ]",
    };
}

fn severityStyle(severity: Severity) []const u8 {
    return switch (severity) {
        .high => ansi_bold_red,
        .medium => ansi_bold_yellow,
        .low => ansi_bold_blue,
        .ignore => ansi_reset,
    };
}

test "scanned honours the default and --all-content sets" {
    try std.testing.expect(scanned(.user_input, false));
    try std.testing.expect(scanned(.tool_output, false));
    try std.testing.expect(scanned(.tool_call, false));
    try std.testing.expect(scanned(.stored_context, false));
    try std.testing.expect(!scanned(.assistant, false));
    try std.testing.expect(!scanned(.reasoning, false));
    try std.testing.expect(scanned(.assistant, true));
    try std.testing.expect(scanned(.reasoning, true));
}

test "progress paths compact home and show files relative to roots" {
    const alloc = std.testing.allocator;
    const compact = try compactHomePath(alloc, "/home/user/.claude/projects", "/home/user");
    defer alloc.free(compact);
    try std.testing.expectEqualStrings("~/.claude/projects", compact);
    try std.testing.expectEqualStrings("app/session.jsonl", relativePath(
        "/home/user/.claude/projects",
        "/home/user/.claude/projects/app/session.jsonl",
    ));
    try std.testing.expectEqualStrings("history.jsonl", relativePath(
        "/home/user/.claude/history.jsonl",
        "/home/user/.claude/history.jsonl",
    ));
}

test "windowContext single-lines and trims a long snippet" {
    const alloc = std.testing.allocator;
    const cmd = ("x" ** 200) ++ "\nSECRET\n" ++ ("y" ** 200);
    const out = try windowContext(alloc, cmd, 201, 6);
    defer alloc.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "SECRET") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\n") == null);
    try std.testing.expect(out.len < cmd.len);
}
