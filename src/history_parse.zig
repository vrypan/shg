const std = @import("std");
const Io = std.Io;
const Entry = @import("entry.zig").Entry;
const agent_formats = @import("agent_formats.zig");

const zsh_parser = @import("parsers/zsh.zig");
const fish_parser = @import("parsers/fish.zig");
const jsonl_parser = @import("parsers/jsonl.zig");

/// Parse a history file into entries, dispatching on the path. Shared by the
/// scan flow and `shg fix` so both agree on how each format is read.
pub fn parseFile(reader: *Io.Reader, path: []const u8, alloc: std.mem.Allocator, skipped: *usize) ![]Entry {
    if (std.mem.indexOf(u8, path, "fish_history") != null)
        return fish_parser.parse(reader, path, alloc, skipped);
    // Agent command histories are JSONL files of typed prompts; treat them as
    // history (one prompt per entry), not as a generic JSON blob.
    if (std.mem.indexOf(u8, path, "/.codex/history.jsonl") != null)
        return parseAgentHistory(reader, path, .codex_history, alloc);
    if (std.mem.indexOf(u8, path, "/.claude/history.jsonl") != null)
        return parseAgentHistory(reader, path, .claude_history, alloc);
    if (std.mem.endsWith(u8, path, ".jsonl"))
        return jsonl_parser.parse(reader, path, alloc);
    // The zsh parser also accepts plain one-command-per-line histories. Using it
    // as the default preserves zsh extended metadata for explicit --path scans.
    return zsh_parser.parse(reader, path, alloc, skipped);
}

/// True for the per-command prompt histories scanned by `shg history`.
/// Findings here may also have been copied into an agent's fuller transcript.
pub fn isAgentHistoryPath(path: []const u8) bool {
    return pathEndsWith(path, "/.codex/history.jsonl", "\\.codex\\history.jsonl") or
        pathEndsWith(path, "/.claude/history.jsonl", "\\.claude\\history.jsonl") or
        pathEndsWith(path, "/.ollama/history", "\\.ollama\\history") or
        pathEndsWith(path, "/.aider.input.history", "\\.aider.input.history");
}

fn pathEndsWith(path: []const u8, unix_suffix: []const u8, windows_suffix: []const u8) bool {
    return std.mem.endsWith(u8, path, unix_suffix) or std.mem.endsWith(u8, path, windows_suffix);
}

pub fn parseEach(reader: *Io.Reader, path: []const u8, alloc: std.mem.Allocator, skipped: *usize, consumer: anytype) !void {
    if (std.mem.indexOf(u8, path, "fish_history") != null)
        return fish_parser.parseEach(reader, path, alloc, skipped, consumer);

    // Structured histories still use their existing whole-file parsers. Their
    // JSON trees require owned input; shell and stdin paths stream directly.
    if (std.mem.indexOf(u8, path, "/.codex/history.jsonl") != null or
        std.mem.indexOf(u8, path, "/.claude/history.jsonl") != null or
        std.mem.endsWith(u8, path, ".jsonl"))
    {
        const entries = try parseFile(reader, path, alloc, skipped);
        for (entries) |entry| try consumer.consume(entry);
        return;
    }
    return zsh_parser.parseEach(reader, path, skipped, consumer);
}

fn parseAgentHistory(reader: *Io.Reader, path: []const u8, format: agent_formats.Format, alloc: std.mem.Allocator) ![]Entry {
    const bytes = try reader.allocRemaining(alloc, Io.Limit.limited(512 * 1024 * 1024));
    const pieces = try agent_formats.extract(format, bytes, alloc);
    var entries: std.ArrayList(Entry) = .empty;
    for (pieces) |p| {
        try entries.append(alloc, .{
            .file = path,
            .line = p.line,
            .timestamp = null,
            .raw = p.text,
            .command = p.text,
        });
    }
    return entries.toOwnedSlice(alloc);
}

const TestConsumer = struct {
    alloc: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn consume(self: *TestConsumer, entry: Entry) !void {
        try self.entries.append(self.alloc, .{
            .file = entry.file,
            .line = entry.line,
            .timestamp = entry.timestamp,
            .raw = try self.alloc.dupe(u8, entry.raw),
            .command = try self.alloc.dupe(u8, entry.command),
        });
    }

    fn deinit(self: *TestConsumer) void {
        for (self.entries.items) |entry| {
            self.alloc.free(entry.raw);
            self.alloc.free(entry.command);
        }
        self.entries.deinit(self.alloc);
    }
};

test "parseEach streams plain and extended zsh entries" {
    const alloc = std.testing.allocator;
    var reader = Io.Reader.fixed("ls -la\n: 1715000000:0;export API_KEY=value\n");
    var skipped: usize = 0;
    var consumer = TestConsumer{ .alloc = alloc };
    defer consumer.deinit();

    try parseEach(&reader, "/tmp/.zsh_history", alloc, &skipped, &consumer);
    try std.testing.expectEqual(@as(usize, 2), consumer.entries.items.len);
    try std.testing.expectEqualStrings("ls -la", consumer.entries.items[0].command);
    try std.testing.expectEqualStrings("export API_KEY=value", consumer.entries.items[1].command);
    try std.testing.expectEqual(@as(?i64, 1715000000), consumer.entries.items[1].timestamp);
}

test "parseEach streams fish entries after reading timestamps" {
    const alloc = std.testing.allocator;
    var reader = Io.Reader.fixed("- cmd: ls -la\n  when: 100\n- cmd: pwd\n  when: 200\n");
    var skipped: usize = 0;
    var consumer = TestConsumer{ .alloc = alloc };
    defer consumer.deinit();

    try parseEach(&reader, "/tmp/fish_history", alloc, &skipped, &consumer);
    try std.testing.expectEqual(@as(usize, 2), consumer.entries.items.len);
    try std.testing.expectEqualStrings("ls -la", consumer.entries.items[0].command);
    try std.testing.expectEqual(@as(?i64, 100), consumer.entries.items[0].timestamp);
    try std.testing.expectEqualStrings("pwd", consumer.entries.items[1].command);
    try std.testing.expectEqual(@as(?i64, 200), consumer.entries.items[1].timestamp);
}

test "isAgentHistoryPath recognizes supported command histories" {
    try std.testing.expect(isAgentHistoryPath("/home/u/.codex/history.jsonl"));
    try std.testing.expect(isAgentHistoryPath("/home/u/.claude/history.jsonl"));
    try std.testing.expect(isAgentHistoryPath("/home/u/.ollama/history"));
    try std.testing.expect(isAgentHistoryPath("/home/u/.aider.input.history"));
    try std.testing.expect(isAgentHistoryPath("C:\\Users\\u\\.codex\\history.jsonl"));
    try std.testing.expect(!isAgentHistoryPath("/home/u/.zsh_history"));
    try std.testing.expect(!isAgentHistoryPath("/tmp/history.jsonl"));
}
