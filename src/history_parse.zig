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
