const std = @import("std");
const Io = std.Io;
const Entry = @import("../entry.zig").Entry;

pub fn parse(reader: *Io.Reader, filename: []const u8, alloc: std.mem.Allocator) ![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    var line_no: usize = 0;

    while (try reader.takeDelimiter('\n')) |raw_line| {
        line_no += 1;
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') raw_line[0 .. raw_line.len - 1] else raw_line;
        if (line.len == 0) continue;

        var timestamp: ?i64 = null;
        var command: []const u8 = line;

        if (std.mem.startsWith(u8, line, ": ")) {
            if (parseExtended(line)) |parsed| {
                timestamp = parsed.ts;
                command = parsed.cmd;
            }
        }

        const cmd = try alloc.dupe(u8, command);
        const raw = try alloc.dupe(u8, line);
        try entries.append(alloc, .{
            .file = filename,
            .line = line_no,
            .timestamp = timestamp,
            .raw = raw,
            .command = cmd,
        });
    }
    return entries.toOwnedSlice(alloc);
}

const Parsed = struct { ts: i64, cmd: []const u8 };

fn parseExtended(line: []const u8) ?Parsed {
    if (!std.mem.startsWith(u8, line, ": ")) return null;
    const rest = line[2..];
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const ts = std.fmt.parseInt(i64, rest[0..colon], 10) catch return null;
    const after = rest[colon + 1 ..];
    const semi = std.mem.indexOfScalar(u8, after, ';') orelse return null;
    const cmd = after[semi + 1 ..];
    if (cmd.len == 0) return null;
    return .{ .ts = ts, .cmd = cmd };
}

test "zsh plain" {
    const alloc = std.testing.allocator;
    var r = std.Io.Reader.fixed("ls -la\n");
    const entries = try parse(&r, "test", alloc);
    defer {
        for (entries) |e| { alloc.free(e.command); alloc.free(e.raw); }
        alloc.free(entries);
    }
    try std.testing.expectEqualStrings("ls -la", entries[0].command);
    try std.testing.expect(entries[0].timestamp == null);
}

test "zsh extended" {
    const alloc = std.testing.allocator;
    var r = std.Io.Reader.fixed(": 1715000000:0;export API=secret\n");
    const entries = try parse(&r, "test", alloc);
    defer {
        for (entries) |e| { alloc.free(e.command); alloc.free(e.raw); }
        alloc.free(entries);
    }
    try std.testing.expectEqualStrings("export API=secret", entries[0].command);
    try std.testing.expectEqual(@as(?i64, 1715000000), entries[0].timestamp);
}
