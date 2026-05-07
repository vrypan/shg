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
        const cmd = try alloc.dupe(u8, line);
        try entries.append(alloc, .{
            .file = filename,
            .line = line_no,
            .timestamp = null,
            .raw = cmd,
            .command = cmd,
        });
    }
    return entries.toOwnedSlice(alloc);
}

test "bash parser" {
    const alloc = std.testing.allocator;
    var r = Io.Reader.fixed("ls -la\nexport FOO=bar\n");
    const entries = try parse(&r, "test", alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("ls -la", entries[0].command);
    try std.testing.expectEqualStrings("export FOO=bar", entries[1].command);
}
