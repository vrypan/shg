const std = @import("std");
const Io = std.Io;
const Entry = @import("../entry.zig").Entry;

// Read the entire file at once to avoid the reader-buffer line-length limit.
// Each non-empty line becomes one entry; the raw JSON is the scanned text.
pub fn parse(reader: *Io.Reader, filename: []const u8, alloc: std.mem.Allocator) ![]Entry {
    const bytes = try reader.allocRemaining(alloc, Io.Limit.limited(512 * 1024 * 1024));
    defer alloc.free(bytes);

    var entries: std.ArrayList(Entry) = .empty;
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (line.len == 0) continue;
        const raw = try alloc.dupe(u8, line);
        try entries.append(alloc, .{
            .file = filename,
            .line = line_no,
            .timestamp = null,
            .raw = raw,
            .command = raw,
        });
    }
    return entries.toOwnedSlice(alloc);
}
