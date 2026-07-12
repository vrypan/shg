const std = @import("std");
const Io = std.Io;
const Entry = @import("../entry.zig").Entry;

/// Lines longer than the reader buffer are skipped (counted in `skipped`)
/// so one oversized line cannot abort the scan of the rest of the file.
pub fn parse(reader: *Io.Reader, filename: []const u8, alloc: std.mem.Allocator, skipped: *usize) ![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    var line_no: usize = 0;

    var cur_cmd: ?[]u8 = null;
    var cur_ts: ?i64 = null;
    var cur_line: usize = 0;

    while (true) {
        const maybe_line = reader.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                line_no += 1;
                skipped.* += 1;
                _ = reader.discardDelimiterInclusive('\n') catch break;
                continue;
            },
            error.ReadFailed => return err,
        };
        const raw_line = maybe_line orelse break;
        line_no += 1;
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') raw_line[0 .. raw_line.len - 1] else raw_line;

        if (std.mem.startsWith(u8, line, "- cmd: ")) {
            if (cur_cmd) |cmd| {
                try entries.append(alloc, .{ .file = filename, .line = cur_line, .timestamp = cur_ts, .raw = cmd, .command = cmd });
            }
            cur_cmd = try alloc.dupe(u8, line[7..]);
            cur_ts = null;
            cur_line = line_no;
        } else if (std.mem.startsWith(u8, line, "  when: ")) {
            cur_ts = std.fmt.parseInt(i64, line[8..], 10) catch null;
        }
    }

    if (cur_cmd) |cmd| {
        try entries.append(alloc, .{ .file = filename, .line = cur_line, .timestamp = cur_ts, .raw = cmd, .command = cmd });
    }

    return entries.toOwnedSlice(alloc);
}

test "fish parser" {
    const alloc = std.testing.allocator;
    const input =
        "- cmd: ls -la\n" ++
        "  when: 1715000000\n" ++
        "- cmd: export TOKEN=abc123\n" ++
        "  when: 1715000001\n";
    var r = std.Io.Reader.fixed(input);
    var skipped: usize = 0;
    const entries = try parse(&r, "test", alloc, &skipped);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("ls -la", entries[0].command);
    try std.testing.expectEqual(@as(?i64, 1715000000), entries[0].timestamp);
}
