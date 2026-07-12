const std = @import("std");
const Io = std.Io;
const Entry = @import("../entry.zig").Entry;

// Strings shorter than this hold nothing detectable.
const min_string = 8;
// A long string with no whitespace is treated as a blob (base64, data URI)
// and skipped — real prose and commands contain spaces.
const blob_len = 256;

// Read the entire file at once to avoid the reader-buffer line-length limit.
// Each line is parsed as JSON and only its human-text string leaves become
// entries; malformed lines fall back to scanning the raw line.
pub fn parse(reader: *Io.Reader, filename: []const u8, alloc: std.mem.Allocator) ![]Entry {
    const bytes = try reader.allocRemaining(alloc, Io.Limit.limited(512 * 1024 * 1024));
    defer alloc.free(bytes);

    var entries: std.ArrayList(Entry) = .empty;
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (line.len == 0) continue;

        // parseFromSlice owns the parsed tree in its own arena; we dupe every
        // extracted string into `alloc` before deinit, so entries stay valid
        // regardless of what allocator the caller passes.
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch {
            // Not valid JSON — scan the raw line as before.
            const raw = try alloc.dupe(u8, line);
            try entries.append(alloc, .{
                .file = filename,
                .line = line_no,
                .timestamp = null,
                .raw = raw,
                .command = raw,
            });
            continue;
        };
        defer parsed.deinit();
        try collectStrings(parsed.value, filename, line_no, alloc, &entries);
    }
    return entries.toOwnedSlice(alloc);
}

fn collectStrings(value: std.json.Value, filename: []const u8, line_no: usize, alloc: std.mem.Allocator, entries: *std.ArrayList(Entry)) !void {
    switch (value) {
        .string => |s| {
            if (s.len < min_string) return;
            if (s.len > blob_len and std.mem.indexOfScalar(u8, s, ' ') == null) return;
            const dup = try alloc.dupe(u8, s);
            try entries.append(alloc, .{
                .file = filename,
                .line = line_no,
                .timestamp = null,
                .raw = dup,
                .command = dup,
            });
        },
        .array => |arr| {
            for (arr.items) |item| try collectStrings(item, filename, line_no, alloc, entries);
        },
        .object => |obj| {
            for (obj.values()) |v| try collectStrings(v, filename, line_no, alloc, entries);
        },
        else => {},
    }
}

test "jsonl extracts text leaf as a command" {
    const alloc = std.testing.allocator;
    var r = Io.Reader.fixed("{\"message\":{\"content\":\"export API_KEY=zK9mQx2LwPq44XyTr7Vn\"}}\n");
    const entries = try parse(&r, "test.jsonl", alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("export API_KEY=zK9mQx2LwPq44XyTr7Vn", entries[0].command);
    try std.testing.expectEqual(@as(usize, 1), entries[0].line);
}

test "jsonl skips long whitespace-free blobs" {
    const alloc = std.testing.allocator;
    const blob = "A" ** 300;
    var r = Io.Reader.fixed("{\"data\":\"" ++ blob ++ "\"}\n");
    const entries = try parse(&r, "test.jsonl", alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "jsonl falls back to raw line for non-JSON" {
    const alloc = std.testing.allocator;
    var r = Io.Reader.fixed("not json at all, PASSWORD=zK9mQx2LwPq44XyTr7Vn\n");
    const entries = try parse(&r, "test.jsonl", alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("not json at all, PASSWORD=zK9mQx2LwPq44XyTr7Vn", entries[0].command);
}

test "jsonl recurses into nested arrays and objects" {
    const alloc = std.testing.allocator;
    var r = Io.Reader.fixed("{\"a\":[{\"b\":\"the quick brown fox says hello\"}]}\n");
    const entries = try parse(&r, "test.jsonl", alloc);
    defer {
        for (entries) |e| alloc.free(e.command);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("the quick brown fox says hello", entries[0].command);
}
