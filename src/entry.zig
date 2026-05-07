pub const Entry = struct {
    file: []const u8,
    line: usize,
    timestamp: ?i64,
    raw: []const u8,
    command: []const u8,
};
