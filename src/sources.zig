const std = @import("std");
const Io = std.Io;

const unix_paths = [_][]const u8{
    ".zsh_history",
    ".bash_history",
    ".local/share/fish/fish_history",
    ".config/fish/fish_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".sqlite_history",
    ".rediscli_history",
};

pub fn discover(io: Io, alloc: std.mem.Allocator, environ: *std.process.Environ.Map) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;

    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse return results.toOwnedSlice(alloc);

    for (unix_paths) |rel| {
        const full = try std.fs.path.join(alloc, &.{ home, rel });
        if (fileExists(io, full)) {
            try results.append(alloc, full);
        } else {
            alloc.free(full);
        }
    }

    return results.toOwnedSlice(alloc);
}

fn fileExists(io: Io, path: []const u8) bool {
    const f = Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
    f.close(io);
    return true;
}
