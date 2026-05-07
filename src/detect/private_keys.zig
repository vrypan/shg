const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;

const markers = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AGE-SECRET-KEY-1",
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    for (markers) |marker| {
        if (std.mem.indexOf(u8, cmd, marker) != null) {
            try results.append(alloc, .{
                .token = marker,
                .det_type = "private_key",
                .signals = .{ .is_private_key = true, .token_len = marker.len },
            });
            return results.toOwnedSlice(alloc);
        }
    }

    if (std.mem.indexOf(u8, cmd, "ssh-rsa AAAA") != null) {
        try results.append(alloc, .{
            .token = "ssh-rsa",
            .det_type = "ssh_key",
            .signals = .{ .is_private_key = true, .token_len = 20 },
        });
    }

    return results.toOwnedSlice(alloc);
}

test "detect encrypted private key marker" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "cat <<EOF -----BEGIN ENCRYPTED PRIVATE KEY-----",
        .command = "cat <<EOF -----BEGIN ENCRYPTED PRIVATE KEY-----",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("private_key", cs[0].det_type);
}

test "detect age secret key marker" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "echo AGE-SECRET-KEY-1QWERTY",
        .command = "echo AGE-SECRET-KEY-1QWERTY",
    };
    const cs = try detect(e, alloc);
    defer alloc.free(cs);
    try std.testing.expectEqual(@as(usize, 1), cs.len);
    try std.testing.expectEqualStrings("private_key", cs[0].det_type);
}
