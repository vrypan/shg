const std = @import("std");

pub fn shannon(s: []const u8) f64 {
    if (s.len == 0) return 0.0;
    var counts = [_]u32{0} ** 256;
    for (s) |c| counts[c] += 1;
    const n: f64 = @floatFromInt(s.len);
    var h: f64 = 0.0;
    for (counts) |count| {
        if (count == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(count)) / n;
        h -= p * std.math.log2(p);
    }
    return h;
}

test "entropy: all same chars is zero" {
    try std.testing.expectApproxEqAbs(0.0, shannon("aaaa"), 0.001);
}

test "entropy: two equal chars is 1.0" {
    try std.testing.expectApproxEqAbs(1.0, shannon("aabb"), 0.001);
}

test "entropy: high-entropy string above threshold" {
    try std.testing.expect(shannon("sk-a8Fs2KpQrT7mNvX1cY4") > 3.5);
}

test "entropy: empty string" {
    try std.testing.expectApproxEqAbs(0.0, shannon(""), 0.001);
}
