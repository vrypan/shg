const finding = @import("finding.zig");
pub const Signals = finding.Signals;
pub const Severity = finding.Severity;

pub const default_entropy_threshold: f64 = 3.5;

pub fn score(s: Signals, entropy_threshold: f64) i32 {
    var n: i32 = 0;
    if (s.has_sensitive_keyword) n += 3;
    if (s.entropy >= entropy_threshold) n += 3;
    if (s.token_len >= 20) n += 2;
    if (s.is_auth_header) n += 2;
    if (s.is_credential_url) n += 2;
    if (s.is_known_format) n += 4;
    if (s.is_private_key) n += 6;
    if (s.is_search_command) n -= 2;
    if (s.is_placeholder) n -= 3;
    return n;
}

pub fn severity(n: i32) Severity {
    if (n <= 2) return .ignore;
    if (n <= 4) return .low;
    if (n <= 6) return .medium;
    return .high;
}

test "known format scores high" {
    const std = @import("std");
    const s = score(.{ .is_known_format = true, .token_len = 40, .entropy = 4.5 }, 3.5);
    try std.testing.expect(severity(s) == .high);
}

test "placeholder suppresses score" {
    const std = @import("std");
    const s = score(.{ .has_sensitive_keyword = true, .is_placeholder = true, .token_len = 10 }, 3.5);
    try std.testing.expect(severity(s) == .ignore or severity(s) == .low);
}
