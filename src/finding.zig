const Entry = @import("entry.zig").Entry;

pub const Signals = struct {
    has_sensitive_keyword: bool = false,
    is_known_format: bool = false,
    is_private_key: bool = false,
    is_credential_url: bool = false,
    is_auth_header: bool = false,
    is_search_command: bool = false,
    is_placeholder: bool = false,
    token_len: usize = 0,
    entropy: f64 = 0.0,
};

pub const Candidate = struct {
    token: []const u8,
    signals: Signals,
    det_type: []const u8,
};

pub const Severity = enum(u8) {
    ignore = 0,
    low = 1,
    medium = 2,
    high = 3,

    pub fn name(self: Severity) []const u8 {
        return switch (self) {
            .ignore => "ignore",
            .low => "low",
            .medium => "medium",
            .high => "high",
        };
    }

    pub fn tag(self: Severity) []const u8 {
        return switch (self) {
            .ignore => "IGNORE",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
        };
    }
};

pub const Finding = struct {
    entry: Entry,
    det_type: []const u8,
    severity: Severity,
    score: i32,
    redacted_cmd: []const u8,
    recommendation: []const u8,
};
