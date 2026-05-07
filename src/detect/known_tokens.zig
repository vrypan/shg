const std = @import("std");
const Entry = @import("../entry.zig").Entry;
const Candidate = @import("../finding.zig").Candidate;
const entropy = @import("../entropy.zig");

const Provider = struct {
    prefix: []const u8,
    min_len: usize,
    name: []const u8,
};

const providers = [_]Provider{
    .{ .prefix = "sk-ant-", .min_len = 50, .name = "anthropic_api_key" },
    .{ .prefix = "sk-", .min_len = 30, .name = "openai_api_key" },
    .{ .prefix = "github_pat_", .min_len = 40, .name = "github_fine_grained_token" },
    .{ .prefix = "ghp_", .min_len = 36, .name = "github_token" },
    .{ .prefix = "gho_", .min_len = 36, .name = "github_oauth_token" },
    .{ .prefix = "ghu_", .min_len = 36, .name = "github_user_token" },
    .{ .prefix = "ghs_", .min_len = 36, .name = "github_app_token" },
    .{ .prefix = "ghr_", .min_len = 36, .name = "github_refresh_token" },
    .{ .prefix = "xoxb-", .min_len = 20, .name = "slack_bot_token" },
    .{ .prefix = "xoxp-", .min_len = 20, .name = "slack_user_token" },
    .{ .prefix = "xapp-", .min_len = 20, .name = "slack_app_token" },
    .{ .prefix = "xwfp-", .min_len = 20, .name = "slack_workflow_token" },
    .{ .prefix = "AKIA", .min_len = 20, .name = "aws_access_key" },
    .{ .prefix = "ASIA", .min_len = 20, .name = "aws_temp_access_key" },
    .{ .prefix = "sk_live_", .min_len = 24, .name = "stripe_key" },
    .{ .prefix = "sk_test_", .min_len = 24, .name = "stripe_test_key" },
    .{ .prefix = "rk_live_", .min_len = 24, .name = "stripe_restricted_key" },
    .{ .prefix = "rk_test_", .min_len = 24, .name = "stripe_test_restricted_key" },
    .{ .prefix = "whsec_", .min_len = 16, .name = "stripe_webhook_secret" },
    .{ .prefix = "sk_org_", .min_len = 16, .name = "stripe_org_key" },
};

pub fn detect(e: Entry, alloc: std.mem.Allocator) ![]Candidate {
    var results: std.ArrayList(Candidate) = .empty;
    const cmd = e.command;

    for (providers) |p| {
        var start: usize = 0;
        while (std.mem.indexOfPos(u8, cmd, start, p.prefix)) |idx| {
            const tok_start = idx;
            var tok_end = tok_start + p.prefix.len;
            while (tok_end < cmd.len and isTokenChar(cmd[tok_end])) tok_end += 1;
            const token = cmd[tok_start..tok_end];
            if (token.len >= p.min_len) {
                try results.append(alloc, .{
                    .token = token,
                    .det_type = p.name,
                    .signals = .{
                        .is_known_format = true,
                        .token_len = token.len,
                        .entropy = entropy.shannon(token),
                    },
                });
            }
            start = if (tok_end > start) tok_end else start + 1;
        }
    }

    return results.toOwnedSlice(alloc);
}

fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '/';
}

test "detect github token" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "git clone https://ghp_abcdefghijklmnopqrstuvwxyz012345@github.com/x/y",
        .command = "git clone https://ghp_abcdefghijklmnopqrstuvwxyz012345@github.com/x/y",
    };
    const candidates = try detect(e, alloc);
    defer alloc.free(candidates);
    try std.testing.expect(candidates.len > 0);
    try std.testing.expectEqualStrings("github_token", candidates[0].det_type);
}

test "detect additional github token formats" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "export GITHUB_FINE=github_pat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ GITHUB_OAUTH=gho_abcdefghijklmnopqrstuvwxyz012345",
        .command = "export GITHUB_FINE=github_pat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ GITHUB_OAUTH=gho_abcdefghijklmnopqrstuvwxyz012345",
    };
    const candidates = try detect(e, alloc);
    defer alloc.free(candidates);
    try std.testing.expectEqual(@as(usize, 2), candidates.len);
    try std.testing.expectEqualStrings("github_fine_grained_token", candidates[0].det_type);
    try std.testing.expectEqualStrings("github_oauth_token", candidates[1].det_type);
}

test "detect additional cloud and provider token formats" {
    const alloc = std.testing.allocator;
    const e = Entry{
        .file = "test", .line = 1, .timestamp = null,
        .raw = "ASIAIOSFODNN7EXAMPLE rk_live_abcdefghijklmnopqrstuvwxyz whsec_abcdefghijklmnop xapp-1-abcdefghijklmnop",
        .command = "ASIAIOSFODNN7EXAMPLE rk_live_abcdefghijklmnopqrstuvwxyz whsec_abcdefghijklmnop xapp-1-abcdefghijklmnop",
    };
    const candidates = try detect(e, alloc);
    defer alloc.free(candidates);
    try std.testing.expectEqual(@as(usize, 4), candidates.len);
    try std.testing.expect(hasDetection(candidates, "aws_temp_access_key"));
    try std.testing.expect(hasDetection(candidates, "stripe_restricted_key"));
    try std.testing.expect(hasDetection(candidates, "stripe_webhook_secret"));
    try std.testing.expect(hasDetection(candidates, "slack_app_token"));
}

fn hasDetection(candidates: []const Candidate, det_type: []const u8) bool {
    for (candidates) |c| {
        if (std.mem.eql(u8, c.det_type, det_type)) return true;
    }
    return false;
}
