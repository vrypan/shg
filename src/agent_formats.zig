const std = @import("std");

// Which part of a transcript a piece of text came from. `shg agents` scans
// user_input + tool_call + tool_output by default; assistant + reasoning only
// with --all-content.
pub const Source = enum {
    user_input,
    tool_call,
    tool_output,
    stored_context,
    assistant,
    reasoning,

    pub fn label(self: Source) []const u8 {
        return switch (self) {
            .user_input => "user_input",
            .tool_call => "tool_call",
            .tool_output => "tool_output",
            .stored_context => "stored_context",
            .assistant => "assistant",
            .reasoning => "reasoning",
        };
    }
};

pub const Piece = struct {
    source: Source,
    line: usize,
    text: []const u8,
};

pub const Format = enum {
    claude,
    claude_history,
    codex_history,
    codex_session,
    gemini_json,
    gemini_jsonl,
    copilot,
    json,
    jsonl,
    markdown,
    text,
};

/// Pick a parser from the file path. Known agents get source-aware extraction;
/// unknown JSON/JSONL recursively scans string values; everything else is text.
pub fn formatForPath(path: []const u8) Format {
    if (std.mem.endsWith(u8, path, ".jsonl")) {
        if (pathContains(path, "/.codex/history.jsonl", "\\.codex\\history.jsonl")) return .codex_history;
        if (pathContains(path, "/.codex/sessions/", "\\.codex\\sessions\\")) return .codex_session;
        if (pathContains(path, "/.claude/history.jsonl", "\\.claude\\history.jsonl")) return .claude_history;
        if (pathContains(path, "/.claude/projects/", "\\.claude\\projects\\")) return .claude;
        if (pathContains(path, "/.gemini/tmp/", "\\.gemini\\tmp\\")) return .gemini_jsonl;
        if (pathContains(path, "/.copilot/session-state/", "\\.copilot\\session-state\\")) return .copilot;
        return .jsonl;
    }
    if (std.mem.endsWith(u8, path, ".json")) {
        if (pathContains(path, "/.gemini/tmp/", "\\.gemini\\tmp\\")) return .gemini_json;
        return .json;
    }
    if (std.mem.endsWith(u8, path, ".md") or std.mem.endsWith(u8, path, ".markdown")) return .markdown;
    return .text;
}

fn pathContains(path: []const u8, unix: []const u8, windows: []const u8) bool {
    return std.mem.indexOf(u8, path, unix) != null or std.mem.indexOf(u8, path, windows) != null;
}

pub fn malformedUnit(format: Format) []const u8 {
    return switch (format) {
        .json, .gemini_json => "JSON document(s)",
        .claude, .claude_history, .codex_history, .codex_session, .gemini_jsonl, .copilot, .jsonl => "JSONL record(s)",
        .markdown, .text => "record(s)",
    };
}

/// Parse one transcript file's bytes into tagged text pieces. Best-effort: a
/// line that is not valid JSON is skipped, never crashed on and never dumped
/// raw.
pub fn extract(format: Format, bytes: []const u8, alloc: std.mem.Allocator) ![]Piece {
    var skipped: usize = 0;
    return extractCounting(format, bytes, alloc, &skipped);
}

pub fn extractCounting(format: Format, bytes: []const u8, alloc: std.mem.Allocator, skipped: *usize) ![]Piece {
    var pieces: std.ArrayList(Piece) = .empty;

    if (format == .text or format == .markdown) {
        try extractTextLines(bytes, alloc, &pieces);
        return pieces.toOwnedSlice(alloc);
    }

    if (format == .json or format == .gemini_json) {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch {
            skipped.* += 1;
            return pieces.toOwnedSlice(alloc);
        };
        defer parsed.deinit();
        if (format == .gemini_json) {
            try extractGeminiDocument(parsed.value, 1, alloc, &pieces);
        } else {
            try emitStringLeaves(&pieces, alloc, .stored_context, 1, parsed.value);
        }
        return pieces.toOwnedSlice(alloc);
    }

    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (line.len == 0) continue;
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch {
            skipped.* += 1;
            continue;
        };
        defer parsed.deinit();
        switch (format) {
            .claude => try extractClaude(parsed.value, line_no, alloc, &pieces),
            .claude_history => try extractClaudeHistory(parsed.value, line_no, alloc, &pieces),
            .codex_history => try extractCodexHistory(parsed.value, line_no, alloc, &pieces),
            .codex_session => try extractCodexSession(parsed.value, line_no, alloc, &pieces),
            .gemini_jsonl => try extractGeminiRecord(parsed.value, line_no, alloc, &pieces),
            .copilot => try extractCopilotEvent(parsed.value, line_no, alloc, &pieces),
            .jsonl => try emitStringLeaves(&pieces, alloc, .stored_context, line_no, parsed.value),
            .gemini_json, .json, .markdown, .text => unreachable,
        }
    }
    return pieces.toOwnedSlice(alloc);
}

fn extractTextLines(bytes: []const u8, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (line.len == 0) continue;
        try emit(pieces, alloc, .stored_context, line_no, std.mem.trimEnd(u8, line, "\r"));
    }
}

fn extractClaude(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse return;
    const rtype = objStr(obj, "type") orelse return;
    const msg = asObject(obj.get("message") orelse return) orelse return;
    const content = msg.get("content") orelse return;

    if (std.mem.eql(u8, rtype, "user")) {
        // A typed prompt is a plain string; a tool result is a list of blocks.
        switch (content) {
            .string => |s| try emit(pieces, alloc, .user_input, line, s),
            .array => |arr| for (arr.items) |block| {
                const b = asObject(block) orelse continue;
                const btype = objStr(b, "type") orelse continue;
                if (std.mem.eql(u8, btype, "tool_result")) {
                    if (b.get("content")) |bc| try emitBlockText(pieces, alloc, .tool_output, line, bc);
                }
            },
            else => {},
        }
    } else if (std.mem.eql(u8, rtype, "assistant")) {
        const arr = asArray(content) orelse return;
        for (arr.items) |block| {
            const b = asObject(block) orelse continue;
            const btype = objStr(b, "type") orelse continue;
            if (std.mem.eql(u8, btype, "tool_use")) {
                if (b.get("input")) |input| try emitStringLeaves(pieces, alloc, .tool_call, line, input);
            } else if (std.mem.eql(u8, btype, "text")) {
                if (objStr(b, "text")) |t| try emit(pieces, alloc, .assistant, line, t);
            } else if (std.mem.eql(u8, btype, "thinking")) {
                if (objStr(b, "thinking")) |t| try emit(pieces, alloc, .reasoning, line, t);
            }
        }
    }
}

fn extractCodexHistory(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse return;
    if (objStr(obj, "text")) |t| try emit(pieces, alloc, .user_input, line, t);
}

// Claude Code command history: {"display": "<typed prompt>",
// "pastedContents": "<stringified JSON of pasted text>", ...}. The typed
// prompt is `display`; pasted content may itself carry a pasted secret, so
// scan it too when non-empty.
fn extractClaudeHistory(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse return;
    if (objStr(obj, "display")) |d| try emit(pieces, alloc, .user_input, line, d);
    if (objStr(obj, "pastedContents")) |pc| {
        if (pc.len > 2) try emit(pieces, alloc, .user_input, line, pc);
    }
}

fn extractCodexSession(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse return;
    const rtype = objStr(obj, "type") orelse return;
    if (!std.mem.eql(u8, rtype, "response_item")) return;
    const p = asObject(obj.get("payload") orelse return) orelse return;
    const ptype = objStr(p, "type") orelse return;

    if (std.mem.eql(u8, ptype, "message")) {
        const role = objStr(p, "role") orelse "assistant";
        const src: Source = if (std.mem.eql(u8, role, "user")) .user_input else .assistant;
        if (p.get("content")) |c| try emitBlockText(pieces, alloc, src, line, c);
    } else if (std.mem.eql(u8, ptype, "function_call") or std.mem.eql(u8, ptype, "custom_tool_call")) {
        if (objStr(p, "arguments")) |a| try emit(pieces, alloc, .tool_call, line, a);
        if (p.get("input")) |i| try emitStringLeaves(pieces, alloc, .tool_call, line, i);
    } else if (std.mem.eql(u8, ptype, "function_call_output") or std.mem.eql(u8, ptype, "custom_tool_call_output")) {
        if (objStr(p, "output")) |o| try emit(pieces, alloc, .tool_output, line, o);
    } else if (std.mem.eql(u8, ptype, "reasoning")) {
        if (p.get("summary")) |s| try emitStringLeaves(pieces, alloc, .reasoning, line, s);
    }
}

// Gemini CLI's current session format is JSONL: one metadata record followed
// by message records. Older releases wrote the same conversation as one JSON
// document with a `messages` array, so both feed the same record extractor.
fn extractGeminiDocument(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse {
        try emitStringLeaves(pieces, alloc, .stored_context, line, root);
        return;
    };
    if (obj.get("messages")) |messages| {
        const arr = asArray(messages) orelse return;
        for (arr.items) |message| try extractGeminiRecord(message, line, alloc, pieces);
        if (obj.get("summary")) |summary| try emitStringLeaves(pieces, alloc, .assistant, line, summary);
        if (obj.get("memoryScratchpad")) |memory| try emitStringLeaves(pieces, alloc, .stored_context, line, memory);
    } else {
        try emitStringLeaves(pieces, alloc, .stored_context, line, root);
    }
}

fn extractGeminiRecord(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse return;
    const rtype = objStr(obj, "type") orelse {
        if (obj.get("$set")) |update| try emitStringLeaves(pieces, alloc, .stored_context, line, update);
        if (obj.get("summary")) |summary| try emitStringLeaves(pieces, alloc, .assistant, line, summary);
        if (obj.get("memoryScratchpad")) |memory| try emitStringLeaves(pieces, alloc, .stored_context, line, memory);
        return;
    };
    const source: Source = if (std.mem.eql(u8, rtype, "user"))
        .user_input
    else if (std.mem.eql(u8, rtype, "gemini"))
        .assistant
    else
        .stored_context;

    if (obj.get("content")) |content| try emitStringLeaves(pieces, alloc, source, line, content);
    if (source == .user_input) {
        if (obj.get("displayContent")) |content| try emitStringLeaves(pieces, alloc, .user_input, line, content);
    }
    if (source != .assistant) return;

    if (obj.get("toolCalls")) |calls| {
        if (asArray(calls)) |arr| {
            for (arr.items) |call| {
                const call_obj = asObject(call) orelse continue;
                if (call_obj.get("args")) |args| try emitStringLeaves(pieces, alloc, .tool_call, line, args);
                if (call_obj.get("result")) |result| try emitStringLeaves(pieces, alloc, .tool_output, line, result);
                if (call_obj.get("resultDisplay")) |result| try emitStringLeaves(pieces, alloc, .tool_output, line, result);
            }
        }
    }
    if (obj.get("thoughts")) |thoughts| try emitStringLeaves(pieces, alloc, .reasoning, line, thoughts);
}

// Copilot CLI stores an append-only stream of {type,data,...} events. Event
// names are stable source hints even as individual data payloads evolve.
fn extractCopilotEvent(root: std.json.Value, line: usize, alloc: std.mem.Allocator, pieces: *std.ArrayList(Piece)) !void {
    const obj = asObject(root) orelse {
        try emitStringLeaves(pieces, alloc, .stored_context, line, root);
        return;
    };
    const rtype = objStr(obj, "type") orelse {
        try emitStringLeaves(pieces, alloc, .stored_context, line, root);
        return;
    };
    const source: Source = if (std.mem.startsWith(u8, rtype, "user.") or std.mem.startsWith(u8, rtype, "prompt."))
        .user_input
    else if (std.mem.indexOf(u8, rtype, "reason") != null)
        .reasoning
    else if (std.mem.startsWith(u8, rtype, "assistant."))
        .assistant
    else if (std.mem.startsWith(u8, rtype, "tool.") and
        (std.mem.indexOf(u8, rtype, "start") != null or std.mem.indexOf(u8, rtype, "request") != null))
        .tool_call
    else if (std.mem.startsWith(u8, rtype, "tool."))
        .tool_output
    else
        .stored_context;

    if (obj.get("data")) |data| {
        try emitStringLeaves(pieces, alloc, source, line, data);
    } else {
        try emitStringLeaves(pieces, alloc, source, line, root);
    }
}

// A block's text is either a plain string or a list of {type,text} blocks.
fn emitBlockText(pieces: *std.ArrayList(Piece), alloc: std.mem.Allocator, src: Source, line: usize, v: std.json.Value) !void {
    switch (v) {
        .string => |s| try emit(pieces, alloc, src, line, s),
        .array => |arr| for (arr.items) |b| {
            const bo = asObject(b) orelse continue;
            if (objStr(bo, "text")) |t| try emit(pieces, alloc, src, line, t);
        },
        else => {},
    }
}

// Emit every string leaf of a value (used for tool_use inputs / reasoning
// summaries whose shape is an object or array of strings).
fn emitStringLeaves(pieces: *std.ArrayList(Piece), alloc: std.mem.Allocator, src: Source, line: usize, v: std.json.Value) !void {
    switch (v) {
        .string => |s| try emit(pieces, alloc, src, line, s),
        .array => |arr| for (arr.items) |it| try emitStringLeaves(pieces, alloc, src, line, it),
        .object => |obj| for (obj.values()) |val| try emitStringLeaves(pieces, alloc, src, line, val),
        else => {},
    }
}

fn emit(pieces: *std.ArrayList(Piece), alloc: std.mem.Allocator, src: Source, line: usize, text: []const u8) !void {
    if (text.len == 0) return;
    try pieces.append(alloc, .{ .source = src, .line = line, .text = try alloc.dupe(u8, text) });
}

fn asObject(v: std.json.Value) ?std.json.ObjectMap {
    return switch (v) {
        .object => |o| o,
        else => null,
    };
}

fn asArray(v: std.json.Value) ?std.json.Array {
    return switch (v) {
        .array => |a| a,
        else => null,
    };
}

fn asString(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn objStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    return asString(obj.get(key) orelse return null);
}

fn freePieces(alloc: std.mem.Allocator, pieces: []Piece) void {
    for (pieces) |p| alloc.free(p.text);
    alloc.free(pieces);
}

test "formatForPath" {
    try std.testing.expectEqual(Format.codex_history, formatForPath("/home/u/.codex/history.jsonl"));
    try std.testing.expectEqual(Format.codex_session, formatForPath("/home/u/.codex/sessions/2026/01/x.jsonl"));
    try std.testing.expectEqual(Format.claude, formatForPath("/home/u/.claude/projects/p/x.jsonl"));
    try std.testing.expectEqual(Format.gemini_jsonl, formatForPath("/home/u/.gemini/tmp/p/chats/session.jsonl"));
    try std.testing.expectEqual(Format.gemini_json, formatForPath("/home/u/.gemini/tmp/p/checkpoint.json"));
    try std.testing.expectEqual(Format.copilot, formatForPath("/home/u/.copilot/session-state/id/events.jsonl"));
    try std.testing.expectEqual(Format.jsonl, formatForPath("/tmp/whatever.jsonl"));
    try std.testing.expectEqual(Format.json, formatForPath("/tmp/whatever.json"));
    try std.testing.expectEqual(Format.markdown, formatForPath("/home/u/.claude/projects/p/memory/MEMORY.md"));
    try std.testing.expectEqual(Format.markdown, formatForPath("/tmp/notes.markdown"));
    try std.testing.expectEqual(Format.text, formatForPath("/home/u/.claude/projects/p/tool-results/result.txt"));
    try std.testing.expectEqual(Format.text, formatForPath("/tmp/unknown.data"));
}

test "generic JSON recursively emits string values" {
    const alloc = std.testing.allocator;
    const pieces = try extract(.json, "{\"token\":\"ghp_nested\",\"items\":[{\"value\":\"tool output\"}],\"count\":2}", alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 2), pieces.len);
    try std.testing.expectEqualStrings("ghp_nested", pieces[0].text);
    try std.testing.expectEqualStrings("tool output", pieces[1].text);
    try std.testing.expectEqual(Source.stored_context, pieces[0].source);
}

test "generic JSONL recursively emits each record's string values" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"data\":{\"prompt\":\"first\"}}\n" ++
        "{\"data\":{\"result\":\"second\"}}\n";
    const pieces = try extract(.jsonl, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 2), pieces.len);
    try std.testing.expectEqualStrings("first", pieces[0].text);
    try std.testing.expectEqual(@as(usize, 1), pieces[0].line);
    try std.testing.expectEqualStrings("second", pieces[1].text);
    try std.testing.expectEqual(@as(usize, 2), pieces[1].line);
}

test "text: emits non-empty lines as stored context" {
    const alloc = std.testing.allocator;
    var skipped: usize = 0;
    const pieces = try extractCounting(.text, "first line\n\nsecond line\r\n", alloc, &skipped);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 2), pieces.len);
    try std.testing.expectEqual(Source.stored_context, pieces[0].source);
    try std.testing.expectEqualStrings("first line", pieces[0].text);
    try std.testing.expectEqual(@as(usize, 3), pieces[1].line);
    try std.testing.expectEqualStrings("second line", pieces[1].text);
    try std.testing.expectEqual(@as(usize, 0), skipped);
}

test "claude: typed prompt is user_input" {
    const alloc = std.testing.allocator;
    const bytes = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"deploy the thing\"}}\n";
    const pieces = try extract(.claude, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 1), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqualStrings("deploy the thing", pieces[0].text);
}

test "claude: tool_result is tool_output" {
    const alloc = std.testing.allocator;
    const bytes = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":\"GITHUB_TOKEN=ghp_x\"}]}}\n";
    const pieces = try extract(.claude, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 1), pieces.len);
    try std.testing.expectEqual(Source.tool_output, pieces[0].source);
    try std.testing.expectEqualStrings("GITHUB_TOKEN=ghp_x", pieces[0].text);
}

test "claude: tool_use input is tool_call, text is assistant, thinking is reasoning" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{\"command\":\"env | grep KEY\"}}]}}\n" ++
        "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"here is the plan\"}]}}\n" ++
        "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"thinking\",\"thinking\":\"let me think\"}]}}\n";
    const pieces = try extract(.claude, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 3), pieces.len);
    try std.testing.expectEqual(Source.tool_call, pieces[0].source);
    try std.testing.expectEqualStrings("env | grep KEY", pieces[0].text);
    try std.testing.expectEqual(Source.assistant, pieces[1].source);
    try std.testing.expectEqual(Source.reasoning, pieces[2].source);
}

test "claude history: display is user_input, pasted content scanned" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"display\":\"deploy with export TOKEN=ghp_x\",\"pastedContents\":\"{}\",\"timestamp\":\"1\",\"project\":\"/p\"}\n" ++
        "{\"display\":\"check this\",\"pastedContents\":\"AWS_SECRET=abc123\",\"timestamp\":\"2\",\"project\":\"/p\"}\n";
    const pieces = try extract(.claude_history, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 3), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqualStrings("deploy with export TOKEN=ghp_x", pieces[0].text);
    // line 2: display + non-empty pastedContents both emitted
    try std.testing.expectEqualStrings("check this", pieces[1].text);
    try std.testing.expectEqualStrings("AWS_SECRET=abc123", pieces[2].text);
}

test "formatForPath detects claude history" {
    try std.testing.expectEqual(Format.claude_history, formatForPath("/home/u/.claude/history.jsonl"));
    try std.testing.expectEqual(Format.claude, formatForPath("/home/u/.claude/projects/p/x.jsonl"));
}

test "codex history: text is user_input" {
    const alloc = std.testing.allocator;
    const bytes = "{\"session_id\":\"a\",\"ts\":1,\"text\":\"run the release\"}\n";
    const pieces = try extract(.codex_history, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 1), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqualStrings("run the release", pieces[0].text);
}

test "codex session: function_call_output is tool_output, user message is user_input" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"timestamp\":\"t\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"c\",\"output\":\"AWS_SECRET=abc\"}}\n" ++
        "{\"timestamp\":\"t\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"fix the bug\"}]}}\n" ++
        "{\"timestamp\":\"t\",\"type\":\"session_meta\",\"payload\":{}}\n";
    const pieces = try extract(.codex_session, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 2), pieces.len);
    try std.testing.expectEqual(Source.tool_output, pieces[0].source);
    try std.testing.expectEqualStrings("AWS_SECRET=abc", pieces[0].text);
    try std.testing.expectEqual(Source.user_input, pieces[1].source);
    try std.testing.expectEqualStrings("fix the bug", pieces[1].text);
}

test "gemini JSONL classifies messages, tools, and reasoning" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"sessionId\":\"s\",\"projectHash\":\"p\"}\n" ++
        "{\"type\":\"user\",\"content\":\"deploy this\"}\n" ++
        "{\"type\":\"gemini\",\"content\":\"assistant reply\",\"toolCalls\":[{\"args\":{\"command\":\"cat .env\"},\"result\":[{\"text\":\"GITHUB_TOKEN=ghp_x\"}]}],\"thoughts\":[{\"description\":\"reasoning text\"}]}\n";
    const pieces = try extract(.gemini_jsonl, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 5), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqualStrings("deploy this", pieces[0].text);
    try std.testing.expectEqual(Source.assistant, pieces[1].source);
    try std.testing.expectEqual(Source.tool_call, pieces[2].source);
    try std.testing.expectEqualStrings("cat .env", pieces[2].text);
    try std.testing.expectEqual(Source.tool_output, pieces[3].source);
    try std.testing.expectEqualStrings("GITHUB_TOKEN=ghp_x", pieces[3].text);
    try std.testing.expectEqual(Source.reasoning, pieces[4].source);
}

test "legacy Gemini JSON document extracts its messages" {
    const alloc = std.testing.allocator;
    const bytes = "{\"sessionId\":\"s\",\"messages\":[{\"type\":\"user\",\"content\":\"hello\"},{\"type\":\"gemini\",\"content\":\"answer\"}]}";
    const pieces = try extract(.gemini_json, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 2), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqual(Source.assistant, pieces[1].source);
}

test "Copilot events classify user, assistant, and tool data" {
    const alloc = std.testing.allocator;
    const bytes =
        "{\"type\":\"user.message\",\"data\":{\"content\":\"check this\"}}\n" ++
        "{\"type\":\"assistant.message\",\"data\":{\"content\":\"response\"}}\n" ++
        "{\"type\":\"tool.execution_start\",\"data\":{\"command\":\"env\"}}\n" ++
        "{\"type\":\"tool.execution_complete\",\"data\":{\"output\":\"API_KEY=secret\"}}\n";
    const pieces = try extract(.copilot, bytes, alloc);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 4), pieces.len);
    try std.testing.expectEqual(Source.user_input, pieces[0].source);
    try std.testing.expectEqual(Source.assistant, pieces[1].source);
    try std.testing.expectEqual(Source.tool_call, pieces[2].source);
    try std.testing.expectEqual(Source.tool_output, pieces[3].source);
}

test "malformed line is skipped, not crashed on" {
    const alloc = std.testing.allocator;
    const bytes =
        "this is not json\n" ++
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}\n";
    var skipped: usize = 0;
    const pieces = try extractCounting(.claude, bytes, alloc, &skipped);
    defer freePieces(alloc, pieces);
    try std.testing.expectEqual(@as(usize, 1), pieces.len);
    try std.testing.expectEqualStrings("ok", pieces[0].text);
    try std.testing.expectEqual(@as(usize, 1), skipped);
}
