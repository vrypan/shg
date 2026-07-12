const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const config = @import("config.zig");
const rules = @import("rules.zig");
const sources = @import("sources.zig");

pub fn run(init: std.process.Init, args: cli.Args) !void {
    const io = init.io;
    const alloc = init.arena.allocator();
    const environ = init.environ_map;

    var out_buf: [32768]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    defer stdout.flush() catch {};

    var err_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &err_buf);
    defer stderr.flush() catch {};

    const cache = (try loadRules(io, alloc, environ)) orelse {
        try stderr.interface.writeAll("shg: no compiled rules found; run shg-config compile\n");
        try stderr.flush();
        std.process.exit(2);
    };

    // Discovery is bounded: explicit --path arguments, or the compiled
    // agent_path rules (paths.agents.*.shg). Never a disk crawl.
    const files = if (args.paths.len > 0)
        try sources.expandExplicitPaths(io, alloc, environ, args.paths)
    else
        try sources.agentPaths(io, alloc, environ, cache);

    for (files) |f| {
        try stdout.interface.print("{s}\n", .{f});
    }
}

fn loadRules(io: Io, alloc: std.mem.Allocator, environ: *const std.process.Environ.Map) !?rules.Cache {
    const path = (try config.compiledFile(alloc, environ)) orelse return null;
    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    const bytes = try reader.interface.readAlloc(alloc, @intCast(stat.size));
    return try rules.Cache.init(bytes);
}
