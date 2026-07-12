const std = @import("std");

const zon_text = @embedFile("build.zig.zon");

fn versionFromZon() []const u8 {
    const marker = ".version = \"";
    const start = std.mem.indexOf(u8, zon_text, marker) orelse @panic("version not found in build.zig.zon");
    const rest = zon_text[start + marker.len ..];
    const end = std.mem.indexOf(u8, rest, "\"") orelse @panic("unterminated version in build.zig.zon");
    return rest[0..end];
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize: std.builtin.OptimizeMode = .ReleaseSmall;

    const zecli = b.dependency("zecli", .{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", versionFromZon());

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("cli", zecli.module("cli"));
    mod.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "shg",
        .root_module = mod,
    });
    b.installArtifact(exe);

    const config_mod = b.createModule(.{
        .root_source_file = b.path("src/config_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    config_mod.addImport("cli", zecli.module("cli"));
    const config_exe = b.addExecutable(.{
        .name = "shg-config",
        .root_module = config_mod,
    });
    b.installArtifact(config_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run shg");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("cli", zecli.module("cli"));
    test_mod.addOptions("build_options", options);
    const unit_tests = b.addTest(.{
        .name = "shg-tests",
        .root_module = test_mod,
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    const smoke_cmd = b.addSystemCommand(&.{ "sh", "tests/smoke.sh" });
    smoke_cmd.step.dependOn(b.getInstallStep());
    smoke_cmd.setEnvironmentVariable("SHG_BIN", b.getInstallPath(.bin, "shg"));
    smoke_cmd.setEnvironmentVariable("SHG_CONFIG_BIN", b.getInstallPath(.bin, "shg-config"));
    const smoke_step = b.step("smoke", "Run end-to-end smoke tests");
    smoke_step.dependOn(&smoke_cmd.step);

    const bench_cmd = b.addSystemCommand(&.{ "sh", "tests/benchmark.sh" });
    bench_cmd.step.dependOn(b.getInstallStep());
    bench_cmd.setEnvironmentVariable("SHG_BIN", b.getInstallPath(.bin, "shg"));
    bench_cmd.setEnvironmentVariable("SHG_CONFIG_BIN", b.getInstallPath(.bin, "shg-config"));
    const bench_step = b.step("bench", "Benchmark scan throughput on a deterministic corpus");
    bench_step.dependOn(&bench_cmd.step);
}
