const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize: std.builtin.OptimizeMode = .ReleaseSmall;

    const zecli = b.dependency("zecli", .{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.1.0");

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
    const smoke_step = b.step("smoke", "Run end-to-end smoke tests");
    smoke_step.dependOn(&smoke_cmd.step);
}
