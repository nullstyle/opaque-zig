const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Path dependency on the sibling opaque-zig library (repo root). The package
    // key is `opaque_zig` (its build.zig.zon `.name`); the consumable module it
    // exposes is named `opaque`.
    const dep = b.dependency("opaque_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("opaque", dep.module("opaque"));

    const exe = b.addExecutable(.{
        .name = "opaque-cli",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // Unit tests, including the in-process client<->server round trip that
    // validates the client flow end-to-end without an HTTP server.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("opaque", dep.module("opaque"));

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
