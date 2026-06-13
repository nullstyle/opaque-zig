const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Optimize mode for the wasm module. Defaults to ReleaseSafe so that the
    // safety checks remain active at the hostile-input (untrusted host) ABI
    // boundary; can be overridden to ReleaseSmall for size-optimized builds.
    const wasm_optimize = b.option(
        std.builtin.OptimizeMode,
        "wasm-optimize",
        "Optimize mode for the wasm module",
    ) orelse .ReleaseSafe;

    // Whether to include the identity-KSF test-vector wasm exports. Off by
    // default; consumed by wasm.zig via the `build_options` module
    // (@import("build_options").test_exports), which gates the
    // *IdentityTestVector exports.
    const test_exports = b.option(
        bool,
        "test-exports",
        "Include identity-KSF test-vector wasm exports",
    ) orelse false;

    // Public consumable module. Dependents `@import("opaque")` to use the
    // library. We export it under the name `opaque` (the keyword is fine as a
    // module import name; it is only rejected as a package *identifier* in
    // build.zig.zon). The same module is also exposed below under the
    // `opaque_root` name that the in-tree tests import.
    const lib_mod = b.addModule("opaque", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "opaque",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("tests/all.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("opaque_root", lib_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/fuzz_all.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_mod.addImport("opaque_root", lib_mod);

    addFuzzStep(b, fuzz_mod, "fuzz", "Run all fuzz harnesses");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-messages", "Fuzz protocol message parsers", "fuzz message parsers");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-oprf", "Fuzz OPRF properties", "fuzz OPRF");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-opaque-roundtrip", "Fuzz OPAQUE registration/login round trips", "fuzz OPAQUE registration");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-opaque-tamper", "Fuzz OPAQUE authentication tamper checks", "fuzz OPAQUE authentication");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-opaque-negative", "Fuzz malformed OPAQUE protocol states", "fuzz OPAQUE malformed");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-validation", "Fuzz protocol input validation", "fuzz protocol input validation");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-wasm", "Fuzz WASM ABI byte layouts", "fuzz WASM ABI");
    addFilteredFuzzStep(b, fuzz_mod, "fuzz-wide", "Fuzz the broad public API surface", "fuzz wide");

    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        }),
        .optimize = wasm_optimize,
    });

    // Expose build-time options to the wasm module as `@import("build_options")`.
    // wasm.zig consumes @import("build_options").test_exports to gate the
    // *IdentityTestVector exports (it is @export-ed only when the flag is true).
    const wasm_options = b.addOptions();
    wasm_options.addOption(bool, "test_exports", test_exports);
    wasm_mod.addOptions("build_options", wasm_options);

    const wasm = b.addExecutable(.{
        .name = "opaque",
        .root_module = wasm_mod,
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;

    const install_wasm = b.addInstallArtifact(wasm, .{
        .dest_dir = .{ .override = .{ .custom = "wasm" } },
    });
    const wasm_step = b.step("wasm", "Build the opaque WASM module");
    wasm_step.dependOn(&install_wasm.step);
}

fn addFuzzStep(b: *std.Build, fuzz_mod: *std.Build.Module, name: []const u8, description: []const u8) void {
    const fuzz_tests = b.addTest(.{
        .name = name,
        .root_module = fuzz_mod,
    });
    forceLlvmForFuzzing(fuzz_tests);
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step(name, description);
    fuzz_step.dependOn(&run_fuzz_tests.step);
}

// Zig's fuzzer needs the LLVM backend for coverage instrumentation. The
// self-hosted x86_64 backend (the default for Debug native builds on
// x86_64-linux) emits no coverage program counters, so `zig build fuzz-*`
// fails there with "corrupted coverage file ...: pcs_len was zero" (and SEGVs
// on self-hosted aarch64). CI's macOS runner passes only because aarch64-macOS
// falls back to LLVM. Force LLVM here so fuzzing works on every platform; the
// regular test/wasm steps keep the (faster) default backend.
fn forceLlvmForFuzzing(fuzz_tests: *std.Build.Step.Compile) void {
    fuzz_tests.use_llvm = true;
}

fn addFilteredFuzzStep(
    b: *std.Build,
    fuzz_mod: *std.Build.Module,
    name: []const u8,
    description: []const u8,
    filter: []const u8,
) void {
    const fuzz_tests = b.addTest(.{
        .name = name,
        .root_module = fuzz_mod,
        .filters = &.{filter},
    });
    forceLlvmForFuzzing(fuzz_tests);
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step(name, description);
    fuzz_step.dependOn(&run_fuzz_tests.step);
}
