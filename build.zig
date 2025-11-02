const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zaudio", .{
        .root_source_file = b.path("src/libzaudio.zig"),
        .target = target,
    });

    const check_exe = b.addExecutable(.{
        .name = "check",
        .root_module = mod,
    });
    check_exe.root_module.addImport("test", mod);

    const check_step = b.step("check", "Run the check executable");
    check_step.dependOn(&check_exe.step);
}
