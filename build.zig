const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "btrfs2squashfs",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
    });
    b.installArtifact(exe);

    const probe = b.addExecutable(.{
        .name = "btrfs-probe-extents",
        .root_source_file = b.path("src/probe.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
    });
    b.installArtifact(probe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run btrfs2squashfs");
    run_step.dependOn(&run_cmd.step);
}
