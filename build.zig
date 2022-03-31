const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();
    const enable_logging = b.option(bool, "enable-logging", "Enables logging to stderr [default: false]") orelse false;
    const exe = b.addExecutable("cld", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    const options = b.addOptions();
    options.addOption(bool, "enable_logging", enable_logging);
    exe.addOptions("build_flags", options);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
