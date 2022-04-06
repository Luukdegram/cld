const std = @import("std");
const Cld = @import("Cld.zig");
const mem = std.mem;

const io = std.io;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
const gpa = gpa_allocator.allocator();

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@import("build_flags").enable_logging) {
        std.log.defaultLog(level, scope, format, args);
    }
}

const usage =
    \\Usage: coff [options] [files...] -o [path]
    \\
    \\Options:
    \\-h, --help                         Print this help and exit
    \\-o [path]                          Output path of the binary
;

pub fn main() !void {
    defer if (@import("builtin").mode == .Debug) {
        _ = gpa_allocator.deinit();
    };

    // we use arena for the arguments and its parsing
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const process_args = try std.process.argsAlloc(arena);
    defer std.process.argsFree(arena, process_args);

    const args = process_args[1..]; // exclude 'coff' binary
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList([]const u8).init(arena);
    var output_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            printHelpAndExit();
        } else if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) printErrorAndExit("Missing output path", .{});
            output_path = args[i + 1];
            i += 1;
        } else if (mem.startsWith(u8, arg, "--")) {
            printErrorAndExit("Unknown argument '{s}'", .{arg});
        } else {
            try positionals.append(arg);
        }
    }

    if (positionals.items.len == 0) {
        printErrorAndExit("Expected one or more object files, none were given", .{});
    }

    if (output_path == null) {
        printErrorAndExit("Missing output path", .{});
    }

    var cld = try Cld.openPath(gpa, output_path.?, .{});
    defer cld.deinit();

    try cld.addObjects(positionals.items);
    try cld.flush();
}

fn printHelpAndExit() noreturn {
    io.getStdOut().writer().print("{s}\n", .{usage}) catch {};
    std.process.exit(0);
}

fn printErrorAndExit(comptime fmt: []const u8, args: anytype) noreturn {
    const writer = io.getStdErr().writer();
    writer.print(fmt, args) catch {};
    writer.writeByte('\n') catch {};
    std.process.exit(1);
}
