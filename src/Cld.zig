//! Cld links one or multiple Coff object files
//! into a single PE binary file. The order of supplying
//! the object files is important to the output.
const Cld = @This();
const std = @import("std");
const Coff = @import("Coff.zig");
const Allocator = std.mem.Allocator;

/// The Cld-scoped logger
const log = std.log.scoped(.cld);

gpa: Allocator,
/// Name of the final binary, also its output path
name: []const u8,
/// User-provided options which influence the final output
options: Options,
/// File descriptor of the output binary
file: std.fs.File,
/// A list of all Coff object files to be linked
objects: std.ArrayListUnmanaged(Coff) = .{},

/// Possible user configuration options
const Options = struct {};

pub fn openPath(allocator: Allocator, path: []const u8, options: Options) !Cld {
    const file = try std.fs.cwd().createFile(path, .{ .lock = .Exclusive });
    return Cld{
        .gpa = allocator,
        .name = path,
        .options = options,
        .file = file,
    };
}

pub fn deinit(cld: *Cld) void {
    cld.file.close();
    for (cld.objects.items) |*obj| {
        obj.file.close();
        obj.deinit();
    }
    cld.* = undefined;
}

/// Appends one or multiple Coff object files that will be linked into the final binary.
/// Skips the file when the given path is not a Coff object file.
///
/// TODO: Make this work for archive files as well as dynamic libraries.
pub fn addObjects(cld: *Cld, paths: []const []const u8) !void {
    for (paths) |path| {
        const file = try std.fs.cwd().openFile(path, .{});
        var coff = Coff.init(cld.gpa, file, path);
        errdefer coff.deinit();

        if (try coff.parse()) {
            try cld.objects.append(cld.gpa, coff);
            log.debug("Appended Coff object '{s}'", .{path});
        }
    }
}

pub fn flush(cld: *Cld) !void {
    _ = cld;
}
