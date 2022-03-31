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
/// List of synthetic symbols
synthetic_symbols: std.ArrayListUnmanaged(Coff.Symbol) = .{},
/// A mapping between a symbol's old location, with its replacement
/// location. i.e. when a weak symbol is overwritten by a stronger symbol.
discarded: std.AutoHashMapUnmanaged(SymbolWithLoc, SymbolWithLoc) = .{},
/// A mapping for all symbols which have been resolved
resolved_symbols: std.AutoHashMapUnmanaged(SymbolWithLoc, void) = .{},
/// Mapping between global's names and their symbol location
globals: std.AutoHashMapUnmanaged(u32, SymbolWithLoc) = .{},

/// Possible user configuration options
const Options = struct {};

pub const SymbolWithLoc = struct {
    /// Index of the symbol entry within the object file
    index: u32,
    /// When file is 'null', this symbol is populated from outside an object file.
    /// i.e. a synthetic symbol
    file: ?u16,

    pub fn getSymbol(sym_loc: SymbolWithLoc, cld: *const Cld) *Coff.Symbol {
        if (cld.discarded.get(sym_loc)) |new_loc| {
            return new_loc.getSymbol(cld);
        }
        if (sym_loc.file) |object_index| {
            return &cld.objects.items[object_index].symbols.items[sym_loc.index];
        }
        return &cld.synthetic_symbols.items[sym_loc.index];
    }
};

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
    cld.synthetic_symbols.deinit(cld.gpa);
    cld.discarded.deinit(cld.gpa);
    cld.resolved_symbols.deinit(cld.gpa);
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
    for (cld.objects.items) |_, idx| {
        try resolveSymbolsInObject(cld, @intCast(u16, idx));
    }

    for (cld.objects.items) |object| {
        try Coff.parseIntoAtoms(object, cld);
    }
}

/// Resolves symbols in given object file index.
fn resolveSymbolsInObject(cld: *Cld, index: u16) !void {
    const object: Coff = cld.objects.items[index];
    var sym_index: u32 = 0;
    while (sym_index < object.header.number_of_symbols) : (sym_index += 1) {
        const symbol: Coff.Symbol = object.symbols.items[sym_index];
        defer sym_index += symbol.number_aux_symbols; // skip auxiliry symbols
    }
}
