//! Cld links one or multiple Coff object files
//! into a single PE binary file. The order of supplying
//! the object files is important to the output.
const Cld = @This();
const std = @import("std");
const Coff = @import("Coff.zig");
const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");

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

/// Contains all section headers (unordered)
section_headers: std.ArrayListUnmanaged(Coff.SectionHeader) = .{},
/// Mapping from section name to their index
section_mapping: std.StringHashMapUnmanaged(u16) = .{},
/// The table with all strings occupying more than 8 bytes.
string_table: std.ArrayListUnmanaged(u8) = .{},
/// Maps section indexes to the last atom of that section.
atoms: std.AutoHashMapUnmanaged(u16, *Atom) = .{},
/// Tracks all atoms created from various object files,
/// used to clean up all resources.
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},

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

/// Closes the file handle to the PE binary file,
/// deallocates all resources related to the linking process,
/// and invalidates the passed `cld` instance.
pub fn deinit(cld: *Cld) void {
    cld.file.close();
    for (cld.objects.items) |*obj| {
        obj.file.close();
        obj.deinit();
    }
    cld.objects.deinit(cld.gpa);
    cld.synthetic_symbols.deinit(cld.gpa);
    cld.discarded.deinit(cld.gpa);
    cld.resolved_symbols.deinit(cld.gpa);
    cld.section_headers.deinit(cld.gpa);
    var header_names_it = cld.section_mapping.keyIterator();
    while (header_names_it.next()) |name| {
        cld.gpa.free(name.*);
    }
    cld.section_mapping.deinit(cld.gpa);
    cld.atoms.deinit(cld.gpa);
    for (cld.managed_atoms.items) |atom| {
        atom.destroy(cld.gpa);
    }
    cld.managed_atoms.deinit(cld.gpa);
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

    for (cld.objects.items) |object, idx| {
        try Coff.parseIntoAtoms(object, cld, @intCast(u16, idx));
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

pub fn getMatchingSection(cld: *Cld, object_index: u16, section_index: u16) !?u16 {
    const object: Coff = cld.objects.items[object_index];
    const sec_header: Coff.SectionHeader = object.section_table.items[section_index];
    const sec_name = object.getString(sec_header.name);
    const flags = sec_header.characteristics;
    const current_index = @intCast(u16, cld.section_headers.items.len);

    if (flags & Coff.SectionHeader.flags.IMAGE_SCN_LNK_REMOVE != 0) return null;
    if (flags & Coff.SectionHeader.flags.IMAGE_SCN_MEM_DISCARDABLE != 0) return null;

    const gop = try cld.section_mapping.getOrPut(cld.gpa, try cld.gpa.dupe(u8, sec_name));
    if (!gop.found_existing) {
        gop.value_ptr.* = current_index;

        const header = try cld.section_headers.addOne(cld.gpa);
        header.* = .{
            .name = try cld.makeString(gop.key_ptr.*, .header),
            .virtual_size = 0,
            .virtual_address = 0,
            .size_of_raw_data = 0,
            .pointer_to_raw_data = 0,
            .pointer_to_relocations = 0,
            .pointer_to_line_numbers = 0,
            .number_of_relocations = 0,
            .number_of_line_numbers = 0,
            .characteristics = flags,
            .alignment = 0,
        };
    }
    return gop.value_ptr.*;
}

/// Makes a Coff-formatted string by storing it directly when smaller or equal to 8 bytes,
/// or else store it in the string table and write the offset into that table in the 8 bytes
/// of the returned array. The layout of this array is determined based on given `string_type`.
fn makeString(cld: *Cld, string: []const u8, string_type: enum { symbol, header }) ![8]u8 {
    var buf = [_]u8{0} ** 8;
    if (string.len <= 8) {
        std.mem.copy(u8, &buf, string);
        return buf;
    }
    const offset = @intCast(u32, cld.string_table.items.len);
    try cld.string_table.appendSlice(cld.gpa, string);

    if (string_type == .symbol) {
        std.mem.writeIntLittle(u32, buf[4..8], offset);
    } else {
        buf[0] = '/';
        _ = std.fmt.bufPrint(buf[1..], "{d}", .{offset}) catch unreachable;
    }
    return buf;
}
