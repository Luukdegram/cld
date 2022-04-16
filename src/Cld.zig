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

    // TODO: Emit unresolved symbols and error out

    for (cld.objects.items) |object, idx| {
        try Coff.parseIntoAtoms(object, cld, @intCast(u16, idx));
    }

    try sortSections(cld);
    try allocateSections(cld);
    try allocateAtoms(cld);
}

/// Resolves symbols in given object file index.
fn resolveSymbolsInObject(cld: *Cld, index: u16) !void {
    const object: Coff = cld.objects.items[index];
    var sym_index: u32 = 0;
    while (sym_index < object.header.number_of_symbols) : (sym_index += 1) {
        const symbol: Coff.Symbol = object.symbols.items[sym_index];
        defer sym_index += symbol.number_aux_symbols; // skip auxiliry symbols

        // Add all symbols to resolved list for now
        // TODO: Actually resolve symbols correctly.
        try cld.resolved_symbols.putNoClobber(cld.gpa, .{ .file = index, .index = sym_index }, {});
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

/// Returns the corresponding string from a given 8-byte buffer
pub fn getString(cld: Cld, buf: [8]u8) []const u8 {
    const offset = if (buf[0] == '/') blk: {
        const offset_len = std.mem.indexOfScalar(u8, buf[1..], 0) orelse 7;
        const offset = std.fmt.parseInt(u32, buf[1..][0..offset_len], 10) catch return "";
        break :blk offset;
    } else if (std.mem.eql(u8, buf[0..4], &.{ 0, 0, 0, 0 })) blk: {
        break :blk std.mem.readIntLittle(u32, buf[4..8]);
    } else return std.mem.sliceTo(&buf, 0);

    const str = @ptrCast([*:0]const u8, cld.string_table.items.ptr + offset);
    return std.mem.sliceTo(str, 0);
}

/// Sorts sections into the most optimal order
fn sortSections(cld: *Cld) !void {
    log.debug("Sorting sections. Old order:", .{});
    for (cld.section_headers.items) |hdr, index| {
        log.debug("  {d: >2} {s: >9}", .{ index, cld.getString(hdr.name) });
    }

    // Sort sections based on their name. When the section is grouped,
    // we ordinally order the corresponding sections based on alphabetic order.
    var ctx: SectionSortContext = .{ .cld = cld };
    std.sort.sort(Coff.SectionHeader, cld.section_headers.items, ctx, SectionSortContext.lessThan);

    // replace old section mapping indexes with the name indexes
    var old_mapping = std.AutoArrayHashMap(u16, u16).init(cld.gpa);
    defer old_mapping.deinit();
    try old_mapping.ensureUnusedCapacity(cld.section_headers.items.len);
    for (cld.section_headers.items) |hdr, index| {
        const value = cld.section_mapping.getPtr(cld.getString(hdr.name)).?;
        const new_index = @intCast(u16, index);
        old_mapping.putAssumeCapacityNoClobber(value.*, new_index);
        value.* = new_index;
    }

    var new_atoms: std.AutoHashMapUnmanaged(u16, *Atom) = .{};
    try new_atoms.ensureUnusedCapacity(cld.gpa, cld.atoms.count());

    var it = cld.atoms.iterator();
    while (it.next()) |entry| {
        const old_index = entry.key_ptr.*;
        const new_index = old_mapping.get(old_index).?;
        new_atoms.putAssumeCapacityNoClobber(new_index, entry.value_ptr.*);
    }

    cld.atoms.deinit(cld.gpa);
    cld.atoms = new_atoms;

    log.debug("Sorted sections. New order:", .{});
    for (cld.section_headers.items) |hdr, index| {
        log.debug("  {d: >2} {s: >9}", .{ index, cld.getString(hdr.name) });
    }
}

const SectionSortContext = struct {
    cld: *const Cld,

    fn value(ctx: SectionSortContext, header: Coff.SectionHeader) u16 {
        const startsWith = std.mem.startsWith;
        const name = ctx.cld.getString(header.name);
        if (startsWith(u8, name, ".text")) {
            return 0;
        } else if (startsWith(u8, name, ".data")) {
            return 1;
        } else if (startsWith(u8, name, ".bss")) {
            return 2;
        } else if (startsWith(u8, name, ".xdata")) {
            return 3;
        } else if (startsWith(u8, name, ".rdata")) {
            return 4;
        } else if (startsWith(u8, name, ".tls")) {
            return 5;
        } else if (startsWith(u8, name, ".debug")) {
            return 6;
        } else if (startsWith(u8, name, ".pdata")) {
            return 7;
        } else std.debug.panic("TODO: value of section named: '{s}'\n", .{name});
        unreachable;
    }

    fn isGroupedFirst(ctx: SectionSortContext, lhs: Coff.SectionHeader, rhs: Coff.SectionHeader) bool {
        std.debug.assert(lhs.isGrouped() and rhs.isGrouped());
        const lhs_name = ctx.cld.getString(lhs.name);
        const rhs_name = ctx.cld.getString(rhs.name);
        const start = std.mem.indexOfScalar(u8, lhs_name, '$').?;
        if (start == lhs_name.len - 1) return true;
        if (start == rhs_name.len - 1) return true;
        return lhs_name[start + 1] < rhs_name[start + 1];
    }

    fn lessThan(ctx: SectionSortContext, lhs: Coff.SectionHeader, rhs: Coff.SectionHeader) bool {
        const lhs_val = ctx.value(lhs);
        const rhs_val = ctx.value(rhs);
        if (lhs_val == rhs_val) {
            return ctx.isGroupedFirst(lhs, rhs);
        }
        return lhs_val < rhs_val;
    }
};

/// From a given section name, returns the short section name.
/// This is useful to determine which section a grouped section belongs to.
/// e.g. .text$X beloging to the .text section.
fn sectionShortName(name: []const u8) []const u8 {
    const startsWith = std.mem.startsWith;
    if (startsWith(u8, name, ".text")) {
        return ".text";
    } else if (startsWith(u8, name, ".data")) {
        return ".data";
    } else if (startsWith(u8, name, ".bss")) {
        return ".bss";
    } else if (startsWith(u8, name, ".xdata")) {
        return ".xdata";
    } else if (startsWith(u8, name, ".rdata")) {
        return ".rdata";
    } else if (startsWith(u8, name, ".tls")) {
        return ".tls";
    } else if (startsWith(u8, name, ".debug")) {
        return ".debug";
    } else if (startsWith(u8, name, ".pdata")) {
        return ".pdata";
    } else std.debug.panic("TODO: shortname of section named: '{s}'\n", .{name});
    unreachable;
}

fn allocateSections(cld: *Cld) !void {
    const signature_offset_at = 0x3c;
    var offset: u32 = signature_offset_at + 8; // 4 bytes for "PE\0\0" and another 4 for the offset.
    offset += 20; // space for the COFF File Header
    offset += 120; // space for optional header

    log.debug("allocating sections, starting at offset: 0x{x:0>4}", .{offset});

    for (cld.section_headers.items) |hdr| {
        if (hdr.isGrouped()) {
            continue;
        }
        offset += 40; // each header takes up 40 bytes
    }

    // as we now have the full offset, we can start to visually allocate all sections
    // into the binary
    for (cld.section_headers.items) |*hdr| {
        hdr.pointer_to_raw_data = offset;
        offset += hdr.size_of_raw_data;

        if (!hdr.isGrouped()) {
            log.debug("  allocated section '{s}' from 0x{x:0>8} to 0x{x:0>8}", .{
                cld.getString(hdr.name),
                hdr.pointer_to_raw_data,
                hdr.pointer_to_raw_data + hdr.size_of_raw_data,
            });
        }
    }
}

fn allocateAtoms(cld: *Cld) !void {
    var it = cld.atoms.iterator();
    while (it.next()) |entry| {
        const section_index = entry.key_ptr.*;
        const hdr: Coff.SectionHeader = cld.section_headers.items[section_index];
        var atom: *Atom = entry.value_ptr.*.getFirst();

        log.debug("allocating atoms in section '{s}'", .{cld.getString(hdr.name)});

        var base_offset = hdr.pointer_to_raw_data;
        while (true) {
            base_offset = std.mem.alignForwardGeneric(u32, base_offset, atom.alignment);

            const coff: *Coff = &cld.objects.items[atom.file];
            const sym: *Coff.Symbol = &coff.symbols.items[atom.sym_index];

            std.debug.assert(sym.value == 0); // section symbols always have their `value` set to 0.

            sym.section_number = @intCast(i16, section_index + 1); // section numbers are 1-indexed.

            log.debug("  atom '{s}' allocated from 0x{x:0>8} to 0x{x:0>8}", .{
                coff.getString(sym.name),
                base_offset,
                base_offset + atom.size,
            });

            for (atom.aliases.items) |sym_index| {
                const alias = &coff.symbols.items[sym_index];
                alias.value = base_offset;
                alias.section_number = sym.section_number;
            }

            for (atom.contained.items) |sym_at_offset| {
                const contained_sym = &coff.symbols.items[sym_at_offset.sym_index];
                contained_sym.value = base_offset + sym_at_offset.offset;
                contained_sym.section_number = sym.section_number;
            }

            base_offset += atom.size;

            atom = atom.next orelse break;
        }
    }
}
