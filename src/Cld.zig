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
/// Represents the coff file header, instructs the image file
/// the data layour of the coff sections
coff_header: Coff.Header,
/// The optional header provides information to the loader.
/// While named optional it's not optional for the final binary
/// when building an image file (PE).
optional_header: Coff.OptionalHeader,
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

const number_of_data_directory = 16;
pub const dos_stub_size = @sizeOf(Coff.DosHeader) + @sizeOf(@TypeOf(dos_program));
comptime {
    std.debug.assert(@sizeOf(Coff.DosHeader) == 64);
}
/// Dos stub that prints "This program cannot be run in DOS mode."
/// This stub will be inserted at the start of the binary, before all other sections.
pub const dos_program = [_]u8{
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
    0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
    0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
    0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
    0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x24, 0x00, 0x00,
};

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

/// Creates a new binary file, overwriting any existing file with the corresponding name.
/// Then initializes all default values.
///
/// Cld has eclusive access to the output file, meaning it cannot be accessed by outside
/// processes until `deinit` is called and all resources are deallocated.
pub fn openPath(allocator: Allocator, path: []const u8, options: Options) !Cld {
    const file = try std.fs.cwd().createFile(path, .{ .lock = .Exclusive });
    const stat = try file.stat();
    const time_stamp = @divFloor(stat.ctime, std.time.ns_per_s);

    return Cld{
        .gpa = allocator,
        .name = path,
        .options = options,
        .file = file,
        .coff_header = .{
            .machine = std.coff.MachineType.X64, // TODO: Make this dynamic, based on target
            .number_of_sections = 0,
            .timedate_stamp = @truncate(u32, @intCast(u64, time_stamp)),
            .pointer_to_symbol_table = 0,
            .number_of_symbols = 0,
            .size_of_optional_header = 112 + @sizeOf(Coff.DataDirectory) * number_of_data_directory,
            .characteristics = 0,
        },
        .optional_header = .{
            .magic = 0x20b, // PE32+, TODO: Make this dynamic, based on target
            .major_version = 0,
            .minor_version = 0,
            .size_of_code = 0,
            .size_of_initialized_data = 0,
            .size_of_uninitialized_data = 0,
            .address_of_entry_point = 0,
            .base_of_code = 0,
            .image_base = 0,
            .section_alignment = 0,
            .file_alignment = 512,
            .major_os_version = 0,
            .minor_os_version = 0,
            .major_img_version = 0,
            .minor_img_version = 0,
            .major_sub_version = 0,
            .minor_sub_version = 0,
            .win32_version = 0,
            .size_of_image = 0,
            .size_of_headers = 0,
            .checksum = 0,
            .subsystem = 0,
            .dll_characteristics = 0,
            .size_of_stack_reserve = 0,
            .size_of_stack_commit = 0,
            .size_of_heap_reserve = 0,
            .size_of_heap_commit = 0,
            .loader_flags = 0,
            .number_of_rva_and_sizes = 0,
        },
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
    try emitImageFile(cld);
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
    var offset: u32 = dos_stub_size +
        @sizeOf(@TypeOf(Coff.pe_magic)) +
        @sizeOf(Coff.Header) +
        cld.coff_header.size_of_optional_header;

    log.debug("allocating sections, starting at offset: 0x{x:0>4}", .{offset});

    for (cld.section_headers.items) |hdr| {
        if (hdr.isGrouped()) {
            continue;
        }
        offset += 40; // each header takes up 40 bytes
        cld.coff_header.number_of_sections += 1;
    }

    // as we now have the full offset, we can start to visually allocate all sections
    // into the binary
    for (cld.section_headers.items) |*hdr| {
        hdr.pointer_to_raw_data = offset;
        offset += hdr.size_of_raw_data;

        const hdr_name = cld.getString(hdr.name);

        if (std.mem.eql(u8, hdr_name, ".text")) {
            cld.optional_header.base_of_code = hdr.pointer_to_raw_data;
        }
        // else if (std.mem.eql(u8, hdr_name, ".data")) {
        //     cld.optional_header.base_of_data = hdr.pointer_to_raw_data;
        // }

        if (hdr.characteristics & Coff.SectionHeader.flags.IMAGE_SCN_CNT_CODE != 0) {
            cld.optional_header.size_of_code += hdr.size_of_raw_data;
        } else if (hdr.characteristics & Coff.SectionHeader.flags.IMAGE_SCN_CNT_INITIALIZED_DATA != 0) {
            cld.optional_header.size_of_initialized_data += hdr.size_of_raw_data;
        } else if (hdr.characteristics & Coff.SectionHeader.flags.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0) {
            cld.optional_header.size_of_uninitialized_data += hdr.size_of_raw_data;
        }

        if (!hdr.isGrouped()) {
            log.debug("  allocated section '{s}' from 0x{x:0>8} to 0x{x:0>8}", .{
                cld.getString(hdr.name),
                hdr.pointer_to_raw_data,
                hdr.pointer_to_raw_data + hdr.size_of_raw_data,
            });
        }
    }

    cld.optional_header.size_of_headers = std.mem.alignForwardGeneric(u32, offset, 512);
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

fn emitImageFile(cld: *Cld) !void {
    var writer_list = std.ArrayList(u8).init(cld.gpa);
    defer writer_list.deinit();
    const writer = writer_list.writer();
    _ = writer;

    // no linker-errors, so update flags
    cld.coff_header.characteristics |= std.coff.IMAGE_FILE_EXECUTABLE_IMAGE;
    if (cld.optional_header.magic == 0x2b) {
        cld.coff_header.characteristics |= std.coff.IMAGE_FILE_LARGE_ADDRESS_AWARE;
    }

    try writeDosHeader(writer);
    try writeFileHeader(cld.coff_header, writer);
    try writeOptionalHeader(cld.*, writer);
    try writeSections(cld.*, writer);

    try cld.file.writevAll(&[_]std.os.iovec_const{
        .{ .iov_base = writer_list.items.ptr, .iov_len = writer_list.items.len },
    });
}

fn writeDosHeader(writer: anytype) !void {
    var header: Coff.DosHeader = std.mem.zeroInit(Coff.DosHeader, .{});
    header.magic = .{ 'M', 'Z' };
    header.used_bytes_last_page = dos_stub_size % 512;
    header.file_size_pages = try std.math.divCeil(u16, dos_stub_size, 512);
    header.header_size_paragraphs = @sizeOf(Coff.DosHeader) / 16;
    header.address_of_relocation_table = @sizeOf(Coff.DosHeader);
    header.address_of_header = dos_stub_size;

    // TODO: Byteswap the header when target compilation is big-endian
    try writer.writeAll(std.mem.asBytes(&header));
    try writer.writeAll(&dos_program);
}

fn writeFileHeader(header: Coff.Header, writer: anytype) !void {
    try writer.writeAll(&Coff.pe_magic);
    try writer.writeAll(std.mem.asBytes(&header));
}

fn writeOptionalHeader(cld: Cld, writer: anytype) !void {
    try writer.writeAll(std.mem.asBytes(&cld.optional_header));
    // TODO: Actually write to each directory when data is known
    var directories = [_]u8{0} ** (@sizeOf(Coff.DataDirectory) * number_of_data_directory);
    try writer.writeAll(&directories);
}

fn writeSections(cld: Cld, writer: anytype) !void {
    for (cld.section_headers.items) |hdr| {
        try writer.writeAll(&hdr.name);
        try writer.writeIntLittle(u32, hdr.virtual_size);
        try writer.writeIntLittle(u32, hdr.virtual_address);
        try writer.writeIntLittle(u32, hdr.size_of_raw_data);
        try writer.writeIntLittle(u32, hdr.pointer_to_raw_data);
        try writer.writeIntLittle(u32, hdr.pointer_to_relocations);
        try writer.writeIntLittle(u32, hdr.pointer_to_line_numbers);
        try writer.writeIntLittle(u16, hdr.number_of_relocations);
        try writer.writeIntLittle(u16, hdr.number_of_line_numbers);
        try writer.writeIntLittle(u32, hdr.characteristics);
    }

    var it = cld.atoms.valueIterator();
    while (it.next()) |last_atom| {
        var atom: *Atom = last_atom.*.getFirst();
        while (true) {
            const size = std.mem.alignForwardGeneric(u32, atom.size, atom.alignment);
            // TODO: Perform relocations before writing
            try writer.writeAll(atom.code.items);
            if (size > atom.size) {
                try writer.writeByteNTimes(0, size - atom.size);
            }
            atom = atom.next orelse break;
        }
    }
}
