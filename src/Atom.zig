//! Atom represents the smallest type of linkage.
//! It can represent a function section, or the data belonging to
//! a global integer.
const Atom = @This();
const Cld = @import("Cld.zig");
const Relocation = @import("Coff.zig").Relocation;
const std = @import("std");

/// The index of the Symbol within the
/// object file that represents this Atom.
sym_index: u32,
/// Index of the object file this atom belongs to
file: u16,
/// Offset within the target section
offset: u32,
/// Alignment of this atom, this will always be equal
/// to the highest alignment within the same section when compiling to
/// a PE image file. In the case of a relocatable object file, the
/// alignment will target the Atom itself.
alignment: u32,
/// Relocations that have to be performed within this Atom,
/// meaning the `code` will be rewritten with values by the Relocation's target.
relocations: []const Relocation,
/// Code representing this atom.
code: std.ArrayListUnmanaged(u8) = .{},
/// The size of this atom, takes account for alignment
/// and can therefore be larger than `code`.
size: u32,

/// Next atom in relation to this atom.
/// This is the last atom when `next` is 'null'.
next: ?*Atom,
/// The previous atom in relation to this atom.
/// This is the first atom in the chain when `prev` is 'null'.
prev: ?*Atom,

/// Symbols by this Atom
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},
/// Symbol indexes containing an alias to this Atom's symbol
aliases: std.ArrayListUnmanaged(u32) = .{},

pub const SymbolAtOffset = struct {
    sym_index: u32,
    offset: u32,
};

/// Allocates memory for an `Atom` and initializes an instance
/// with default values. Memory is owned by the caller.
pub fn create(gpa: std.mem.Allocator) !*Atom {
    const atom = try gpa.create(Atom);
    atom.* = .{
        .sym_index = 0,
        .file = 0,
        .offset = 0,
        .alignment = 0,
        .relocations = &.{},
        .size = 0,
        .next = null,
        .prev = null,
    };
    return atom;
}

/// Frees all resources contained by this `Atom`.
pub fn destroy(atom: *Atom, gpa: std.mem.Allocator) void {
    atom.code.deinit(gpa);
    atom.contained.deinit(gpa);
    atom.aliases.deinit(gpa);
    gpa.destroy(atom);
}

/// Returns the first `Atom` from a given atom
pub fn getFirst(atom: *Atom) *Atom {
    var tmp = atom;
    while (tmp.prev) |prev| tmp = prev;
    return tmp;
}

/// Returns the symbol location for the given Atom.
pub fn symLoc(atom: Atom) Cld.SymbolWithLoc {
    return .{ .index = atom.sym_index, .file = atom.file };
}
