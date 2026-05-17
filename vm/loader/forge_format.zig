// File: vm/loader/forge_format.zig
// .forge contract package format for Zephyria.
// Bundles bytecode (ELF), ABI JSON, and metadata into a single deployable package.

const std = @import("std");

/// Magic bytes identifying a .forge file
pub const FORGE_MAGIC = [4]u8{ 'F', 'O', 'R', 'G' };

/// Current format version
pub const FORGE_VERSION: u16 = 2;

/// Package flags
pub const Flags = struct {
    pub const HAS_ABI: u16 = 0x0001;
    pub const HAS_METADATA: u16 = 0x0002;
    pub const HAS_CONSTRUCTOR: u16 = 0x0004;
    pub const HAS_SOURCE_MAP: u16 = 0x0008;
    pub const HAS_TYPE_TABLE: u16 = 0x0010;
    pub const HAS_PARALLEL_DESC: u16 = 0x0020;
};

/// .forge file header (fixed-size)
pub const ForgeHeader = extern struct {
    magic: [4]u8 = FORGE_MAGIC,
    version: u16 = FORGE_VERSION,
    flags: u16 = 0,
    bytecode_offset: u32 = 0,
    bytecode_size: u32 = 0,
    abi_offset: u32 = 0,
    abi_size: u32 = 0,
    metadata_offset: u32 = 0,
    metadata_size: u32 = 0,
    type_table_offset: u32 = 0,
    type_table_size: u32 = 0,
    parallel_descriptor_offset: u32 = 0,
    parallel_descriptor_size: u32 = 0,
    source_map_hash: [32]u8 = [_]u8{0} ** 32,
    code_hash: [32]u8 = [_]u8{0} ** 32,
};

pub const FormatError = error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidFormat,
    NoByteCode,
};

/// Parsed .forge package — slices reference the original data
pub const ForgePackage = struct {
    header: ForgeHeader,
    bytecode: []const u8,
    abi: ?[]const u8,
    metadata: ?[]const u8,
    type_table: ?[]const u8,
    parallel_descriptor: ?[]const u8,
};

/// Parse a .forge package from raw bytes.
pub fn parse(data: []const u8) FormatError!ForgePackage {
    if (data.len < @sizeOf(ForgeHeader)) return FormatError.InvalidFormat;

    const hdr: *align(1) const ForgeHeader = @ptrCast(data[0..@sizeOf(ForgeHeader)].ptr);

    if (!std.mem.eql(u8, &hdr.magic, &FORGE_MAGIC)) return FormatError.InvalidMagic;
    if (hdr.version != FORGE_VERSION) return FormatError.UnsupportedVersion;

    if (hdr.bytecode_size == 0) return FormatError.NoByteCode;
    const bc_end = hdr.bytecode_offset + hdr.bytecode_size;
    if (bc_end > data.len) return FormatError.InvalidFormat;
    const bytecode = data[hdr.bytecode_offset..bc_end];

    var abi: ?[]const u8 = null;
    if (hdr.flags & Flags.HAS_ABI != 0 and hdr.abi_size > 0) {
        const abi_end = hdr.abi_offset + hdr.abi_size;
        if (abi_end <= data.len) abi = data[hdr.abi_offset..abi_end];
    }

    var metadata: ?[]const u8 = null;
    if (hdr.flags & Flags.HAS_METADATA != 0 and hdr.metadata_size > 0) {
        const md_end = hdr.metadata_offset + hdr.metadata_size;
        if (md_end <= data.len) metadata = data[hdr.metadata_offset..md_end];
    }

    var type_table: ?[]const u8 = null;
    if (hdr.flags & Flags.HAS_TYPE_TABLE != 0 and hdr.type_table_size > 0) {
        const tt_end = hdr.type_table_offset + hdr.type_table_size;
        if (tt_end <= data.len) type_table = data[hdr.type_table_offset..tt_end];
    }

    var parallel_descriptor: ?[]const u8 = null;
    if (hdr.flags & Flags.HAS_PARALLEL_DESC != 0 and hdr.parallel_descriptor_size > 0) {
        const pd_end = hdr.parallel_descriptor_offset + hdr.parallel_descriptor_size;
        if (pd_end <= data.len) parallel_descriptor = data[hdr.parallel_descriptor_offset..pd_end];
    }

    return .{
        .header = hdr.*,
        .bytecode = bytecode,
        .abi = abi,
        .metadata = metadata,
        .type_table = type_table,
        .parallel_descriptor = parallel_descriptor,
    };
}

pub const BuildOptions = struct {
    abi: ?[]const u8 = null,
    metadata: ?[]const u8 = null,
    type_table: ?[]const u8 = null,
    parallel_descriptor: ?[]const u8 = null,
    source_map_hash: ?[32]u8 = null,
};

/// Build a .forge package from components.
pub fn build(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    options: BuildOptions,
) ![]u8 {
    const hdr_size: u32 = @sizeOf(ForgeHeader);
    var total_size: u32 = hdr_size;

    const bc_offset = total_size;
    total_size += @intCast(bytecode.len);

    var flags: u16 = 0;

    var abi_offset: u32 = 0;
    var abi_size: u32 = 0;
    if (options.abi) |a| {
        abi_offset = total_size;
        abi_size = @intCast(a.len);
        total_size += abi_size;
        flags |= Flags.HAS_ABI;
    }

    var md_offset: u32 = 0;
    var md_size: u32 = 0;
    if (options.metadata) |m| {
        md_offset = total_size;
        md_size = @intCast(m.len);
        total_size += md_size;
        flags |= Flags.HAS_METADATA;
    }

    var tt_offset: u32 = 0;
    var tt_size: u32 = 0;
    if (options.type_table) |tt| {
        tt_offset = total_size;
        tt_size = @intCast(tt.len);
        total_size += tt_size;
        flags |= Flags.HAS_TYPE_TABLE;
    }

    var pd_offset: u32 = 0;
    var pd_size: u32 = 0;
    if (options.parallel_descriptor) |pd| {
        pd_offset = total_size;
        pd_size = @intCast(pd.len);
        total_size += pd_size;
        flags |= Flags.HAS_PARALLEL_DESC;
    }

    if (options.source_map_hash != null) {
        flags |= Flags.HAS_SOURCE_MAP;
    }

    var code_hash: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(bytecode);
    hasher.final(&code_hash);

    const buf = try allocator.alloc(u8, total_size);

    const hdr = ForgeHeader{
        .flags = flags,
        .bytecode_offset = bc_offset,
        .bytecode_size = @intCast(bytecode.len),
        .abi_offset = abi_offset,
        .abi_size = abi_size,
        .metadata_offset = md_offset,
        .metadata_size = md_size,
        .type_table_offset = tt_offset,
        .type_table_size = tt_size,
        .parallel_descriptor_offset = pd_offset,
        .parallel_descriptor_size = pd_size,
        .source_map_hash = options.source_map_hash orelse [_]u8{0} ** 32,
        .code_hash = code_hash,
    };
    const hdr_bytes = std.mem.asBytes(&hdr);
    @memcpy(buf[0..hdr_bytes.len], hdr_bytes);

    @memcpy(buf[bc_offset..][0..bytecode.len], bytecode);

    if (options.abi) |a| @memcpy(buf[abi_offset..][0..a.len], a);
    if (options.metadata) |m| @memcpy(buf[md_offset..][0..m.len], m);
    if (options.type_table) |tt| @memcpy(buf[tt_offset..][0..tt.len], tt);
    if (options.parallel_descriptor) |pd| @memcpy(buf[pd_offset..][0..pd.len], pd);

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "build and parse round-trip" {
    const bytecode = &[_]u8{ 0x13, 0x00, 0x00, 0x00 }; // NOP
    const abi_json = "{\"functions\":[]}";
    const pkg = try build(testing.allocator, bytecode, .{ .abi = abi_json });
    defer testing.allocator.free(pkg);

    const parsed = try parse(pkg);
    try testing.expectEqualSlices(u8, bytecode, parsed.bytecode);
    try testing.expectEqualSlices(u8, abi_json, parsed.abi.?);
    try testing.expect(parsed.metadata == null);
}

test "parse rejects invalid magic" {
    var data = [_]u8{0} ** @sizeOf(ForgeHeader);
    try testing.expectError(FormatError.InvalidMagic, parse(&data));
}

test "parse rejects unsupported version" {
    var data = [_]u8{0} ** @sizeOf(ForgeHeader);
    data[0] = 'F';
    data[1] = 'O';
    data[2] = 'R';
    data[3] = 'G';
    data[4] = 99; // Bad version
    try testing.expectError(FormatError.UnsupportedVersion, parse(&data));
}

test "code hash is correct" {
    const bytecode = "hello bytecode";
    const pkg = try build(testing.allocator, bytecode, .{});
    defer testing.allocator.free(pkg);

    const parsed = try parse(pkg);

    var expected_hash: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(bytecode);
    hasher.final(&expected_hash);

    try testing.expectEqualSlices(u8, &expected_hash, &parsed.header.code_hash);
}

test "full package with new fields" {
    const bytecode = "fake bytecode";
    const type_table = "types";
    const parallel_desc = "parallel";
    var sm_hash: [32]u8 = [_]u8{0xAA} ** 32;

    const pkg = try build(testing.allocator, bytecode, .{
        .type_table = type_table,
        .parallel_descriptor = parallel_desc,
        .source_map_hash = sm_hash,
    });
    defer testing.allocator.free(pkg);

    const parsed = try parse(pkg);
    try testing.expectEqualSlices(u8, type_table, parsed.type_table.?);
    try testing.expectEqualSlices(u8, parallel_desc, parsed.parallel_descriptor.?);
    try testing.expectEqualSlices(u8, &sm_hash, &parsed.header.source_map_hash);
    try testing.expect((parsed.header.flags & Flags.HAS_SOURCE_MAP) != 0);
}
