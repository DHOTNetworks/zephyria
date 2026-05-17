// File: vm/loader/forge_loader.zig
// ELF parser for RISC-V binaries targeting ForgeVM.
// Supports both ELFCLASS32 (RV32IM) and ELFCLASS64 (RV64IM) little-endian executables.
//
// The ForgeVM sandbox uses a 32-bit address space (512 KB, addresses 0x00000000–0x0007FFFF).
// For ELF64 binaries the virtual addresses must fit in u32; RV64IM toolchains targeting the
// ForgeVM linker script emit low vaddrs (< 0x80000) so this constraint is always met for
// correctly built contracts.
//
// Supported:  ET_EXEC, ET_DYN (PIE), EM_RISCV, little-endian only.
// Unsupported: ELFCLASS64 with vaddrs > 0xFFFFFFFF (rejected with TooLarge).

const std = @import("std");
const sandbox = @import("../memory/sandbox.zig");

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

pub const ELF_MAGIC = [4]u8{ 0x7F, 'E', 'L', 'F' };
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1; // Little-endian

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_RISCV: u16 = 243;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_NOBITS: u32 = 8;

pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// ---------------------------------------------------------------------------
// ELF32 structures
// ---------------------------------------------------------------------------

pub const Elf32Header = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

pub const Elf32ProgramHeader = extern struct {
    p_type: u32,
    pOffset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
};

pub const Elf32SectionHeader = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u32,
    sh_addr: u32,
    sh_offset: u32,
    sh_size: u32,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u32,
    sh_entsize: u32,
};

// ---------------------------------------------------------------------------
// ELF64 structures
// NOTE: In ELF64 program headers p_flags is at offset 4 (before pOffset),
// which differs from ELF32 where p_flags is at offset 24 (after p_memsz).
// ---------------------------------------------------------------------------

pub const Elf64Header = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

pub const Elf64ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32, // NOTE: before pOffset in ELF64
    pOffset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

pub const Elf64SectionHeader = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

// ---------------------------------------------------------------------------
// Parse result types
// ---------------------------------------------------------------------------

pub const ParseError = error{
    InvalidMagic,
    NotElf32OrElf64,
    NotLittleEndian,
    NotExecutable,
    NotRiscV,
    NoCode,
    TooLarge,
    InvalidFormat,
    Overflow,
};

pub const LoadSegment = struct {
    vaddr: u32,
    data: []const u8,
    memsz: u32,
    writable: bool,
    executable: bool,
};

pub const ElfBinary = struct {
    entryPoint: u32,
    code: []const u8,
    initData: []const u8,
    codeVaddr: u32,
    dataVaddr: u32,
    segments: [8]LoadSegment,
    segmentCount: u8,
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse an ELF binary (ELFCLASS32 or ELFCLASS64) from raw bytes.
/// Returns slices into `data`; performs no heap allocation.
pub fn parse(data: []const u8) ParseError!ElfBinary {
    if (data.len < 20) return ParseError.InvalidFormat;
    if (!std.mem.eql(u8, data[0..4], &ELF_MAGIC)) return ParseError.InvalidMagic;
    if (data[5] != ELFDATA2LSB) return ParseError.NotLittleEndian;

    return switch (data[4]) {
        ELFCLASS32 => parse32(data),
        ELFCLASS64 => parse64(data),
        else => ParseError.NotElf32OrElf64,
    };
}

// ---------------------------------------------------------------------------
// ELF32 parser
// ---------------------------------------------------------------------------

fn parse32(data: []const u8) ParseError!ElfBinary {
    if (data.len < @sizeOf(Elf32Header)) return ParseError.InvalidFormat;
    const hdr: *align(1) const Elf32Header = @ptrCast(data[0..@sizeOf(Elf32Header)].ptr);
    if (hdr.e_type != ET_EXEC and hdr.e_type != ET_DYN) return ParseError.NotExecutable;
    if (hdr.e_machine != EM_RISCV) return ParseError.NotRiscV;

    var result = ElfBinary{
        .entryPoint = hdr.e_entry,
        .code = &[_]u8{},
        .initData = &[_]u8{},
        .codeVaddr = 0,
        .dataVaddr = 0,
        .segments = undefined,
        .segmentCount = 0,
    };

    if (hdr.e_phnum > 0 and hdr.e_phoff > 0) {
        var i: u16 = 0;
        while (i < hdr.e_phnum and result.segmentCount < 8) : (i += 1) {
            const ph_off = hdr.e_phoff + @as(u32, i) * @as(u32, hdr.e_phentsize);
            if (ph_off + @sizeOf(Elf32ProgramHeader) > data.len) break;
            const ph: *align(1) const Elf32ProgramHeader =
                @ptrCast(data[ph_off..][0..@sizeOf(Elf32ProgramHeader)].ptr);
            if (ph.p_type != PT_LOAD or ph.p_filesz == 0) continue;
            const seg_end = ph.pOffset + ph.p_filesz;
            if (seg_end > data.len) return ParseError.InvalidFormat;
            const exec = (ph.p_flags & PF_X) != 0;
            const writ = (ph.p_flags & PF_W) != 0;
            result.segments[result.segmentCount] = .{
                .vaddr = ph.p_vaddr,
                .data = data[ph.pOffset..seg_end],
                .memsz = ph.p_memsz,
                .writable = writ,
                .executable = exec,
            };
            result.segmentCount += 1;
            if (exec and result.code.len == 0) {
                result.code = data[ph.pOffset..seg_end];
                result.codeVaddr = ph.p_vaddr;
            } else if (!exec and result.initData.len == 0) {
                result.initData = data[ph.pOffset..seg_end];
                result.dataVaddr = ph.p_vaddr;
            }
        }
    }

    if (result.code.len == 0 and hdr.e_shnum > 0 and hdr.e_shoff > 0) {
        const strtab = getSectionOffset32(data, hdr, hdr.e_shstrndx) orelse
            return ParseError.InvalidFormat;
        var i: u16 = 0;
        while (i < hdr.e_shnum) : (i += 1) {
            const sh_off = hdr.e_shoff + @as(u32, i) * @as(u32, hdr.e_shentsize);
            if (sh_off + @sizeOf(Elf32SectionHeader) > data.len) break;
            const sh: *align(1) const Elf32SectionHeader =
                @ptrCast(data[sh_off..][0..@sizeOf(Elf32SectionHeader)].ptr);
            if (sh.sh_type != SHT_PROGBITS or sh.sh_size == 0) continue;
            const name = getSectionName(data, strtab, sh.sh_name) orelse continue;
            const sec_end = sh.sh_offset + sh.sh_size;
            if (sec_end > data.len) return ParseError.InvalidFormat;
            if (std.mem.eql(u8, name, ".text")) {
                result.code = data[sh.sh_offset..sec_end];
                result.codeVaddr = sh.sh_addr;
            } else if (std.mem.eql(u8, name, ".data") or std.mem.eql(u8, name, ".rodata")) {
                if (result.initData.len == 0) {
                    result.initData = data[sh.sh_offset..sec_end];
                    result.dataVaddr = sh.sh_addr;
                }
            }
        }
    }

    if (result.code.len == 0) return ParseError.NoCode;
    return result;
}

// ---------------------------------------------------------------------------
// ELF64 parser
// ---------------------------------------------------------------------------

fn parse64(data: []const u8) ParseError!ElfBinary {
    if (data.len < @sizeOf(Elf64Header)) return ParseError.InvalidFormat;
    const hdr: *align(1) const Elf64Header = @ptrCast(data[0..@sizeOf(Elf64Header)].ptr);
    if (hdr.e_type != ET_EXEC and hdr.e_type != ET_DYN) return ParseError.NotExecutable;
    if (hdr.e_machine != EM_RISCV) return ParseError.NotRiscV;
    if (hdr.e_entry > std.math.maxInt(u32)) return ParseError.TooLarge;

    var result = ElfBinary{
        .entryPoint = @truncate(hdr.e_entry),
        .code = &[_]u8{},
        .initData = &[_]u8{},
        .codeVaddr = 0,
        .dataVaddr = 0,
        .segments = undefined,
        .segmentCount = 0,
    };

    if (hdr.e_phnum > 0 and hdr.e_phoff > 0) {
        var i: u16 = 0;
        while (i < hdr.e_phnum and result.segmentCount < 8) : (i += 1) {
            const ph_off64 = hdr.e_phoff + @as(u64, i) * @as(u64, hdr.e_phentsize);
            if (ph_off64 + @sizeOf(Elf64ProgramHeader) > data.len) break;
            const ph_off: usize = @intCast(ph_off64);
            const ph: *align(1) const Elf64ProgramHeader =
                @ptrCast(data[ph_off..][0..@sizeOf(Elf64ProgramHeader)].ptr);
            if (ph.p_type != PT_LOAD or ph.p_filesz == 0) continue;
            if (ph.p_vaddr > sandbox.memorySize) return ParseError.TooLarge;
            if (ph.p_filesz > sandbox.memorySize) return ParseError.TooLarge;
            if (ph.p_memsz > sandbox.memorySize) return ParseError.TooLarge;
            if (ph.pOffset > data.len) return ParseError.InvalidFormat;
            const pOff: usize = @intCast(ph.pOffset);
            const pFsz: usize = @intCast(ph.p_filesz);
            const seg_end = pOff + pFsz;
            if (seg_end > data.len) return ParseError.InvalidFormat;
            const exec: bool = (ph.p_flags & PF_X) != 0;
            const writ: bool = (ph.p_flags & PF_W) != 0;
            const vaddr32: u32 = @truncate(ph.p_vaddr);
            const memsz32: u32 = @truncate(ph.p_memsz);
            result.segments[result.segmentCount] = .{
                .vaddr = vaddr32,
                .data = data[pOff..seg_end],
                .memsz = memsz32,
                .writable = writ,
                .executable = exec,
            };
            result.segmentCount += 1;
            if (exec and result.code.len == 0) {
                result.code = data[pOff..seg_end];
                result.codeVaddr = vaddr32;
            } else if (!exec and result.initData.len == 0) {
                result.initData = data[pOff..seg_end];
                result.dataVaddr = vaddr32;
            }
        }
    }

    if (result.code.len == 0 and hdr.e_shnum > 0 and hdr.e_shoff > 0) {
        const strtab = getSectionOffset64(data, hdr, hdr.e_shstrndx) orelse
            return ParseError.InvalidFormat;
        var i: u16 = 0;
        while (i < hdr.e_shnum) : (i += 1) {
            const sh_off64 = hdr.e_shoff + @as(u64, i) * @as(u64, hdr.e_shentsize);
            if (sh_off64 + @sizeOf(Elf64SectionHeader) > data.len) break;
            const sh_off: usize = @intCast(sh_off64);
            const sh: *align(1) const Elf64SectionHeader =
                @ptrCast(data[sh_off..][0..@sizeOf(Elf64SectionHeader)].ptr);
            if (sh.sh_type != SHT_PROGBITS or sh.sh_size == 0) continue;
            if (sh.sh_size > sandbox.memorySize) return ParseError.TooLarge;
            if (sh.sh_offset > data.len) return ParseError.InvalidFormat;
            const name = getSectionName(data, strtab, sh.sh_name) orelse continue;
            const sec_off: usize = @intCast(sh.sh_offset);
            const sec_size: usize = @intCast(sh.sh_size);
            const sec_end = sec_off + sec_size;
            if (sec_end > data.len) return ParseError.InvalidFormat;
            if (std.mem.eql(u8, name, ".text")) {
                result.code = data[sec_off..sec_end];
                result.codeVaddr = @truncate(sh.sh_addr);
            } else if (std.mem.eql(u8, name, ".data") or std.mem.eql(u8, name, ".rodata")) {
                if (result.initData.len == 0) {
                    result.initData = data[sec_off..sec_end];
                    result.dataVaddr = @truncate(sh.sh_addr);
                }
            }
        }
    }

    if (result.code.len == 0) return ParseError.NoCode;
    return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn getSectionOffset32(data: []const u8, hdr: *align(1) const Elf32Header, index: u16) ?u32 {
    if (index >= hdr.e_shnum) return null;
    const off = hdr.e_shoff + @as(u32, index) * @as(u32, hdr.e_shentsize);
    if (off + @sizeOf(Elf32SectionHeader) > data.len) return null;
    const sh: *align(1) const Elf32SectionHeader =
        @ptrCast(data[off..][0..@sizeOf(Elf32SectionHeader)].ptr);
    return sh.sh_offset;
}

fn getSectionOffset64(data: []const u8, hdr: *align(1) const Elf64Header, index: u16) ?u32 {
    if (index >= hdr.e_shnum) return null;
    const off64 = hdr.e_shoff + @as(u64, index) * @as(u64, hdr.e_shentsize);
    if (off64 + @sizeOf(Elf64SectionHeader) > data.len) return null;
    const off: usize = @intCast(off64);
    const sh: *align(1) const Elf64SectionHeader =
        @ptrCast(data[off..][0..@sizeOf(Elf64SectionHeader)].ptr);
    if (sh.sh_offset > std.math.maxInt(u32)) return null;
    return @truncate(sh.sh_offset);
}

fn getSectionName(data: []const u8, strtab_offset: u32, name_offset: u32) ?[]const u8 {
    const start = @as(usize, strtab_offset) + @as(usize, name_offset);
    if (start >= data.len) return null;
    const rest = data[start..];
    for (rest, 0..) |byte, idx| {
        if (byte == 0) return rest[0..idx];
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "reject non-ELF data" {
    const bad = [_]u8{ 0x00, 0x01, 0x02, 0x03 } ++ [_]u8{0} ** 60;
    try testing.expectError(ParseError.InvalidMagic, parse(&bad));
}

test "reject truncated data" {
    const short = [_]u8{ 0x7F, 'E', 'L', 'F' };
    try testing.expectError(ParseError.InvalidFormat, parse(&short));
}

test "reject unknown ELF class" {
    var d = [_]u8{0} ** 64;
    d[0] = 0x7F;
    d[1] = 'E';
    d[2] = 'L';
    d[3] = 'F';
    d[4] = 3; // unknown class
    d[5] = ELFDATA2LSB;
    try testing.expectError(ParseError.NotElf32OrElf64, parse(&d));
}

test "reject big-endian ELF" {
    var d = [_]u8{0} ** 64;
    d[0] = 0x7F;
    d[1] = 'E';
    d[2] = 'L';
    d[3] = 'F';
    d[4] = ELFCLASS32;
    d[5] = 2; // ELFDATA2MSB
    try testing.expectError(ParseError.NotLittleEndian, parse(&d));
}

test "reject non-RISCV ELF32" {
    var d = [_]u8{0} ** 64;
    d[0] = 0x7F;
    d[1] = 'E';
    d[2] = 'L';
    d[3] = 'F';
    d[4] = ELFCLASS32;
    d[5] = ELFDATA2LSB;
    std.mem.writeInt(u16, d[16..18], ET_EXEC, .little);
    std.mem.writeInt(u16, d[18..20], 3, .little); // x86
    try testing.expectError(ParseError.NotRiscV, parse(&d));
}

test "reject non-RISCV ELF64" {
    var d = [_]u8{0} ** 128;
    d[0] = 0x7F;
    d[1] = 'E';
    d[2] = 'L';
    d[3] = 'F';
    d[4] = ELFCLASS64;
    d[5] = ELFDATA2LSB;
    std.mem.writeInt(u16, d[16..18], ET_EXEC, .little);
    std.mem.writeInt(u16, d[18..20], 62, .little); // x86_64
    try testing.expectError(ParseError.NotRiscV, parse(&d));
}

test "ELF struct layout: Elf64Header is 64 bytes" {
    try testing.expectEqual(@as(usize, 64), @sizeOf(Elf64Header));
}

test "ELF struct layout: Elf64ProgramHeader is 56 bytes" {
    try testing.expectEqual(@as(usize, 56), @sizeOf(Elf64ProgramHeader));
}

test "ELF struct layout: Elf64SectionHeader is 64 bytes" {
    try testing.expectEqual(@as(usize, 64), @sizeOf(Elf64SectionHeader));
}

test "ELF struct layout: Elf32ProgramHeader is 32 bytes" {
    try testing.expectEqual(@as(usize, 32), @sizeOf(Elf32ProgramHeader));
}

test "ELF64 p_flags at offset 4 in program header (ELF spec)" {
    // Critical: p_flags is at byte 4 in ELF64 phdrs (differs from ELF32).
    try testing.expectEqual(@as(usize, 4), @offsetOf(Elf64ProgramHeader, "p_flags"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(Elf64ProgramHeader, "pOffset"));
}

test "ELF32 p_flags at offset 24 in program header" {
    try testing.expectEqual(@as(usize, 24), @offsetOf(Elf32ProgramHeader, "p_flags"));
}
