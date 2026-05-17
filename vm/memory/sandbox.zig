// File: vm/memory/sandbox.zig
// Sandboxed linear memory for ForgeVM contract execution.
// Enforces per-region permissions (Code=R-X, Heap=RW, Stack=RW, Calldata=R, Return=RW).
// Total per-instance: ~392 KB — fits in L2 cache.

const std = @import("std");

/// Memory access permissions
pub const Permission = enum {
    readExecute, // Code region: read + execute, no write
    readWrite, // Heap, Stack, Return regions
    readOnly, // Calldata region
};

/// A named memory region with offset, size, and permission
pub const Region = struct {
    start: u32,
    end: u32, // inclusive
    perm: Permission,
    name: []const u8,
};

/// Memory region layout — matches architecture doc exactly.
pub const REGIONS = [_]Region{
    .{ .start = 0x0000_0000, .end = 0x0001_FFFF, .perm = .readExecute, .name = "Code" }, // 128 KB
    .{ .start = 0x0002_0000, .end = 0x0005_FFFF, .perm = .readWrite, .name = "Heap" }, // 256 KB
    .{ .start = 0x0006_0000, .end = 0x0006_FFFF, .perm = .readWrite, .name = "Stack" }, // 64 KB
    .{ .start = 0x0007_0000, .end = 0x0007_3FFF, .perm = .readOnly, .name = "Calldata" }, // 16 KB
    .{ .start = 0x0007_4000, .end = 0x0007_7FFF, .perm = .readWrite, .name = "Return" }, // 16 KB
    .{ .start = 0x0007_8000, .end = 0x0007_FFFF, .perm = .readWrite, .name = "Scratch" }, // 32 KB
};

/// Total memory size (512 KB)
pub const memorySize: u32 = 0x0008_0000;

/// Code region constants
pub const codeStart: u32 = 0x0000_0000;
pub const codeEnd: u32 = 0x0001_FFFF;
pub const codeSize: u32 = 0x0002_0000; // 128 KB

/// Heap region constants
pub const heapStart: u32 = 0x0002_0000;
pub const heapEnd: u32 = 0x0005_FFFF;

/// Stack region constants
pub const stackStart: u32 = 0x0006_0000;
pub const stackEnd: u32 = 0x0006_FFFF;
/// stackTop must be 8-byte aligned so the compiler prologue's first
/// SD (store doubleword) after ADDI sp, sp, -N lands on an aligned address.
/// 0x0006_FFFC was only 4-byte aligned → storeDoubleword fault on every call.
pub const stackTop: u32 = 0x0006_FFF8;

/// Calldata region constants
pub const calldataStart: u32 = 0x0007_0000;
pub const calldataEnd: u32 = 0x0007_3FFF;
pub const calldataSize: u32 = 0x0000_4000; // 16 KB

/// Return data region constants
pub const returnStart: u32 = 0x0007_4000;
pub const returnEnd: u32 = 0x0007_7FFF;
pub const returnSize: u32 = 0x0000_4000; // 16 KB

/// Scratch region constants
pub const scratchStart: u32 = 0x0007_8000;
pub const scratchEnd: u32 = 0x0007_FFFF;

pub const MemoryError = error{
    SegFault, // Access outside any valid region
    PermissionDenied, // Write to read-only or read-execute region
    MisalignedAccess, // Unaligned word/halfword access
};

/// Sandboxed linear memory with bounds-checked, permission-enforced access.
pub const SandboxMemory = struct {
    backing: []u8,
    allocator: std.mem.Allocator,
    owned: bool, // whether we own the backing allocation

    /// Create a new sandbox memory instance.
    pub fn init(allocator: std.mem.Allocator) !SandboxMemory {
        const backing = try allocator.alloc(u8, memorySize);
        @memset(backing, 0);
        return .{
            .backing = backing,
            .allocator = allocator,
            .owned = true,
        };
    }

    /// Create sandbox memory from existing buffer (no allocation).
    pub fn initFromBuffer(buf: []u8) SandboxMemory {
        return .{
            .backing = buf,
            .allocator = undefined,
            .owned = false,
        };
    }

    pub fn deinit(self: *SandboxMemory) void {
        if (self.owned) {
            self.allocator.free(self.backing);
        }
    }

    /// Reset all writable memory regions to zero without dealloc/realloc.
    /// Used by VM instance pool to reuse sandbox memory across TXs.
    /// Only clears heap, stack, calldata, and return regions — code region is overwritten by loadCode.
    pub fn reset(self: *SandboxMemory) void {
        // Clear heap (256 KB)
        @memset(self.backing[heapStart .. heapEnd + 1], 0);
        // Clear stack (64 KB)
        @memset(self.backing[stackStart .. stackEnd + 1], 0);
        // Clear calldata (16 KB)
        @memset(self.backing[calldataStart .. calldataEnd + 1], 0);
        // Clear return data (16 KB)
        @memset(self.backing[returnStart .. returnEnd + 1], 0);
        // Clear scratch (32 KB)
        @memset(self.backing[scratchStart .. scratchEnd + 1], 0);
    }

    // -------------------------------------------------------------------
    // Load operations (with bounds + permission checks)
    // -------------------------------------------------------------------

    /// Load a 32-bit word from the given address.
    /// Address must be 4-byte aligned.
    pub fn loadWord(self: *const SandboxMemory, addr: u64) MemoryError!u32 {
        if (addr & 3 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 4, .read);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..4];
        return std.mem.readInt(u32, slice, .little);
    }

    pub fn loadDoubleword(self: *const SandboxMemory, addr: u64) MemoryError!u64 {
        if (addr & 7 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 8, .read);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..8];
        return std.mem.readInt(u64, slice, .little);
    }

    /// Load a 16-bit halfword (sign-extended to i32, returned as u32).
    /// Address must be 2-byte aligned.
    pub fn loadHalfword(self: *const SandboxMemory, addr: u64) MemoryError!u16 {
        if (addr & 1 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 2, .read);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..2];
        return std.mem.readInt(u16, slice, .little);
    }

    /// Load a single byte.
    pub fn loadByte(self: *const SandboxMemory, addr: u64) MemoryError!u8 {
        try self.checkAccess(addr, 1, .read);
        const addr32: u32 = @truncate(addr);
        return self.backing[addr32];
    }

    // -------------------------------------------------------------------
    // Store operations (with bounds + permission checks)
    // -------------------------------------------------------------------

    /// Store a 32-bit word at the given address.
    /// Address must be 4-byte aligned.
    pub fn storeWord(self: *SandboxMemory, addr: u64, value: u32) MemoryError!void {
        if (addr & 3 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 4, .write);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..4];
        std.mem.writeInt(u32, slice, value, .little);
    }

    pub fn storeDoubleword(self: *SandboxMemory, addr: u64, value: u64) MemoryError!void {
        if (addr & 7 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 8, .write);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..8];
        std.mem.writeInt(u64, slice, value, .little);
    }

    /// Store a 16-bit halfword at the given address.
    /// Address must be 2-byte aligned.
    pub fn storeHalfword(self: *SandboxMemory, addr: u64, value: u16) MemoryError!void {
        if (addr & 1 != 0) return MemoryError.MisalignedAccess;
        try self.checkAccess(addr, 2, .write);
        const addr32: u32 = @truncate(addr);
        const slice = self.backing[addr32..][0..2];
        std.mem.writeInt(u16, slice, value, .little);
    }

    /// Store a single byte at the given address.
    pub fn storeByte(self: *SandboxMemory, addr: u64, value: u8) MemoryError!void {
        try self.checkAccess(addr, 1, .write);
        const addr32: u32 = @truncate(addr);
        self.backing[addr32] = value;
    }

    // -------------------------------------------------------------------
    // Bulk operations (for loading code, calldata, reading return data)
    // -------------------------------------------------------------------

    /// Write a slice of bytes into the backing memory at the given offset.
    /// Bypasses permission checks — used for initial setup only.
    pub fn loadCode(self: *SandboxMemory, code: []const u8) MemoryError!void {
        if (code.len > codeSize) return MemoryError.SegFault;
        @memcpy(self.backing[codeStart..][0..code.len], code);
    }

    /// Write calldata into the calldata region.
    pub fn loadCalldata(self: *SandboxMemory, calldata: []const u8) MemoryError!void {
        if (calldata.len > calldataSize) return MemoryError.SegFault;
        @memcpy(self.backing[calldataStart..][0..calldata.len], calldata);
    }

    /// Read return data from the return region.
    pub fn getReturnData(self: *const SandboxMemory, offset: u64, len: u64) MemoryError![]const u8 {
        if (offset > returnEnd or len > returnSize) return MemoryError.SegFault;
        const offset32: u32 = @truncate(offset);
        const len32: u32 = @truncate(len);
        const start = returnStart + offset32;
        const end = start + len32;
        if (end > returnEnd + 1) return MemoryError.SegFault;
        return self.backing[start..end];
    }

    /// Get a raw slice of underlying memory (for syscall data transfer).
    /// This performs read permission checks.
    pub fn getSlice(self: *const SandboxMemory, addr: u64, len: u64) MemoryError![]const u8 {
        try self.checkAccess(addr, len, .read);
        const addr32: u32 = @truncate(addr);
        const len32: u32 = @truncate(len);
        return self.backing[addr32..][0..len32];
    }

    /// Get a mutable raw slice (for syscall data transfer).
    /// This performs write permission checks.
    pub fn getSliceMut(self: *SandboxMemory, addr: u64, len: u64) MemoryError![]u8 {
        try self.checkAccess(addr, len, .write);
        const addr32: u32 = @truncate(addr);
        const len32: u32 = @truncate(len);
        return self.backing[addr32..][0..len32];
    }

    /// Get a direct pointer to a 32-byte aligned region (zero-copy read).
    /// Used by SLOAD/SSTORE to avoid memcpy for 32-byte key/value operations.
    /// Caller must ensure the address is within a readable region.
    pub fn getAligned32(self: *const SandboxMemory, addr: u64) MemoryError!*const [32]u8 {
        try self.checkAccess(addr, 32, .read);
        const addr32: u32 = @truncate(addr);
        return self.backing[addr32..][0..32];
    }

    /// Get a mutable direct pointer to a 32-byte aligned region (zero-copy write).
    /// Used by SLOAD/SSTORE result writes to avoid memcpy.
    pub fn getAligned32Mut(self: *SandboxMemory, addr: u64) MemoryError!*[32]u8 {
        try self.checkAccess(addr, 32, .write);
        const addr32: u32 = @truncate(addr);
        return self.backing[addr32..][0..32];
    }

    // -------------------------------------------------------------------
    // Access checking
    // -------------------------------------------------------------------

    const AccessMode = enum { read, write };

    fn checkAccess(self: *const SandboxMemory, addr: u64, size: u64, mode: AccessMode) MemoryError!void {
        _ = self;
        if (size == 0) return;
        const endAddr = addr +| (size - 1); // saturating add
        if (endAddr >= memorySize) return MemoryError.SegFault;

        // Fast-path: direct address range comparisons (replaces region loop scan).
        // Ordered by access frequency: Heap > Stack > Code > Return > Calldata.
        // This eliminates a 5-iteration loop on every memory access.

        // Heap (256 KB) — most common access pattern
        if (addr >= heapStart and endAddr <= heapEnd) {
            return; // Heap is RW — always OK
        }

        // Stack (64 KB) — second most common
        if (addr >= stackStart and endAddr <= stackEnd) {
            return; // Stack is RW — always OK
        }

        // Code (64 KB) — read/execute only
        if (addr >= codeStart and endAddr <= codeEnd) {
            if (mode == .write) return MemoryError.PermissionDenied;
            return;
        }

        // Return data (16 KB) — writable
        if (addr >= returnStart and endAddr <= returnEnd) {
            return; // Return is RW
        }

        // Calldata (16 KB) — read-only
        if (addr >= calldataStart and endAddr <= calldataEnd) {
            if (mode == .write) return MemoryError.PermissionDenied;
            return;
        }

        // Scratch data (32 KB) — writable
        if (addr >= scratchStart and endAddr <= scratchEnd) {
            return;
        }

        // Address doesn't fall within any region
        return MemoryError.SegFault;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "init and deinit" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    try testing.expectEqual(@as(usize, memorySize), mem.backing.len);
}

test "load/store word in heap" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    try mem.storeWord(heapStart, 0xDEADBEEF);
    const val = try mem.loadWord(heapStart);
    try testing.expectEqual(@as(u32, 0xDEADBEEF), val);
}

test "load/store byte in heap" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    try mem.storeByte(heapStart + 100, 0x42);
    const val = try mem.loadByte(heapStart + 100);
    try testing.expectEqual(@as(u8, 0x42), val);
}

test "load/store halfword in stack" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    try mem.storeHalfword(stackStart, 0xBEEF);
    const val = try mem.loadHalfword(stackStart);
    try testing.expectEqual(@as(u16, 0xBEEF), val);
}

test "write to code region fails" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const result = mem.storeWord(codeStart, 0x12345678);
    try testing.expectError(MemoryError.PermissionDenied, result);
}

test "write to calldata region fails" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const result = mem.storeByte(calldataStart, 0xFF);
    try testing.expectError(MemoryError.PermissionDenied, result);
}

test "read from code region succeeds" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    // Load code bypasses permissions
    try mem.loadCode(&[_]u8{ 0x13, 0x00, 0x00, 0x00 }); // NOP
    const val = try mem.loadWord(codeStart);
    try testing.expectEqual(@as(u32, 0x00000013), val);
}

test "access beyond memory size returns SegFault" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const result = mem.loadByte(memorySize);
    try testing.expectError(MemoryError.SegFault, result);
}

test "misaligned word access returns error" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const result = mem.loadWord(heapStart + 1);
    try testing.expectError(MemoryError.MisalignedAccess, result);
}

test "misaligned halfword access returns error" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const result = mem.loadHalfword(heapStart + 1);
    try testing.expectError(MemoryError.MisalignedAccess, result);
}

test "loadCalldata and read back" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    const cd = [_]u8{ 0xA0, 0xB0, 0xC0, 0xD0 };
    try mem.loadCalldata(&cd);
    try testing.expectEqual(@as(u8, 0xA0), try mem.loadByte(calldataStart));
    try testing.expectEqual(@as(u8, 0xD0), try mem.loadByte(calldataStart + 3));
}

test "return region is writable" {
    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();
    try mem.storeWord(returnStart, 0x12345678);
    const val = try mem.loadWord(returnStart);
    try testing.expectEqual(@as(u32, 0x12345678), val);
}
