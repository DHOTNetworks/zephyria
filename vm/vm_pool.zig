// File: vm/vm_pool.zig
// Pre-allocated VM instance pool for high-throughput execution.
// Eliminates per-TX allocation overhead (alloc + memset of 640KB sandbox).
//
// Design:
//   - Lock-Free / Low-Contention sharded architecture (MAX_SHARDS = 128)
//   - Each thread hashes to a local shard for O(1) uncontended acquire
//   - Work stealing implemented for load spikes
//   - CodeCache uses LRU with a Read-Write Lock for thread safety

const std = @import("std");
const sandbox = @import("memory/sandbox.zig");
const threaded_executor = @import("core/threaded_executor.zig");

pub const SandboxMemory = sandbox.SandboxMemory;
pub const DecodedInsn = threaded_executor.DecodedInsn;

pub const MAX_SHARDS: usize = 128;

pub const PoolConfig = struct {
    pool_size: u32 = 32,
    max_overflow: u32 = 64,
    code_cache_size: u32 = 100,
};

pub const CachedCode = struct {
    decoded_insns: []const DecodedInsn,
    insn_count: u32,
    code_len: u32,
    last_access: u64,
};

pub const CodeCacheStats = struct {
    lookups: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    entries: u32 = 0,
};

pub const PoolStats = struct {
    total_acquires: u64 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    total_releases: u64 = 0,
    peak_checked_out: u32 = 0,
};

pub const PoolShard = struct {
    mutex: std.Thread.Mutex = .{},
    free_list: std.ArrayListUnmanaged(*SandboxMemory) = .empty,
    all_buffers: std.ArrayListUnmanaged(*SandboxMemory) = .empty,
    checked_out: u32 = 0,
    stats: PoolStats = .{},

    pub fn init(_: std.mem.Allocator) PoolShard {
        return .{};
    }

    pub fn deinit(self: *PoolShard, allocator: std.mem.Allocator) void {
        for (self.all_buffers.items) |buf| {
            buf.deinit();
            allocator.destroy(buf);
        }
        self.all_buffers.deinit(allocator);
        self.free_list.deinit(allocator);
    }

    pub fn tryAcquire(self: *PoolShard) ?*SandboxMemory {
        if (!self.mutex.tryLock()) return null; // non-blocking acquire
        defer self.mutex.unlock();

        self.stats.total_acquires += 1;
        if (self.free_list.items.len > 0) {
            const mem = self.free_list.items[self.free_list.items.len - 1];
            self.free_list.items.len -= 1;
            mem.reset();
            self.checked_out += 1;
            self.stats.cache_hits += 1;
            if (self.checked_out > self.stats.peak_checked_out) {
                self.stats.peak_checked_out = self.checked_out;
            }
            return mem;
        }
        self.stats.cache_misses += 1;
        return null;
    }

    pub fn forceAcquire(self: *PoolShard) ?*SandboxMemory {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.stats.total_acquires += 1;
        if (self.free_list.items.len > 0) {
            const mem = self.free_list.items[self.free_list.items.len - 1];
            self.free_list.items.len -= 1;
            mem.reset();
            self.checked_out += 1;
            self.stats.cache_hits += 1;
            if (self.checked_out > self.stats.peak_checked_out) {
                self.stats.peak_checked_out = self.checked_out;
            }
            return mem;
        }
        self.stats.cache_misses += 1;
        return null;
    }

    pub fn release(self: *PoolShard, allocator: std.mem.Allocator, mem: *SandboxMemory) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_releases += 1;
        if (self.checked_out > 0) self.checked_out -= 1;
        self.free_list.append(allocator, mem) catch {};
    }
};

pub const CodeCache = struct {
    lock: std.Thread.RwLock = .{},
    map: std.AutoHashMap([32]u8, CachedCode),
    stats: CodeCacheStats = .{},
    access_counter: u64 = 0,
    config: PoolConfig,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) CodeCache {
        return .{
            .map = std.AutoHashMap([32]u8, CachedCode).init(allocator),
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CodeCache) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.decoded_insns);
        }
        self.map.deinit();
    }

    pub fn getDecodedCode(self: *CodeCache, code_hash: [32]u8) ?CachedCode {
        self.lock.lockShared();

        if (self.map.contains(code_hash)) {
            self.lock.unlockShared();

            // Acquire write lock to update LRU safely
            self.lock.lock();
            defer self.lock.unlock();

            self.stats.lookups += 1;

            if (self.map.getPtr(code_hash)) |mutable_entry| {
                self.stats.hits += 1;
                self.access_counter += 1;
                mutable_entry.last_access = self.access_counter;
                return mutable_entry.*;
            }
            return null;
        }

        self.lock.unlockShared();

        self.lock.lock();
        defer self.lock.unlock();
        self.stats.lookups += 1;
        self.stats.misses += 1;
        return null;
    }

    pub fn cacheDecodedCode(
        self: *CodeCache,
        code_hash: [32]u8,
        decoded_insns: []const DecodedInsn,
        insn_count: u32,
        code_len: u32,
    ) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.map.contains(code_hash)) return;

        if (self.stats.entries >= self.config.code_cache_size) {
            self.evictLRU();
        }

        const owned = self.allocator.dupe(DecodedInsn, decoded_insns) catch return;

        self.access_counter += 1;
        self.map.put(code_hash, .{
            .decoded_insns = owned,
            .insn_count = insn_count,
            .code_len = code_len,
            .last_access = self.access_counter,
        }) catch {
            self.allocator.free(owned);
            return;
        };
        self.stats.entries += 1;
    }

    fn evictLRU(self: *CodeCache) void {
        var min_access: u64 = std.math.maxInt(u64);
        var evict_key: ?[32]u8 = null;

        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_access < min_access) {
                min_access = entry.value_ptr.last_access;
                evict_key = entry.key_ptr.*;
            }
        }

        if (evict_key) |key| {
            if (self.map.fetchRemove(key)) |removed| {
                self.allocator.free(removed.value.decoded_insns);
                self.stats.entries -= 1;
                self.stats.evictions += 1;
            }
        }
    }
};

pub const VMPool = struct {
    shards: [MAX_SHARDS]PoolShard,
    code_cache: CodeCache,
    allocator: std.mem.Allocator,
    config: PoolConfig,

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) !VMPool {
        var pool = VMPool{
            .shards = undefined,
            .code_cache = CodeCache.init(allocator, config),
            .allocator = allocator,
            .config = config,
        };

        // Initialize shards
        var i: usize = 0;
        while (i < MAX_SHARDS) : (i += 1) {
            pool.shards[i] = PoolShard.init(allocator);
        }

        // Allocate buffers round-robin to shards
        var b: u32 = 0;
        while (b < config.pool_size) : (b += 1) {
            const mem_ptr = try allocator.create(SandboxMemory);
            mem_ptr.* = try SandboxMemory.init(allocator);
            const shard_idx = b % MAX_SHARDS;
            try pool.shards[shard_idx].free_list.append(allocator, mem_ptr);
            try pool.shards[shard_idx].all_buffers.append(allocator, mem_ptr);
        }

        return pool;
    }

    pub fn acquire(self: *VMPool) ?*SandboxMemory {
        const thread_id = std.Thread.getCurrentId();
        const thread_bytes = std.mem.asBytes(&thread_id);
        const shard_idx = std.hash.Wyhash.hash(0, thread_bytes) % MAX_SHARDS;

        // Fast path: thread-local tryAcquire
        if (self.shards[shard_idx].tryAcquire()) |mem| {
            return mem;
        }

        // Fast path: thread-local forceAcquire (blocks on its own shard)
        if (self.shards[shard_idx].forceAcquire()) |mem| {
            return mem;
        }

        // Slow path: Work stealing
        var i: usize = 0;
        while (i < MAX_SHARDS) : (i += 1) {
            if (i == shard_idx) continue;
            if (self.shards[i].tryAcquire()) |mem| {
                return mem;
            }
        }

        // Overflow allocation
        self.shards[shard_idx].mutex.lock();
        defer self.shards[shard_idx].mutex.unlock();

        const total = @as(u32, @intCast(self.shards[shard_idx].all_buffers.items.len));
        // Simple heuristic: distribute max_overflow evenly across shards
        const shard_max = (self.config.pool_size / MAX_SHARDS) + (self.config.max_overflow / MAX_SHARDS) + 1;

        if (total >= shard_max) {
            return null; // overflow limit
        }

        const mem_ptr = self.allocator.create(SandboxMemory) catch return null;
        mem_ptr.* = SandboxMemory.init(self.allocator) catch {
            self.allocator.destroy(mem_ptr);
            return null;
        };
        self.shards[shard_idx].all_buffers.append(self.allocator, mem_ptr) catch {
            mem_ptr.deinit();
            self.allocator.destroy(mem_ptr);
            return null;
        };
        self.shards[shard_idx].checked_out += 1;
        return mem_ptr;
    }

    pub fn release(self: *VMPool, mem: *SandboxMemory) void {
        const thread_id = std.Thread.getCurrentId();
        const thread_bytes = std.mem.asBytes(&thread_id);
        const shard_idx = std.hash.Wyhash.hash(0, thread_bytes) % MAX_SHARDS;
        self.shards[shard_idx].release(self.allocator, mem);
    }

    pub fn deinit(self: *VMPool) void {
        self.code_cache.deinit();
        var i: usize = 0;
        while (i < MAX_SHARDS) : (i += 1) {
            self.shards[i].deinit(self.allocator);
        }
    }

    pub fn getDecodedCode(self: *VMPool, code_hash: [32]u8) ?CachedCode {
        return self.code_cache.getDecodedCode(code_hash);
    }

    pub fn cacheDecodedCode(
        self: *VMPool,
        code_hash: [32]u8,
        decoded_insns: []const DecodedInsn,
        insn_count: u32,
        code_len: u32,
    ) void {
        self.code_cache.cacheDecodedCode(code_hash, decoded_insns, insn_count, code_len);
    }

    pub fn available(self: *const VMPool) usize {
        var total: usize = 0;
        var i: usize = 0;
        while (i < MAX_SHARDS) : (i += 1) {
            total += self.shards[i].free_list.items.len;
        }
        return total;
    }

    pub fn getStats(self: *const VMPool) PoolStats {
        var agg = PoolStats{};
        var i: usize = 0;
        while (i < MAX_SHARDS) : (i += 1) {
            // Note: inherently racy reads, fine for stats
            agg.total_acquires += self.shards[i].stats.total_acquires;
            agg.cache_hits += self.shards[i].stats.cache_hits;
            agg.cache_misses += self.shards[i].stats.cache_misses;
            agg.total_releases += self.shards[i].stats.total_releases;
            agg.peak_checked_out += self.shards[i].stats.peak_checked_out; // Sum of peaks
        }
        return agg;
    }

    pub fn getCodeCacheStats(self: *const VMPool) CodeCacheStats {
        return self.code_cache.stats;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "VMPool: init creates pool_size buffers distributed across shards" {
    var pool = try VMPool.init(testing.allocator, .{ .pool_size = 64, .max_overflow = 64 });
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 64), pool.available());
}

test "VMPool: acquire and release" {
    var pool = try VMPool.init(testing.allocator, .{ .pool_size = 2, .max_overflow = 0 });
    defer pool.deinit();

    const mem1 = pool.acquire().?;
    try testing.expectEqual(@as(usize, 1), pool.available());

    const mem2 = pool.acquire().?;
    try testing.expectEqual(@as(usize, 0), pool.available());

    // Pool exhausted, no overflow allowed (will fail to steal or allocate)
    try testing.expect(pool.acquire() == null);

    pool.release(mem1);
    try testing.expectEqual(@as(usize, 1), pool.available());

    pool.release(mem2);
    try testing.expectEqual(@as(usize, 2), pool.available());
}

test "VMPool: overflow allocation" {
    // Force a setup where overflow happens easily
    var pool = try VMPool.init(testing.allocator, .{ .pool_size = 1, .max_overflow = 128 });
    defer pool.deinit();

    const mem1 = pool.acquire().?;
    const mem2 = pool.acquire().?; // overflow allocation on thread-local shard
    try testing.expect(mem1 != mem2);

    pool.release(mem1);
    pool.release(mem2);
}

test "VMPool: statistics tracking" {
    var pool = try VMPool.init(testing.allocator, .{ .pool_size = 2, .max_overflow = 128 });
    defer pool.deinit();

    const m1 = pool.acquire().?;
    _ = pool.acquire().?;
    pool.release(m1);
    _ = pool.acquire().?;

    // Since thread_id is constant here, they all hit the same shard.
    const stats = pool.getStats();
    try testing.expectEqual(@as(u64, 3), stats.total_acquires);
    try testing.expectEqual(@as(u64, 2), stats.cache_hits);
    try testing.expectEqual(@as(u64, 1), stats.cache_misses); // overflow allocation
}
