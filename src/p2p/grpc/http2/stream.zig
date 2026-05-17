const std = @import("std");
const frame = @import("frame.zig");

pub const StreamState = enum {
    IDLE,
    RESERVED_LOCAL,
    RESERVED_REMOTE,
    OPEN,
    HALF_CLOSED_LOCAL,
    HALF_CLOSED_REMOTE,
    CLOSED,
};

pub const Stream = struct {
    id: u31,
    state: StreamState,
    window_size: u32,
    headers: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(id: u31, allocator: std.mem.Allocator) !Stream {
        return Stream{
            .id = id,
            .state = .IDLE,
            .window_size = 65535, // Default initial window size
            .headers = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Stream) void {
        var header_it = self.headers.iterator();
        while (header_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }

    pub fn addHeader(self: *Stream, name: []const u8, value: []const u8) !void {
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);
        const value_dup = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_dup);

        try self.headers.put(name_dup, value_dup);
    }
};
