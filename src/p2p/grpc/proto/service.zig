const std = @import("std");

pub const HelloRequest = struct {
    name: []const u8,

    pub fn encode(self: HelloRequest, writer: anytype) !void {
        try writer.writeString(1, self.name);
    }

    pub fn decode(reader: anytype) !HelloRequest {
        var name: ?[]const u8 = null;
        while (try reader.next()) |field| {
            switch (field.number) {
                1 => name = try field.string(),
                else => try field.skip(),
            }
        }
        return HelloRequest{ .name = name orelse "" };
    }
};

pub const HelloResponse = struct {
    message: []const u8,

    pub fn encode(self: HelloResponse, writer: anytype) !void {
        try writer.writeString(1, self.message);
    }

    pub fn decode(reader: anytype) !HelloResponse {
        var message: ?[]const u8 = null;
        while (try reader.next()) |field| {
            switch (field.number) {
                1 => message = try field.string(),
                else => try field.skip(),
            }
        }
        return HelloResponse{ .message = message orelse "" };
    }
};
