const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Arena = @This();

// @TODO should there be an ability to reallocate or resize allocations?

memory: []u8,
current: usize,

pub const empty = Arena{
    .memory = &.{},
    .current = 0,
};

/// Initializes an arena with the given buffer. The user is responsible for
/// ensuring the lifetime of the buffer is larger than the lifetime of the arena.
pub fn initBuffer(buffer: []u8) Arena {
    return .{
        .memory = buffer,
        .current = 0,
    };
}

/// Initializes an arena with the given capacity and alignment. The allocator will
/// align to the target's page size if no alignment is provided.
/// arena.deinit(allocator) must be called if the memroy needs to be reclaimed.
pub fn init(
    alloc: Allocator,
    capacity: usize,
    comptime alignment_bytes: ?usize,
) Allocator.Error!Arena {
    const alignment =
        comptime if (alignment_bytes) |bytes|
            std.mem.Alignment.fromByteUnits(bytes)
        else
            std.mem.Alignment.fromByteUnits(std.heap.pageSize());
    const buffer = try alloc.alignedAlloc(u8, alignment, capacity);
    return .{
        .memory = @alignCast(buffer),
        .current = 0,
    };
}

pub fn deinit(self: *Arena, alloc: Allocator) void {
    alloc.free(self.memory);
    self.current = 0;
}

pub fn reset(self: *Arena, comptime zero_memory: bool) void {
    if (zero_memory) {
        @memset(self.memory, 0);
    }
    self.current = 0;
}

pub inline fn remainingCapacity(self: Arena) usize {
    return self.memory.len - self.current;
}

/// Returns a sub-arena with the remaining capacity. This should not be used at the same time as the arena
/// as it will cause overwrites. Instead push a buffer to the arena and use it to intialize another arena.
/// This is only useful if you want to pass a function a arena that will be reset after the call returns.
// @TODO is this useful/required?
// pub fn subArena(self: *Arena) Arena {
//     return .{
//         .memory = self.memory[self.current..],
//         .current = 0,
//     };
// }

pub fn pushAligned(
    self: *Arena,
    comptime T: type,
    comptime alignment: std.mem.Alignment,
) *align(alignment.toByteUnits()) T {
    const size = @sizeOf(T);
    const ptr: *align(alignment.toByteUnits()) T = @ptrCast(self.rawAlloc(size, alignment));
    return @ptrCast(ptr);
}

pub fn push(self: *Arena, comptime T: type) *T {
    const size = @sizeOf(T);
    const ptr: *T = @ptrCast(self.rawAlloc(size, .of(T)));
    return @ptrCast(ptr);
}

pub fn pushArray(self: *Arena, comptime T: type, length: usize) []T {
    const size = @sizeOf(T) * length;
    const ptr: [*]T = @ptrCast(self.rawAlloc(size, .of(T)));
    return ptr[0..length];
}

pub fn pushArrayAligned(
    self: *Arena,
    comptime T: type,
    comptime alignment: std.mem.Alignment,
    length: usize,
) []align(alignment.toByteUnits()) T {
    const size = @sizeOf(T) * length;
    const ptr: [*]align(alignment.toByteUnits()) T = @ptrCast(self.rawAlloc(size, alignment));
    return ptr[0..length];
}

pub fn pushString(self: *Arena, str: []const u8) []u8 {
    const size = str.len;
    const ptr: [*]u8 = @ptrCast(self.rawAlloc(size, .of(u8)));
    @memcpy(ptr[0..size], str);
    return ptr[0..size];
}

pub fn rawAlloc(self: *Arena, n: usize, alignment: std.mem.Alignment) [*]u8 {
    const ptr_align = alignment.toByteUnits();
    const base_address: usize = @intFromPtr(self.memory.ptr);
    const current_address: usize = base_address + self.current;
    const aligned_address: usize = (current_address + ptr_align - 1) & ~(ptr_align - 1);
    const aligned_index: usize = self.current + (aligned_address - current_address);
    const new_index: usize = aligned_index + n;

    assert(new_index <= self.memory.len);

    const result = self.memory[aligned_index..new_index];
    self.current = new_index;
    return result.ptr;
}

/// Returns an allocator interface that only allows allocations, no freeing or resizing.
pub fn allocator(self: *Arena) Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = zigAlloc,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = std.mem.Allocator.noFree,
        },
    };
}

fn zigAlloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    const self: *Arena = @ptrCast(@alignCast(ctx));
    return self.rawAlloc(n, alignment);
}

test "arena" {
    const buffer = try std.testing.allocator.alloc(u8, 2 * 1024 * 1024);
    defer std.testing.allocator.free(buffer);
    var arena = Arena.initBuffer(buffer);
    var rng_src = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng_src.random();
    var rounds: usize = 25;
    while (rounds > 0) {
        rounds -= 1;
        arena.reset(false);
        try std.testing.expectEqual(0, arena.current);
        const size = random.intRangeAtMost(usize, 0, arena.memory.len);
        var alloced_bytes: usize = 0;
        while (alloced_bytes < size) {
            const alloc_size = random.intRangeAtMost(usize, 1, arena.remainingCapacity());
            _ = arena.pushArray(u8, alloc_size);
            alloced_bytes += alloc_size;
        }
    }
}

test "arena from allocator" {
    var arena = try Arena.init(std.testing.allocator, 4 * 1024 * 1024, null);
    defer arena.deinit(std.testing.allocator);
    arena.reset(false);
    try std.testing.expectEqual(0, arena.current);
    const size = 1024 * 1024;
    const data = arena.pushArray(u8, size);
    try std.testing.expectEqual(size, arena.current);
    const ptr_int = @intFromPtr(data.ptr);
    const page_size = std.heap.pageSize();
    try std.testing.expectEqual(ptr_int, (ptr_int + page_size - 1) & ~(page_size - 1));
}
