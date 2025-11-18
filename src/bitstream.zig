const std = @import("std");
const assert = std.debug.assert;

const BitStream = @This();

buffer: []const u8,
bit_index: usize,

pub const empty: BitStream = .{
    .buffer = &.{},
    .bit_index = 0,
};

pub fn init(buffer: []const u8) BitStream {
    return .{
        .buffer = buffer,
        .bit_index = 0,
    };
}

pub fn reset(self: *BitStream) void {
    self.bit_index = 0;
}

pub fn read(self: *const BitStream, bits: u7) u64 {
    // TODO: Can we have arbitrary bit widths greater than 64?
    // @TODO If we reach the end of packet we need to return -1 as u32
    // TODO: Should we provide the ability to provide a return type?
    assert(bits <= 64);
    var result: u64 = 0;

    var current_bit_index = self.bit_index;
    var bit_index_in_byte: u3 = @intCast(current_bit_index & 7);

    const remaining_bits = (self.buffer.len - (current_bit_index >> 3)) * 8 - bit_index_in_byte;
    assert(bits <= remaining_bits);

    var bits_left: u7 = bits;
    while (bits_left > 0) {
        if (bits_left <= 8 - @as(usize, @intCast(bit_index_in_byte))) {
            const mask = ~@as(u64, 0) >> @truncate(64 - bits_left);
            result |= (@as(u64, self.buffer[current_bit_index >> 3] >> bit_index_in_byte) & mask) << @truncate(bits - bits_left);
            break;
        }
        result |= (@as(u64, self.buffer[current_bit_index >> 3] >> bit_index_in_byte)) << @truncate(bits - bits_left);
        current_bit_index += 8 - @as(u7, @intCast(bit_index_in_byte));
        bits_left -= 8 - @as(u7, @intCast(bit_index_in_byte));
        bit_index_in_byte = 0;
    }
    return result;
}

pub fn consume(self: *BitStream, bits: u7) u64 {
    const result = self.read(bits);
    self.bit_index += bits;
    return result;
}

test "bitstream" {
    const buffer = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    var bitstream = BitStream.init(buffer[0..]);
    try std.testing.expectEqual(@as(u64, 0x01), bitstream.read(8));
    try std.testing.expectEqual(@as(u64, 0x01), bitstream.read(5));
    try std.testing.expectEqual(@as(u64, 0x0807060504030201), bitstream.read(64));
    // Try consuming bits
    bitstream.reset();
    try std.testing.expectEqual(@as(u64, 0x01), bitstream.consume(5));
    try std.testing.expectEqual(@as(u64, 16), bitstream.read(8));
}
