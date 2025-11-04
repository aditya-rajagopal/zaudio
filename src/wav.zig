const std = @import("std");
const assert = std.debug.assert;

pub const WavData = struct {
    /// Raw data
    data: []u8,
    /// Format data of the wav file
    format: Format,

    pub const Format = struct {
        /// The audio format of the wav file (PCM, IEEE_FLOAT, etc.)
        audio_format: AudioFormat,
        /// The number of channels in the wav file. Data is interleaved.
        /// For example if there are 4 channles the data will be
        /// [c0_0, c1_0, c2_0, c3_0, c0_1, c1_1, c2_1, c3_1, ...]
        num_channels: u16,
        /// The frequency of the wav file in Hz (samples per second)
        frequency: u32,
        /// The number of bytes per second: Frequency * block align
        byte_per_second: u32,
        /// The number of bytes per block: num_channels * bits_per_sample / 8
        block_align: u16,
        /// The resolution of each sample in bits.
        bits_per_sample: u16,
    };

    // TODO: Add more audio formats
    const AudioFormat = enum(u16) {
        pcm = 1,
        ieee_754_float = 3,
    };
};

// TODO: Use IO interface maybe?
// TODO: Do we want to parse chunks other than the data and format chunks?
pub fn decode(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!WavData {
    assert(data.len >= @sizeOf(MasterRIFFChunk));
    const wav_header: *const MasterRIFFChunk = @ptrCast(@alignCast(data[0..@sizeOf(MasterRIFFChunk)].ptr));

    assert(wav_header.file_type_block_id == MasterRIFFChunk.block_id);
    assert(wav_header.format == MasterRIFFChunk.format_id);

    var read_head: []const u8 = data[@sizeOf(MasterRIFFChunk)..];

    const state: ReaderState = .parse_next_chunk_header;

    var found_format_chunk: bool = false;
    var result: WavData = undefined;
    var current_chunk_header: *const ChunkHeader = undefined;

    loop: switch (state) {
        .parse_next_chunk_header => {
            assert(read_head.len >= @sizeOf(ChunkHeader));
            current_chunk_header = @ptrCast(@alignCast(read_head[0..@sizeOf(ChunkHeader)].ptr));
            read_head = read_head[@sizeOf(ChunkHeader)..];

            switch (current_chunk_header.block_id.toInt()) {
                FormatChunk.block_id.toInt() => continue :loop .parse_format_chunk,
                DataChunk.block_id.toInt() => continue :loop .parse_data_chunk,
                else => {
                    // TODO(adi): Do we want to log this?
                    assert(read_head.len > @sizeOf(ChunkHeader) + current_chunk_header.block_size);
                    read_head = read_head[@sizeOf(ChunkHeader) + current_chunk_header.block_size ..];
                    continue :loop .parse_next_chunk_header;
                },
            }
        },
        .parse_format_chunk => {
            assert(!found_format_chunk);
            found_format_chunk = true;
            assert(read_head.len >= @sizeOf(FormatChunk));
            const format_chunk: *const FormatChunk = @ptrCast(@alignCast(read_head[0..@sizeOf(FormatChunk)].ptr));
            result.format = WavData.Format{
                .audio_format = format_chunk.audio_format,
                .num_channels = format_chunk.num_channels,
                .frequency = format_chunk.frequency,
                .byte_per_second = format_chunk.byte_per_second,
                .block_align = format_chunk.byte_per_block,
                .bits_per_sample = format_chunk.bits_per_sample,
            };

            assert(read_head.len >= current_chunk_header.block_size);
            read_head = read_head[current_chunk_header.block_size..];

            continue :loop .parse_next_chunk_header;
        },
        .parse_data_chunk => {
            // NOTE: Cant get to data chunk without having parsed the format chunk first
            assert(found_format_chunk);
            // TODO(adi): Can a wav file contain more than one data chunk?
            assert(read_head.len >= current_chunk_header.block_size);
            result.data = try allocator.alloc(u8, current_chunk_header.block_size);
            @memcpy(result.data, read_head[0..current_chunk_header.block_size]);
            return result;
        },
    }
    unreachable;
}

pub fn encode(allocator: std.mem.Allocator, wav_data: WavData) std.mem.Allocator.Error![]u8 {
    // TODO: Incorporate IO interface to direclty output to a file?
    const data_len: u32 = @intCast(wav_data.data.len);
    const total_size: u32 =
        @sizeOf(MasterRIFFChunk) + @sizeOf(ChunkHeader) +
        @sizeOf(FormatChunk) + @sizeOf(ChunkHeader) + data_len;
    const result = try allocator.alloc(u8, total_size);

    var builder = std.ArrayListUnmanaged(u8).initBuffer(result);
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&MasterRIFFChunk.block_id.toInt()));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&total_size));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&MasterRIFFChunk.format_id.toInt()));

    builder.appendSliceAssumeCapacity(std.mem.asBytes(&FormatChunk.block_id.toInt()));
    const format_chunk_size: u32 = @sizeOf(FormatChunk);
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&format_chunk_size));

    const audio_format: u16 = @intFromEnum(wav_data.format.audio_format);
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&audio_format));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&wav_data.format.num_channels));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&wav_data.format.frequency));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&wav_data.format.byte_per_second));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&wav_data.format.block_align));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&wav_data.format.bits_per_sample));

    builder.appendSliceAssumeCapacity(std.mem.asBytes(&DataChunk.block_id.toInt()));
    builder.appendSliceAssumeCapacity(std.mem.asBytes(&data_len));
    builder.appendSliceAssumeCapacity(wav_data.data);

    return builder.items;
}

const MasterRIFFChunk = extern struct {
    file_type_block_id: FourCC align(1),
    file_size: u32 align(1),
    format: FourCC align(1),

    pub const block_id: FourCC = .{ .byte_1 = 'R', .byte_2 = 'I', .byte_3 = 'F', .byte_4 = 'F' };
    pub const format_id: FourCC = .{ .byte_1 = 'W', .byte_2 = 'A', .byte_3 = 'V', .byte_4 = 'E' };
};

const FourCC = packed struct(u32) {
    byte_1: u8,
    byte_2: u8,
    byte_3: u8,
    byte_4: u8,

    pub fn toInt(self: FourCC) u32 {
        return @bitCast(self);
    }
};

const ChunkHeader = extern struct {
    block_id: FourCC align(1),
    block_size: u32 align(1),
};

const FormatChunk = extern struct {
    audio_format: WavData.AudioFormat align(1),
    num_channels: u16 align(1),
    frequency: u32 align(1),
    byte_per_second: u32 align(1),
    byte_per_block: u16 align(1),
    bits_per_sample: u16 align(1),

    pub const block_id: FourCC = @bitCast([_]u8{ 'f', 'm', 't', ' ' });
};

const DataChunk = struct {
    pub const block_id: FourCC = @bitCast([_]u8{ 'd', 'a', 't', 'a' });
};

const ReaderState = enum(u8) {
    parse_next_chunk_header,
    parse_format_chunk,
    parse_data_chunk,
};

test "wav decode" {
    const wav_data = try std.fs.cwd().readFileAlloc("assets/sounds/pop.wav", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(wav_data);

    const wav_data_decoded = try decode(std.testing.allocator, wav_data);
    defer std.testing.allocator.free(wav_data_decoded.data);

    const wav_data_encoded = try encode(std.testing.allocator, wav_data_decoded);
    defer std.testing.allocator.free(wav_data_encoded);
    try std.fs.cwd().writeFile(.{ .sub_path = "test_out.wav", .data = wav_data_encoded, .flags = .{} });

    std.log.err("first bytes: {any}", .{wav_data_decoded.data[0..10]});
}

test "size" {
    std.log.err("wav size: {any}", .{@sizeOf(FormatChunk)});
}
