const std = @import("std");
const assert = std.debug.assert;

const BitStream = @import("bitstream.zig");

const FourCC = packed struct(u32) {
    byte_1: u8,
    byte_2: u8,
    byte_3: u8,
    byte_4: u8,

    pub fn init(data: []const u8) FourCC {
        assert(data.len == 4);
        return .{ .byte_1 = data[0], .byte_2 = data[1], .byte_3 = data[2], .byte_4 = data[3] };
    }

    pub fn toInt(self: FourCC) u32 {
        return @bitCast(self);
    }
};
// NOTE:
//  1.  Each segment is prefixed with an 27 byte header
//  2. If header's Flags field has a bit 2, or TotalSegments field is a zero, this is the end of the audio file.
//  You start with reading the OGG header, figure out how many segments there are grab them and then move to the next
//  header and repeat. This will pick up all the vorbis data.
//  NOTE: Packets are logically divided into multiple segments before encoding into a page. Packets are divided into segments
//  of 255 bytes, the first segment that has a size of less than 255 bytes is the last segment of the packet. If a packet
//  is exactly 255 bytes it is followed by a 0 value segment.
//  NOTE: A zero value zegment is not invalid;
//  NOTE: Packets are not restricted to beginning and ending within a page
//  although individual segments are, by definition, required to do so
const OGG_MAGIC: FourCC = .init("OggS");
const OggHeader = extern struct {
    magic: FourCC align(1),
    version: u8 align(1),
    header_type_flag: HeaderFlags align(1),
    granule_position: u64 align(1),
    bitstream_serial_number: u32 align(1),
    page_sequence_number: u32 align(1),
    crc_checksum: u32 align(1), // The generator polynomial is 0x04c11db7.
    number_page_segments: u8 align(1), // If this is 0 then the header is for the end of the stream.

    pub const HeaderFlags = packed struct(u8) {
        continued_packet: bool = false,
        bos: bool = false,
        eos: bool = false,
        _reserved: u5 = 0,
    };
};

pub const Error = error{
    InvalidOggSMagic,
    MalformedIncompleteData,
    MalformedNoBeginningOfStream,
    MalformedMissingContinuedPacket,
    MalformedPageSequenceOutOfOrder,
    InvalidVorbisIdentificationPacket,
    InvalidVorbisCommentPacket,
    InvalidVorbisSetupPacket,
    InvalidCodebookSyncPattern,
    InvalidCodebookLengthGreaterThan32,
    InvalidCodebookInsufficientEntries,
    InvalidCodebookCannotFindPrefix,
    InvalidCodebookLookupType,
} || std.mem.Allocator.Error;

const VORBIS_IDENTIFICATION: u32 = 0;
const VORBIS_COMMENT: u32 = 1;
const VORBIS_CODEC_SETUP: u32 = 2;
const VORBIS_CODEC_SETUP_NO: u32 = 3;

// TODO: Use errors instead of asserts?
// TODO: Use IO interface maybe?
// TODO: Is there any way to provide an arena to thsi function so that we dont ahve to worry about frees?
// TODO: Do we need to handle multiplexed streams? We can look at all BOS packets and the codec definition to figure out
// which serial number to use for which type of stream.
pub fn decode(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const start_state: DecoderState = .read_header;
    // TODO: Arena allocator for intermediate buffers

    var read_head: []const u8 = data;
    // TODO: Do we want to parse this?
    // var comment_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
    // var vorbis_comment_packet: VorbisCommentPacket = undefined;

    // TODO: Is there any way to avoid this allocation?
    // PERF: Can we have a code path when the packets are contigous and not write to this buffer?
    // PERF: 4096 seems reasonable as a buffer for packets since we expect small packets when dealing with audio files.
    var packet_buffer = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer packet_buffer.deinit(allocator);
    var segments: []const u8 = undefined;
    var current_segment: usize = 0;
    var current_page: usize = 0;
    var continued_packet_flag: bool = false;
    var begin_of_stream_flag: bool = true;
    var end_of_stream_flag: bool = false;
    var current_packet_serial_number: u32 = undefined;

    // TODO: Filter only the vorbis packets
    var vorbis_current_packet_number: u32 = 0;
    var vorbis_serial_identified: bool = false;
    var vorbis_serial_number: u32 = undefined;
    var vorbis_identification_packet: VorbisIDPacket = undefined;
    // var vorbis_codec_setup_packet: VorbisCodecSetupPacket = undefined;

    blk: switch (start_state) {
        .read_header => {
            if (end_of_stream_flag) {
                break :blk;
            }
            if (read_head.len < @sizeOf(OggHeader)) {
                return error.MalformedIncompleteData;
            }

            const ogg_header: *const OggHeader = @ptrCast(@alignCast(read_head[0..@sizeOf(OggHeader)].ptr));
            read_head = read_head[@sizeOf(OggHeader)..];

            if (ogg_header.magic != OGG_MAGIC) {
                return error.InvalidOggSMagic;
            }

            if (vorbis_serial_identified and ogg_header.bitstream_serial_number != vorbis_serial_number) {
                const logal_segments = read_head[0..ogg_header.number_page_segments];
                var page_size: usize = 0;
                for (logal_segments) |segment| {
                    page_size += segment;
                    // TODO: Can we have continuations here?
                }
                read_head = read_head[page_size + ogg_header.number_page_segments ..];
                continue :blk .read_header;
            }

            if (begin_of_stream_flag and !ogg_header.header_type_flag.bos) {
                return error.MalformedNoBeginningOfStream;
            }
            begin_of_stream_flag = false;

            if (continued_packet_flag and !ogg_header.header_type_flag.continued_packet) {
                return error.MalformedMissingContinuedPacket;
            }
            continued_packet_flag = false;

            end_of_stream_flag = ogg_header.header_type_flag.eos;

            if (ogg_header.page_sequence_number != current_page) {
                return error.MalformedPageSequenceOutOfOrder;
            }
            current_packet_serial_number = ogg_header.bitstream_serial_number;
            // TODO: Verify checksum

            segments = read_head[0..ogg_header.number_page_segments];
            current_segment = 0;
            read_head = read_head[ogg_header.number_page_segments..];

            current_page += 1;
            continue :blk .read_next_packet;
        },
        .read_next_packet => {
            if (current_segment >= segments.len) {
                continue :blk .read_header;
            }
            var packet_size: usize = 0;
            for (current_segment..segments.len) |index| {
                packet_size += segments[index];
                if (segments[index] < 255) {
                    // std.log.err("packet size: {any}", .{packet_size});
                    current_segment = index + 1;
                    if (packet_buffer.items.len > 0) {
                        // NOTE: We have already collected some packets so we need to append to the buffer
                        try packet_buffer.appendSlice(allocator, read_head[0..packet_size]);
                        read_head = read_head[packet_size..];
                        continue :blk .{ .parse_packet = packet_buffer.items };
                    } else {
                        const packet = read_head[0..packet_size];
                        read_head = read_head[packet_size..];
                        // NOTE: Since this is a contigious packet we dont need to use the packet_buffer
                        continue :blk .{ .parse_packet = packet };
                    }
                }
            }
            // NOTE: We can only reach here if the last segment is 255 and we havent reached the end of the packet.
            // std.log.err("Continuation packet", .{});
            try packet_buffer.appendSlice(allocator, read_head[0..packet_size]);
            continued_packet_flag = true;
            read_head = read_head[packet_size..];
            continue :blk .read_header;
        },
        .parse_packet => |packet| {
            var packet_read_head: []const u8 = packet;
            // NOTE: Once we are done parsing the packet we can reset the buffer even if we are not using the packet_buffer
            defer packet_buffer.shrinkRetainingCapacity(0);
            switch (vorbis_current_packet_number) {
                VORBIS_IDENTIFICATION => {
                    // TODO: Check if this is a vorbis stream and if not check the next header for a BOS packet
                    if (packet_read_head.len == 0) {
                        return error.MalformedIncompleteData;
                    }
                    const packet_type: u8 = packet[0];
                    if (packet_type != 0x01) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (packet_read_head.len < 7) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (!std.mem.eql(u8, packet_read_head[1..7], "vorbis")) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    vorbis_serial_number = current_packet_serial_number;
                    vorbis_serial_identified = true;
                    packet_read_head = packet_read_head[7..];
                    if (packet_read_head.len != @sizeOf(VorbisIDPacket)) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    const vorbis_id_packet: *const VorbisIDPacket = @ptrCast(@alignCast(packet_read_head[0..@sizeOf(VorbisIDPacket)].ptr));

                    if (vorbis_id_packet.version != 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.audio_channels == 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.audio_sample_rate == 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.block_size._0 > vorbis_id_packet.block_size._1 or
                        vorbis_id_packet.block_size._0 < 6 or vorbis_id_packet.block_size._0 > 13 or
                        vorbis_id_packet.block_size._1 < 6 or vorbis_id_packet.block_size._1 > 13)
                    {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.framing_flag != 1) {
                        return error.InvalidVorbisIdentificationPacket;
                    }

                    vorbis_identification_packet = vorbis_id_packet.*;
                },
                VORBIS_COMMENT => {
                    if (packet_read_head.len == 0) {
                        return error.MalformedIncompleteData;
                    }
                    const packet_type: u8 = packet[0];
                    if (packet_type != 0x03) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    if (packet_read_head.len < 7) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    if (!std.mem.eql(u8, packet_read_head[1..7], "vorbis")) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    packet_read_head = packet_read_head[7..];
                    if (packet_read_head.len < 4) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    const vendor_string_length: u32 = @bitCast(packet_read_head[0..4].*);
                    packet_read_head = packet_read_head[4..];
                    if (packet_read_head.len < vendor_string_length) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    // try comment_buffer.appendSlice(allocator, packet_read_head[0..vendor_string_length]);
                    // std.log.err("Vendor string: {s}", .{packet_read_head[0..vendor_string_length]});
                    packet_read_head = packet_read_head[vendor_string_length..];

                    if (packet_read_head.len < 4) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    const user_comment_list_length: u32 = @bitCast(packet_read_head[0..4].*);
                    packet_read_head = packet_read_head[4..];
                    for (0..user_comment_list_length) |_| {
                        if (packet_read_head.len < 4) {
                            return error.InvalidVorbisCommentPacket;
                        }
                        const user_comment_length: u32 = @bitCast(packet_read_head[0..4].*);
                        packet_read_head = packet_read_head[4..];
                        if (packet_read_head.len < user_comment_length) {
                            return error.InvalidVorbisCommentPacket;
                        }
                        // try comment_buffer.appendSlice(allocator, packet_read_head[0..user_comment_length]);
                        // std.log.err("User comment: {s}", .{packet_read_head[0..user_comment_length]});
                        packet_read_head = packet_read_head[user_comment_length..];
                    }
                },

                VORBIS_CODEC_SETUP => {
                    // TODO: Parse the vorbis codec setup header
                    if (packet_read_head.len < 7) {
                        return error.InvalidVorbisSetupPacket;
                    }
                    const packet_type: u8 = packet[0];
                    if (packet_type != 0x05) {
                        return error.InvalidVorbisSetupPacket;
                    }
                    if (!std.mem.eql(u8, packet_read_head[1..7], "vorbis")) {
                        return error.InvalidVorbisSetupPacket;
                    }
                    var bitstream = BitStream.init(packet_read_head[7..]);
                    const codebook_count: usize = bitstream.consume(8) + 1;
                    const codebooks = allocator.alloc(Codebook, codebook_count) catch unreachable;
                    // @TODO Pass in a temporary allocator/arena and reset it each loop
                    for (codebooks, 0..) |*codebook, i| {
                        std.log.err("codebook {d}", .{i});
                        try Codebook.init(codebook, allocator, &bitstream);

                        // @LEFTOFF getting some error on the lookup type parsing
                        if (i == 36) {
                            break; // HACK
                        }
                    }
                },
                else => {
                    // std.log.err("Audio packet", .{});
                },
            }
            vorbis_current_packet_number += 1;
            continue :blk .read_next_packet;
        },
    }

    const intermediate_buffer = try allocator.alloc(u8, 10);
    return intermediate_buffer;
}

const END_OF_PACKET: i32 = -1;

const LookupType = enum(u8) {
    no_lookup = 0,
    implicitly_populated = 1,
    explicity_populated = 2,
};

/// @NOTE: according to the spec this function is defined as:
///        The return value for this function is defined to be ’the greatest integer value for which [return_value] to the power of [codebook_dimensions] is less than or equal to [codebook_entries]’.
///        if return_value is r and codebook_dimensions is d and codebook_entries is e then the return value is.
///        r^d = e => d*log(r) = log(e) => log(r) = log(e)/d => r = e^(log(e)/d)
///        and the largest integer for which this is true will be the floor of this value
///        r = floor(e^(log(e)/d))
fn lookup1Values(dimension: u16, entries: u32) ?u32 {
    var result = @floor(@exp(@log(@as(f32, @floatFromInt(entries))) / @as(f32, @floatFromInt(dimension))));
    var test_next_int: i32 = @intFromFloat(@floor(std.math.pow(f32, result + 1, @floatFromInt(dimension))));
    if (test_next_int < entries) {
        result += 1;
    }
    // @TODO I DONT KNOW WHY THIS IS NEEDED BUT STB VORBIS DOES IT. Look into it. I can see
    // why these checks might be needed due to floating point precision errors
    test_next_int = @intFromFloat(@floor(std.math.pow(f32, result + 1, @floatFromInt(dimension))));
    if (test_next_int <= entries) {
        return null;
    }
    test_next_int = @intFromFloat(@floor(std.math.pow(f32, result, @floatFromInt(dimension))));
    if (test_next_int > entries) {
        return null;
    }
    return @intFromFloat(result);
}

fn float32Unpack(bytes: u32) f32 {
    const mantissa: u32 = bytes & 0x1FFFFF;
    const sign: u32 = bytes & 0x80000000;
    const exponent: u32 = (bytes & 0x7FE00000) >> 21;
    const result = if (sign == 1) -@as(f64, @floatFromInt(mantissa)) else @as(f64, @floatFromInt(mantissa));
    return @floatCast(std.math.ldexp(result, @as(i32, @intCast(exponent)) - 788));
}

const Codebook = struct {
    entries: u32,
    dimension: u16,
    sparse_flag: bool,
    dimensions: u16,
    slow_path_entry_count: u32,
    slow_path_table_codewords: []u32,
    slow_path_table_values: []u32,
    fast_huffman_table: [FAST_HUFFMAN_TABLE_SIZE]i16,

    codewords: []u32,
    codeword_lengths: []u8,

    multiplicands: []f32,
    lookup_type: LookupType,
    minimum_value: f32,
    delta_value: f32,
    value_bits: u8,
    sequence_p: u8,
    lookup_values: u32,

    pub const FAST_HUFFMAN_BITS: u6 = 10;
    pub const FAST_HUFFMAN_TABLE_SIZE: usize = 1 << FAST_HUFFMAN_BITS;

    // @TODO Pass in a temporary allocator/arena
    pub fn init(c: *Codebook, allocator: std.mem.Allocator, bitstream: *BitStream) Error!void {
        // @TODO Should everything from the setup live in temporary storage since we dont need to
        // keep these around once we are done?
        const sync_pattern: u64 = bitstream.consume(24);
        if (sync_pattern != 0x564342) {
            return error.InvalidCodebookSyncPattern;
        }
        c.dimension = @truncate(bitstream.consume(16));

        c.entries = @truncate(bitstream.consume(24));

        const is_ordered: u64 = bitstream.consume(1);
        c.sparse_flag = if (is_ordered == 0) bitstream.consume(1) == 1 else false;

        // @TODO This is a temporary allocation and should go on the arena
        var lengths = try allocator.alloc(u8, c.entries);

        var total: usize = 0;
        if (is_ordered == 0) {
            for (0..c.entries) |i| {
                const is_entry_used: u64 = if (c.sparse_flag) bitstream.consume(1) else 1;
                if (is_entry_used != 0) {
                    total += 1;
                    lengths[i] = @truncate(bitstream.consume(5) + 1);
                    if (lengths[i] > 32) {
                        return error.InvalidCodebookLengthGreaterThan32;
                    }
                } else {
                    lengths[i] = VORBIS_NO_CODE;
                }
            }
        } else {
            var current_length: u64 = bitstream.consume(5) + 1;
            var current_entry: usize = 0;
            while (current_entry < c.entries) {
                const bits_to_read: u64 = ilog(@intCast(c.entries - current_entry)) + 1;
                const num_at_this_length: u64 = bitstream.consume(@truncate(bits_to_read));
                if (current_length >= 32) {
                    return error.InvalidCodebookLengthGreaterThan32;
                }
                if (current_entry + num_at_this_length > c.entries) {
                    return error.InvalidCodebookInsufficientEntries;
                }
                @memset(lengths[current_entry..][0..num_at_this_length], @truncate(current_length));
                current_entry += num_at_this_length;
                current_length += 1;
            }
        }

        if (c.sparse_flag and total >= c.entries >> 2) {
            // TODO: If there are enough entries that are valid treat it as non-sparse
            c.sparse_flag = false;
        }

        c.slow_path_entry_count = if (c.sparse_flag)
            @truncate(total)
        else slow_path_count: {
            var count: u32 = 0;
            for (lengths) |length| {
                if (length > FAST_HUFFMAN_BITS and length != VORBIS_NO_CODE) {
                    count += 1;
                }
            }
            break :slow_path_count count;
        };

        // @NOTE If the codebook is sparse we wills store just the valid codewords and their corresponding
        // lengths. Otherwise we will store all the codewords and their corresponding lengths. This
        // is the optimization that stb_vorbis does and it seems reasonable to me to do so as well.
        var values: []u32 = undefined;
        if (!c.sparse_flag) {
            c.codewords = allocator.alloc(u32, c.entries) catch unreachable;
            c.codeword_lengths = lengths;
        } else {
            // @TODO For sparse codebooks allocate only the number of entries that are valid
            c.codewords = allocator.alloc(u32, c.slow_path_entry_count) catch unreachable;
            c.codeword_lengths = allocator.alloc(u8, c.slow_path_entry_count) catch unreachable;
            values = allocator.alloc(u32, c.slow_path_entry_count) catch unreachable;
        }

        // @TODO For sparse codebooks this is very slow. We should implement a different path for sparse
        // codebooks.
        { // Compute codewords
            var sparse_count: usize = 0;
            var available_bits: [32]u32 = [_]u32{0} ** 32;
            // find the first one with a valid length i.e not VORBIS_NO_CODE
            var first_valid_symbol: u32 = 0;
            for (lengths, 0..) |length, i| {
                if (length != VORBIS_NO_CODE) {
                    first_valid_symbol = @truncate(i);
                    break;
                }
            }
            assert(lengths[first_valid_symbol] < 32);
            // Set the first symbol to be 0
            if (!c.sparse_flag) {
                c.codewords[first_valid_symbol] = 0;
            } else {
                c.codewords[sparse_count] = 0;
                c.codeword_lengths[sparse_count] = lengths[first_valid_symbol];
                values[sparse_count] = first_valid_symbol;
                sparse_count += 1;
            }
            // For all codewords that are less than and equal the first valid symbol's length cannot
            // start with zeros as the prefix. Eg. if the first valid symbol is 3 and we assign 000
            // to it in the previous step then length 1 codewords must start with 1 do must start with
            // 01 and the next symbol with length 3 must start with 001. And since the code is most significant
            // bit first we shift by 32 - length to get the prefix.
            {
                var index: usize = 1;
                while (index <= lengths[first_valid_symbol]) : (index += 1) {
                    available_bits[index] = @as(u32, 1) << @truncate(32 - index);
                }
            }
            for (first_valid_symbol + 1..c.entries) |i| {
                var length = lengths[i];
                if (length == VORBIS_NO_CODE) continue;
                assert(length < 32);
                // According to teh stb_vorbis comments though not provable we dont have more than 1
                // leaf node per level. So we can find the earliest available (i.e the lowest available)
                // leaf node to assign to this codeword.
                // eg. if the lengths are [3, 5] then 3 is assigned 000 and 5 is assigned 00100
                while (length > 0 and available_bits[length] == 0) {
                    length -= 1;
                }
                if (length == 0) {
                    return error.InvalidCodebookCannotFindPrefix;
                }
                // NOTE: Take the next available codeword at a particular length and assign it to the
                // current symbol. We then take every codeword at the length we assigned up to the
                // the actual length and set them to the next avaialbel codeword.
                // eg. if the lengths are [3, 5] and we assign 000 to 3 and 00100 to 5. We then set the next
                // available codewword for 3 to  be 010 (001 + 1), for 4 the next available will be 0011
                // and for 5 the next available will be 00101. To maintain the
                const result = available_bits[length];
                available_bits[length] = 0;
                if (!c.sparse_flag) {
                    c.codewords[i] = @bitReverse(result);
                } else {
                    c.codewords[sparse_count] = @bitReverse(result);
                    c.codeword_lengths[sparse_count] = lengths[i];
                    values[sparse_count] = @truncate(i);
                    sparse_count += 1;
                }
                if (length != lengths[i]) {
                    var index: usize = lengths[i];
                    while (index > length) : (index -= 1) {
                        assert(available_bits[index] == 0);
                        available_bits[index] = result + (@as(u32, 1) << @truncate(32 - index));
                    }
                }
            }
        }

        std.log.err("Slow path entry count: {d}, sparse flag: {any}", .{ c.slow_path_entry_count, c.sparse_flag });

        if (c.slow_path_entry_count > 0) {
            c.slow_path_table_codewords = allocator.alloc(u32, c.slow_path_entry_count + 1) catch unreachable;
            c.slow_path_table_values = allocator.alloc(u32, c.slow_path_entry_count + 1) catch unreachable;
            c.slow_path_table_values[0] = 0;
            { // Slow path
                // NOTE: From the codewords collect everythign that is not in the fast huffman table
                // for the case of sparse codebooks we will do it for everything anyway.
                if (!c.sparse_flag) {
                    var index: usize = 0;
                    for (0..c.entries) |i| {
                        if (lengths[i] != VORBIS_NO_CODE and lengths[i] > FAST_HUFFMAN_BITS) {
                            c.slow_path_table_codewords[index] = @bitReverse(c.codewords[i]);
                            index += 1;
                        }
                    }
                    assert(c.slow_path_entry_count == index);
                } else {
                    for (0..c.slow_path_entry_count) |i| {
                        c.slow_path_table_codewords[i] = @bitReverse(c.codewords[i]);
                    }
                }

                // @NOTE: Sort only the first c.slow_path_entry_count elements and then set the last element to 0xFFFFFFFF
                std.sort.heap(u32, c.slow_path_table_codewords[0..c.slow_path_entry_count], {}, std.sort.asc(u32));
                c.slow_path_table_codewords[c.slow_path_entry_count] = 0xFFFFFFFF;

                const length = if (c.sparse_flag) c.slow_path_entry_count else c.entries;
                for (0..length) |i| {
                    const huffman_code_length = if (c.sparse_flag) lengths[values[i]] else lengths[i];
                    const should_include = c.sparse_flag or
                        (huffman_code_length > FAST_HUFFMAN_BITS and
                            huffman_code_length != VORBIS_NO_CODE);
                    if (should_include) {
                        const codeword = @bitReverse(c.codewords[i]);
                        // @NOTE Binary search for the codeword in the sorted list of codewords
                        // Since each codeword is unqiue there should be no collisions
                        var search_length: usize = c.slow_path_entry_count;
                        var current_candidate: usize = 0;
                        while (search_length > 1) {
                            const test_point = current_candidate + (search_length >> 1);
                            if (c.slow_path_table_codewords[test_point] <= codeword) {
                                current_candidate = test_point;
                                search_length -= (search_length >> 1);
                            } else {
                                search_length >>= 1;
                            }
                        }
                        // NOTE: The one we find must be the codeword
                        assert(c.slow_path_table_codewords[current_candidate] == codeword);
                        if (c.sparse_flag) {
                            c.slow_path_table_values[current_candidate] = values[i];
                            c.codeword_lengths[current_candidate] = huffman_code_length;
                        } else {
                            c.slow_path_table_values[current_candidate] = @truncate(i);
                        }
                    }
                }
            }
        }
        // @TODO Once we are done with building the slow path we can free the codewords, values and
        // the lengths arrays if the codebook is sparse

        // NOTE: To decode the codewords we need a way to do a lookup given a bitstream of huffman
        // encoded data. For codes less than say 10 bits we can do a fast lookup table that just
        // has an O(1) lookup. For ones larger than 10 bits we can construct a symbol table that we
        // can do a slow search through.
        // TODO: Decide how big the fast huffman table should be
        const fast_huffman_table = allocator.alloc(i16, FAST_HUFFMAN_TABLE_SIZE) catch unreachable;
        { // Fast huffman table
            @memset(fast_huffman_table, -1);
            var entries: usize = if (c.sparse_flag) c.slow_path_entry_count else c.entries;
            if (entries > std.math.maxInt(i16)) {
                entries = std.math.maxInt(i16);
            }
            for (0..entries) |i| {
                if (lengths[i] <= FAST_HUFFMAN_BITS) {
                    var length = if (c.sparse_flag) @bitReverse(c.slow_path_table_codewords[i]) else c.codewords[i];
                    while (length < FAST_HUFFMAN_TABLE_SIZE) {
                        fast_huffman_table[length] = @intCast(i);
                        length += @as(u32, 1) << @truncate(lengths[i]);
                    }
                }
            }
        }

        // @TODO parse lookup types
        c.lookup_type = @enumFromInt(bitstream.consume(4));
        switch (c.lookup_type) {
            .no_lookup => {},
            .implicitly_populated, .explicity_populated => {
                c.minimum_value = float32Unpack(@truncate(bitstream.consume(32)));
                c.delta_value = float32Unpack(@truncate(bitstream.consume(32)));
                c.value_bits = @truncate(bitstream.consume(4) + 1);
                c.sequence_p = @truncate(bitstream.consume(1));
                c.lookup_values =
                    if (c.lookup_type == .implicitly_populated)
                        lookup1Values(c.dimension, c.entries) orelse return error.InvalidVorbisSetupPacket
                    else
                        c.dimension * c.entries;
                assert(c.lookup_values > 0);
                // @TODO This is a temporary allocation and should go on the arena
                const multipliers = allocator.alloc(u16, c.lookup_values) catch unreachable;
                for (multipliers) |*multiplier| {
                    const value: i64 = @bitCast(bitstream.consume(@truncate(c.value_bits)));
                    // @TODO If we reach the end of packet we need to return -1 as u32
                    if (value == END_OF_PACKET) return error.InvalidVorbisSetupPacket;
                    multiplier.* = @intCast(value);
                }

                // @NOTE: We are going to precalculate the multipliers for the implicitly populated lookup type
                // to save on integer divisions for each vector element
                const length = if (c.sparse_flag) c.slow_path_entry_count else c.entries;
                c.multiplicands = allocator.alloc(f32, length * c.dimension) catch unreachable;
                if (c.lookup_type == .implicitly_populated and length > 0) {
                    for (0..length) |j| {
                        const value: u32 = if (c.sparse_flag) c.slow_path_table_values[j] else @truncate(j);
                        var divisor: u32 = 1;
                        var last_value: f32 = 0;
                        for (0..c.dimension) |k| {
                            const offset: u32 = @divTrunc(value, divisor) % c.lookup_values;
                            const multiplier_value: f32 =
                                @as(f32, @floatFromInt(multipliers[offset])) * c.delta_value +
                                c.minimum_value +
                                last_value;
                            c.multiplicands[j * c.dimension + k] = multiplier_value;
                            if (c.sequence_p > 0) {
                                last_value = multiplier_value;
                            }
                            if (k + 1 < c.dimension) {
                                if (divisor > @divTrunc(std.math.maxInt(u32), c.lookup_values)) {
                                    return error.InvalidVorbisSetupPacket;
                                }
                                divisor *= c.lookup_values;
                            }
                        }
                    }
                    c.lookup_type = .explicity_populated;
                } else {
                    var last_value: f32 = 0;
                    for (0..c.lookup_values) |j| {
                        const multiplier_value: f32 =
                            @as(f32, @floatFromInt(multipliers[j])) * c.delta_value +
                            c.minimum_value +
                            last_value;
                        c.multiplicands[j] = multiplier_value;
                        if (c.sequence_p > 0) {
                            last_value = multiplier_value;
                        }
                    }
                }
            },
        }
    }
};

const VORBIS_NO_CODE: u8 = 255;
const VorbisIDPacket = extern struct {
    version: u32 align(1), // Must be 0
    audio_channels: u8 align(1), // Number of audio channels 1 for mono 2 for stereo
    audio_sample_rate: u32 align(1), // Audio sample rate in Hz
    bitrate_maximum: u32 align(1), // Hint for the maximum bitrate in bps
    bitrate_nominal: u32 align(1), // Hint for the nominal bitrate in bps
    bitrate_minimum: u32 align(1), // Hint for the minimum bitrate in bps
    block_size: packed struct(u8) { _0: u4, _1: u4 } align(1), // Block size in samples
    framing_flag: u8 align(1), // Flag indicating whether the stream is framed must be 1
};

const VorbisCommentPacket = extern struct {
    vendor_string_length: u32 align(1), // Length of the vendor string
    vendor_string: [*]const u8 align(1), // Vendor string
    user_comment_list_length: u32 align(1), // Length of the user comment list
    user_comment_list: [*]const UserComment align(1), // User comment list

    pub const UserComment = extern struct {
        length: u32 align(1), // Length of the user comment
        entry: [*]const u8 align(1), // User commen
    };
};

const VorbisCodecSetupPacket = extern struct {};

const ParserState = enum(u8) {
    read_next_packet,
    read_header,
    parse_packet,
};

const DecoderState = union(ParserState) {
    read_next_packet,
    read_header,
    parse_packet: []const u8,
};

/// The ”ilog(x)” function returns the position number (1 through n) of the highest set bit in the two’s complement
/// integer value [x]. Values of [x] less than zero are defined to return zero.
inline fn ilog(x: i32) u32 {
    if (x <= 0) return 0;
    return 32 - @clz(x);
}

test "ogg decode" {
    const allocator = std.heap.page_allocator;
    const ogg_data = try std.fs.cwd().readFileAlloc("assets/sounds/footstep00.ogg", allocator, .unlimited);
    defer allocator.free(ogg_data);
    const ogg_data_decoded = try decode(allocator, ogg_data);
    defer allocator.free(ogg_data_decoded);
}

test "ilog" {
    try std.testing.expectEqual(@as(u32, 0), ilog(0));
    try std.testing.expectEqual(@as(u32, 1), ilog(1));
    try std.testing.expectEqual(@as(u32, 2), ilog(2));
    try std.testing.expectEqual(@as(u32, 2), ilog(3));
    try std.testing.expectEqual(@as(u32, 3), ilog(4));
    try std.testing.expectEqual(@as(u32, 3), ilog(7));
    try std.testing.expectEqual(@as(u32, 0), ilog(-5));
}
