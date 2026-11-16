# U_BStream

ANSI C module for building and parsing binary data.

Released under BSD license.

## Usage

1. Include `u_bstream.c` and `u_bstream.h` in your project, or add the repository as a CMake subdirectory / via FetchContent.
2. Link the library via `target_link_libraries(${PROJECT_NAME} u_bstream)`.

## API Reference

### Initialization

| Function | Description |
|---|---|
| `void U_bstream_init(U_BStream *bs, void *data, unsigned long size)` | Initializes a byte stream with the given buffer. Sets position to 0 and status to OK. |

### Navigation

| Function | Description |
|---|---|
| `unsigned long U_bstream_remaining(U_BStream *bs)` | Returns the number of bytes remaining from the current position to the end of the buffer. Returns 0 if an error has occurred. |
| `unsigned long U_bstream_pos(U_BStream *bs)` | Returns the current stream position, i.e. the number of bytes committed to the buffer. A stream that failed part way still reports what was written, where `size - U_bstream_remaining()` would not. |
| `int U_bstream_fits(U_BStream *bs, unsigned long n)` | Returns non-zero if `n` bytes can still be written without overflow. A shortcut for `n <= U_bstream_remaining(bs)`. |
| `void U_bstream_advance(U_BStream *bs, unsigned long n)` | Advances the stream position by `n` bytes. Sets `U_BSTREAM_WRITE_PAST_END` if advancing would exceed the buffer size. |
| `void U_bstream_seek(U_BStream *bs, unsigned long pos)` | Seeks to an absolute byte offset within the buffer. Sets `U_BSTREAM_WRITE_PAST_END` if `pos` exceeds the buffer size. |

### Write Functions (`put_`)

Writes advance the stream position. All write functions set an error status if the buffer would be exceeded or the stream is uninitialized. Subsequent calls become no-ops.

| Function | Description |
|---|---|
| `void U_bstream_put_u8(U_BStream *bs, unsigned char v)` | Writes a single 8-bit unsigned byte. |
| `void U_bstream_put_s8(U_BStream *bs, signed char v)` | Writes a single 8-bit signed byte. |
| `void U_bstream_put_bytes(U_BStream *bs, const void *src, unsigned long n)` | Copies `n` raw bytes from `src` into the stream. |
| `void U_bstream_put_u16_le(U_BStream *bs, unsigned short v)` | Writes a 16-bit unsigned integer in little-endian order. |
| `void U_bstream_put_s16_le(U_BStream *bs, signed short v)` | Writes a 16-bit signed integer in little-endian order. |
| `void U_bstream_put_u16_be(U_BStream *bs, unsigned short v)` | Writes a 16-bit unsigned integer in big-endian order. |
| `void U_bstream_put_s16_be(U_BStream *bs, signed short v)` | Writes a 16-bit signed integer in big-endian order. |
| `void U_bstream_put_u32_le(U_BStream *bs, unsigned long v)` | Writes a 32-bit unsigned integer in little-endian order. |
| `void U_bstream_put_s32_le(U_BStream *bs, signed long v)` | Writes a 32-bit signed integer in little-endian order. |
| `void U_bstream_put_u32_be(U_BStream *bs, unsigned long v)` | Writes a 32-bit unsigned integer in big-endian order. |
| `void U_bstream_put_s32_be(U_BStream *bs, signed long v)` | Writes a 32-bit signed integer in big-endian order. |
| `void U_bstream_put_leb128_u32(U_BStream *bs, unsigned long v)` | Writes the low 32 bits of `v` as an unsigned LEB128 varint, 1 to 5 bytes. Writes the whole value or none of it. |
| `void U_bstream_put_leb128_s64(U_BStream *bs, long long v)` | Writes a signed `long long` using zigzag-encoded LEB128 variable-length encoding.* |
| `void U_bstream_put_u64_le(U_BStream *bs, unsigned long long v)` | Writes a 64-bit unsigned integer in little-endian order.* |
| `void U_bstream_put_s64_le(U_BStream *bs, long long v)` | Writes a 64-bit signed integer in little-endian order.* |
| `void U_bstream_put_u64_be(U_BStream *bs, unsigned long long v)` | Writes a 64-bit unsigned integer in big-endian order.* |
| `void U_bstream_put_s64_be(U_BStream *bs, long long v)` | Writes a 64-bit signed integer in big-endian order.* |

`unsigned long U_bstream_leb128_u32_size(unsigned long v)` returns the number of bytes (1 to 5) `U_bstream_put_leb128_u32` needs for `v`, so a caller can check `U_bstream_fits` before writing. It writes nothing and takes no stream.

### Read Functions (`get_`)

Reads advance the stream position. All read functions return zero and set an error status on overflow, truncated input, or uninitialized stream. Subsequent calls become no-ops.

| Function | Description |
|---|---|
| `unsigned char U_bstream_get_u8(U_BStream *bs)` | Reads a single 8-bit unsigned byte. |
| `signed char U_bstream_get_s8(U_BStream *bs)` | Reads a single 8-bit signed byte. |
| `void U_bstream_get_bytes(U_BStream *bs, void *dst, unsigned long n)` | Copies `n` raw bytes from the stream into `dst`. |
| `unsigned short U_bstream_get_u16_le(U_BStream *bs)` | Reads a 16-bit unsigned integer in little-endian order. |
| `signed short U_bstream_get_s16_le(U_BStream *bs)` | Reads a 16-bit signed integer in little-endian order. |
| `unsigned short U_bstream_get_u16_be(U_BStream *bs)` | Reads a 16-bit unsigned integer in big-endian order. |
| `signed short U_bstream_get_s16_be(U_BStream *bs)` | Reads a 16-bit signed integer in big-endian order. |
| `unsigned long U_bstream_get_u32_le(U_BStream *bs)` | Reads a 32-bit unsigned integer in little-endian order. |
| `signed long U_bstream_get_s32_le(U_BStream *bs)` | Reads a 32-bit signed integer in little-endian order. |
| `unsigned long U_bstream_get_u32_be(U_BStream *bs)` | Reads a 32-bit unsigned integer in big-endian order. |
| `signed long U_bstream_get_s32_be(U_BStream *bs)` | Reads a 32-bit signed integer in big-endian order. |
| `unsigned long U_bstream_get_leb128_u32(U_BStream *bs)` | Reads an unsigned LEB128 varint as a 32-bit value. Sets `U_BSTREAM_DECODE_ERROR` on a value needing more than 5 bytes, on a group whose bits fall above bit 32, or on input that ends before a terminating group. |
| `long long U_bstream_get_leb128_s64(U_BStream *bs)` | Reads a signed `long long` from zigzag-decoded LEB128 variable-length bytes.* |
| `unsigned long long U_bstream_get_u64_le(U_BStream *bs)` | Reads a 64-bit unsigned integer in little-endian order.* |
| `long long U_bstream_get_s64_le(U_BStream *bs)` | Reads a 64-bit signed integer in little-endian order.* |
| `unsigned long long U_bstream_get_u64_be(U_BStream *bs)` | Reads a 64-bit unsigned integer in big-endian order.* |
| `long long U_bstream_get_s64_be(U_BStream *bs)` | Reads a 64-bit signed integer in big-endian order.* |

> *\* Signed LEB128 and the fixed-width 64-bit functions are available only when `U_BSTREAM_HAS_LONG_LONG` is defined (C99 or MSVC ≥ 1310). The unsigned 32-bit varint needs no `long long` and is always available.*

### Status Codes

| Constant | Meaning |
|---|---|
| `U_BSTREAM_OK` | No error. |
| `U_BSTREAM_READ_PAST_END` | A read operation went beyond the buffer boundary. |
| `U_BSTREAM_WRITE_PAST_END` | A write operation would exceed the buffer size. |
| `U_BSTREAM_NOT_INITIALISED` | The stream was used before calling `U_bstream_init`. |
| `U_BSTREAM_DECODE_ERROR` | LEB128 decode failed (overflow or truncated input). |

### Notes

- **Sticky status** — once an error status is set, all subsequent operations become no-ops. Re-initialize the stream with `U_bstream_init` to reset.
- **Navigation** — use `U_bstream_remaining`, `U_bstream_pos`, `U_bstream_fits`, `U_bstream_advance`, and `U_bstream_seek` to inspect or reposition the stream cursor without reading or writing data.
- **Endianness** — 16-bit, 32-bit and 64-bit values read and write in both orders. A value wider than the function writes its low bytes, so `put_u32_le` and `put_u32_be` on a 64-bit `unsigned long` both encode the low 32 bits.
- **LEB128** — `put_leb128_u32`/`get_leb128_u32` are the plain unsigned varint, the encoding a Spinel packed uint uses. The signed 64-bit pair maps through zigzag so that small negative numbers encode compactly (e.g., `-1 → 0x01`, `63 → 0x7E`).
