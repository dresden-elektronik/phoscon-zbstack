# U_SStream


ANSI C module for building and parsing strings.

Released under BSD license.

## Usage

Include `u_sstream.c` and `u_sstream.h` to your project.

**Important:** It's the users responsibility to call `U_sstream_init` with valid non null arguments.
The code will crash by design if functions are called with invalid or uninitialized U_SStream instances.  

## API Reference

| Prototype | Description |
|-----------|-------------|
| **Initialization** ||
| `void U_sstream_init(U_SStream *ss, void *str, unsigned size)` | Initialize a string stream with a buffer |
| **Query** ||
| `unsigned U_sstream_pos(const U_SStream *ss)` | Get current position in stream |
| `const char *U_sstream_str(const U_SStream *ss)` | Get pointer to current stream content |
| `unsigned U_sstream_remaining(const U_SStream *ss)` | Get remaining characters count |
| `int U_sstream_at_end(const U_SStream *ss)` | Check if at end of stream |
| **Parsing** ||
| `long U_sstream_get_long(U_SStream *ss)` | Parse and consume a long integer |
| `double U_sstream_get_double(U_SStream *ss)` | Parse and consume a double |
| `char U_sstream_peek_char(const U_SStream *ss)` | Look at current character without consuming |
| `void U_sstream_skip_whitespace(U_SStream *ss)` | Skip leading whitespace characters |
| **Search/Compare** ||
| `int U_sstream_starts_with(const U_SStream *ss, const char *str)` | Check if stream starts with string |
| `int U_sstream_find(U_SStream *ss, const char *str)` | Search for string and seek to it |
| `int U_sstream_compare(const U_SStream *ss, const char *str)` | Compare stream content with string |
| **Modification** ||
| `void U_sstream_seek(U_SStream *ss, unsigned pos)` | Seek to position in stream |
| `void U_sstream_put_str(U_SStream *ss, const char *str)` | Append string to stream |
| `void U_sstream_put_double(U_SStream *ss, double num, int precision)` | Append double as string |
| `void U_sstream_put_long(U_SStream *ss, long num)` | Append long as string |
| `void U_sstream_put_longlong(U_SStream *ss, long long num)` | Append long long as string |
| `void U_sstream_put_ulonglong(U_SStream *ss, unsigned long long num)` | Append unsigned long long as string |
| `void U_sstream_put_hex(U_SStream *ss, const void *data, unsigned size)` | Append binary data as hex string |
| **Utility** ||
| `long U_strtol(const char *s, unsigned len, const char **endp, int *err)` | Parse string to long with bounds checking |
| `double U_strtod(const char *str, unsigned len, const char **endp, int *err)` | Parse string to double with bounds checking |

## Run tests

```
cmake -B build .
cmake --build build
cd build/tests
ctest --output-on-failure
```
