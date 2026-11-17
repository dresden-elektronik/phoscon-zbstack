/* The file calls of port_file.h, run by each target's own suite over the backend its build links: POSIX descriptors in
   port_posix, Windows handles in port_win32. */

#include <string.h>

#include "port_file.h"
#include "test_harness.h"

#define SCRATCH_FILE ZB_SCRATCH_DIR "/port_file_scratch.bin"
#define SCRATCH_MISSING ZB_SCRATCH_DIR "/port_file_missing.bin"
#define SCRATCH_RENAMED ZB_SCRATCH_DIR "/port_file_renamed.bin"

/* A target's files (docs/porting.md §3): a missing file does not open for reading, a write creates and empties, what
   was written reads back from any position, a mode refuses the direction it does not allow, and a rename replaces in
   one step. */
void caseFileRoundTrip(void)
{
    static const uint8_t first[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    static const uint8_t second[] = { 0xaa, 0xbb };
    PortFile file;
    uint8_t buf[16];
    uint32_t got = 0;
    uint32_t size = 0;

    (void)Port_FileDelete(SCRATCH_MISSING);
    Test_Expect(Port_FileOpen(&file, SCRATCH_MISSING, PORT_FILE_READ) == 0, "a missing file does not open for reading");
    Test_Expect(file.mode == 0 && file.platformErrno != 0, "and is left closed, the platform's error kept");
    Test_Expect(Port_FileExists(SCRATCH_MISSING) == 0, "nor is it there");

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_WRITE) == 1, "write mode creates the file");
    Test_Expect(Port_FileWrite(&file, first, (uint32_t)sizeof first, &got) == 1 && got == sizeof first,
                "every octet is written");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 0 && got == 0,
                "write mode refuses a read");
    Port_FileClose(&file);
    Port_FileClose(&file);
    Test_Expect(file.mode == 0, "a closed file is closed, and closing it again does nothing");
    Test_Expect(Port_FileExists(SCRATCH_FILE) == 1, "the file is there");

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ) == 1, "it opens for reading");
    Test_Expect(Port_FileSize(&file, &size) == 1 && size == sizeof first, "with the size written");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1 && got == sizeof first
                && memcmp(buf, first, sizeof first) == 0, "and the octets read back");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1 && got == 0,
                "at the end a read succeeds with nothing");
    Test_Expect(Port_FileSeek(&file, 4) == 1 && Port_FileRead(&file, buf, 1, &got) == 1 && got == 1 && buf[0] == 0x50,
                "a seek moves the position from the start");
    Test_Expect(Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 0 && got == 0,
                "read mode refuses a write");
    Port_FileClose(&file);

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ_WRITE) == 1, "read-write keeps the file");
    Test_Expect(Port_FileSeek(&file, 2) == 1 && Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 1,
                "and writes in place");
    Test_Expect(Port_FileSeek(&file, 0) == 1 && Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1
                && got == sizeof first && buf[1] == 0x20 && buf[2] == 0xaa && buf[3] == 0xbb && buf[4] == 0x50,
                "what it wrote replaces those octets and leaves the rest");
    Port_FileClose(&file);

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_WRITE) == 1 && Port_FileSize(&file, &size) == 1 && size == 0,
                "write mode empties an existing file");
    Port_FileClose(&file);
    Test_Expect(Port_FileSeek(&file, 0) == 0 && Port_FileSize(&file, &size) == 0, "a closed file answers nothing");
    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, 4) == 0, "an unknown mode does not open");

    Test_Expect(Port_FileOpen(&file, SCRATCH_RENAMED, PORT_FILE_WRITE) == 1
                && Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 1, "a second file is written");
    Test_Expect(Port_FileSync(&file) == 1, "and synced through to its storage");
    Port_FileClose(&file);
    Test_Expect(Port_FileSync(&file) == 0, "a closed file has nothing to sync");
    Test_Expect(Port_FileOpen(&file, SCRATCH_RENAMED, PORT_FILE_READ) == 1 && Port_FileSync(&file) == 0,
                "and a file opened to read is not one this call writes through");
    Port_FileClose(&file);
    Test_Expect(Port_FileRename(SCRATCH_RENAMED, SCRATCH_FILE) == 1 && Port_FileExists(SCRATCH_RENAMED) == 0,
                "a rename moves it to the first one's name");
    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ) == 1 && Port_FileSize(&file, &size) == 1
                && size == sizeof second, "and replaces the file that was there");
    Port_FileClose(&file);
    Test_Expect(Port_FileRename(SCRATCH_MISSING, SCRATCH_FILE) == 0 && Port_FileExists(SCRATCH_FILE) == 1,
                "a rename from a missing file fails and leaves the target alone");

    Test_Expect(Port_FileDelete(SCRATCH_FILE) == 1 && Port_FileExists(SCRATCH_FILE) == 0, "a delete removes the file");
    Test_Expect(Port_FileDelete(SCRATCH_FILE) == 0, "and a second delete finds nothing to remove");
    Test_Expect(Port_FileExists(ZB_SCRATCH_DIR) == 0, "a directory is not a file");
}
