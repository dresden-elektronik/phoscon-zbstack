/* Before any include: the smallest <windows.h> that still declares the file calls */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include "port_file.h"

#include <windows.h>

/* The Windows files (docs/porting.md §3): a file handle in PortFile's handle, and GetLastError carried out as the
   platform's error. */

static int win32FileAccess(uint32_t mode, DWORD *access, DWORD *disposition)
{
    if (mode == PORT_FILE_READ)
    {
        *access = GENERIC_READ;
        *disposition = OPEN_EXISTING;
    }
    else if (mode == PORT_FILE_WRITE)
    {
        *access = GENERIC_WRITE;
        *disposition = CREATE_ALWAYS;
    }
    else if (mode == PORT_FILE_READ_WRITE)
    {
        *access = GENERIC_READ | GENERIC_WRITE;
        *disposition = OPEN_ALWAYS;
    }
    else
        return 0;

    return 1;
}

/* Whether the file is open in a mode that allows `want` */
static int win32FileAllows(const PortFile *file, uint32_t want)
{
    return file != 0 && (file->mode & want) != 0;
}

static int win32FileFailed(PortFile *file)
{
    file->platformErrno = (uint32_t)GetLastError();
    return 0;
}

int Port_FileOpen(PortFile *file, const char *path, uint32_t mode)
{
    DWORD access;
    DWORD disposition;
    HANDLE handle;

    if (file == 0)
        return 0;

    file->handle = 0;
    file->mode = 0;
    file->platformErrno = 0;

    if (path == 0 || !win32FileAccess(mode, &access, &disposition))
        return 0;

    /* Shared every way, as a POSIX open is, and for delete too, so a reader holding the file does not stop a save from
       renaming over it. */
    handle = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, disposition,
                         FILE_ATTRIBUTE_NORMAL, 0);

    if (handle == INVALID_HANDLE_VALUE)
        return win32FileFailed(file);

    file->handle = (uintptr_t)handle;
    file->mode = mode;

    return 1;
}

int Port_FileRead(PortFile *file, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    DWORD n = 0;

    if (got != 0)
        *got = 0;

    if (!win32FileAllows(file, PORT_FILE_READ) || buf == 0 || got == 0)
        return 0;

    if (!ReadFile((HANDLE)file->handle, buf, (DWORD)cap, &n, 0))
        return win32FileFailed(file);

    *got = (uint32_t)n;

    return 1;
}

int Port_FileWrite(PortFile *file, const uint8_t *bytes, uint32_t len, uint32_t *written)
{
    uint32_t done = 0;
    DWORD n;

    if (written != 0)
        *written = 0;

    if (!win32FileAllows(file, PORT_FILE_WRITE) || (bytes == 0 && len != 0))
        return 0;

    while (done < len)
    {
        n = 0;

        if (!WriteFile((HANDLE)file->handle, bytes + done, (DWORD)(len - done), &n, 0))
        {
            (void)win32FileFailed(file);
            break;
        }

        if (n == 0)
            break;

        done += (uint32_t)n;
    }

    if (written != 0)
        *written = done;

    return done == len;
}

int Port_FileSeek(PortFile *file, uint32_t offset)
{
    LARGE_INTEGER to;

    if (file == 0 || file->mode == 0)
        return 0;

    to.QuadPart = (LONGLONG)offset;

    if (!SetFilePointerEx((HANDLE)file->handle, to, 0, FILE_BEGIN))
        return win32FileFailed(file);

    return 1;
}

int Port_FileSize(PortFile *file, uint32_t *size)
{
    LARGE_INTEGER bytes;

    if (file == 0 || file->mode == 0 || size == 0)
        return 0;

    if (!GetFileSizeEx((HANDLE)file->handle, &bytes))
        return win32FileFailed(file);

    if (bytes.QuadPart < 0 || (uint64_t)bytes.QuadPart > 0xffffffff)
        return 0;

    *size = (uint32_t)bytes.QuadPart;

    return 1;
}

void Port_FileClose(PortFile *file)
{
    if (file == 0 || file->mode == 0)
        return;

    (void)CloseHandle((HANDLE)file->handle);
    file->handle = 0;
    file->mode = 0;
}

/* FlushFileBuffers writes the system's cache through and asks the drive to empty its own. */
int Port_FileSync(PortFile *file)
{
    if (!win32FileAllows(file, PORT_FILE_WRITE))
        return 0;

    if (FlushFileBuffers((HANDLE)file->handle))
        return 1;

    return win32FileFailed(file);
}

int Port_FileDelete(const char *path)
{
    return path != 0 && DeleteFileA(path) != 0;
}

/* MOVEFILE_REPLACE_EXISTING is what makes this the POSIX rename, which replaces in one step; without it a file
   already at `to` refuses the move. MOVEFILE_WRITE_THROUGH returns once the move is on the disk. */
int Port_FileRename(const char *from, const char *to)
{
    return from != 0 && to != 0 && MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

int Port_FileExists(const char *path)
{
    DWORD attributes;

    if (path == 0)
        return 0;

    attributes = GetFileAttributesA(path);

    return attributes != INVALID_FILE_ATTRIBUTES
           && (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) == 0;
}
