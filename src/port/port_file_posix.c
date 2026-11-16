/* Before any include: glibc fixes its feature set at the first system header */
#define _XOPEN_SOURCE 700          /* O_CLOEXEC and the descriptor calls are POSIX, C99 does not imply them */

#include "port_file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* <stdio.h> is the one header that declares rename, and its byte and text calls are src/utils' to give; C99 7.1.4
   lets a function whose prototype names no type of its header be declared without it. */
int rename(const char *from, const char *to);

/* The POSIX files (docs/porting.md §3): a descriptor in the handle, opened close-on-exec, and every call retried
   where a signal interrupted it, so an interrupt is never reported as a failure. */

#define POSIX_FILE_CREATE_MODE 0644 /* rw-r--r--, narrowed by the process's umask */

static int posixFileFlags(uint32_t mode, int *flags)
{
    if (mode == PORT_FILE_READ)
        *flags = O_RDONLY;
    else if (mode == PORT_FILE_WRITE)
        *flags = O_WRONLY | O_CREAT | O_TRUNC;
    else if (mode == PORT_FILE_READ_WRITE)
        *flags = O_RDWR | O_CREAT;
    else
        return 0;

    *flags |= O_CLOEXEC;

    return 1;
}

/* Whether the file is open in a mode that allows `want` */
static int posixFileAllows(const PortFile *file, uint32_t want)
{
    return file != 0 && (file->mode & want) != 0;
}

int Port_FileOpen(PortFile *file, const char *path, uint32_t mode)
{
    int flags;
    int fd;

    if (file == 0)
        return 0;

    file->handle = 0;
    file->mode = 0;
    file->platformErrno = 0;

    if (path == 0 || !posixFileFlags(mode, &flags))
        return 0;

    fd = open(path, flags, POSIX_FILE_CREATE_MODE);

    while (fd < 0 && errno == EINTR)
        fd = open(path, flags, POSIX_FILE_CREATE_MODE);

    if (fd < 0)
    {
        file->platformErrno = (uint32_t)errno;
        return 0;
    }

    file->handle = (uintptr_t)fd;
    file->mode = mode;

    return 1;
}

int Port_FileRead(PortFile *file, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    ssize_t n;

    if (got != 0)
        *got = 0;

    if (!posixFileAllows(file, PORT_FILE_READ) || buf == 0 || got == 0)
        return 0;

    n = read((int)file->handle, buf, (size_t)cap);

    while (n < 0 && errno == EINTR)
        n = read((int)file->handle, buf, (size_t)cap);

    if (n < 0)
    {
        file->platformErrno = (uint32_t)errno;
        return 0;
    }

    *got = (uint32_t)n;

    return 1;
}

int Port_FileWrite(PortFile *file, const uint8_t *bytes, uint32_t len, uint32_t *written)
{
    uint32_t done = 0;
    ssize_t n;

    if (written != 0)
        *written = 0;

    if (!posixFileAllows(file, PORT_FILE_WRITE) || (bytes == 0 && len != 0))
        return 0;

    while (done < len)
    {
        n = write((int)file->handle, bytes + done, (size_t)(len - done));

        if (n < 0 && errno == EINTR)
            continue;

        if (n <= 0)
        {
            file->platformErrno = n < 0 ? (uint32_t)errno : 0;
            break;
        }

        done += (uint32_t)n;
    }

    if (written != 0)
        *written = done;

    return done == len;
}

int Port_FileSeek(PortFile *file, uint32_t offset)
{
    if (file == 0 || file->mode == 0)
        return 0;

    if (lseek((int)file->handle, (off_t)offset, SEEK_SET) < 0)
    {
        file->platformErrno = (uint32_t)errno;
        return 0;
    }

    return 1;
}

int Port_FileSize(PortFile *file, uint32_t *size)
{
    struct stat st;

    if (file == 0 || file->mode == 0 || size == 0)
        return 0;

    if (fstat((int)file->handle, &st) != 0)
    {
        file->platformErrno = (uint32_t)errno;
        return 0;
    }

    if (st.st_size < 0 || (uint64_t)st.st_size > 0xffffffff)
        return 0;

    *size = (uint32_t)st.st_size;

    return 1;
}

void Port_FileClose(PortFile *file)
{
    if (file == 0 || file->mode == 0)
        return;

    (void)close((int)file->handle);
    file->handle = 0;
    file->mode = 0;
}

/* macOS's fsync leaves the data in the drive's own cache, and F_FULLFSYNC is the call that empties it; a system or a
   file system without it is given fsync. */
#ifdef F_FULLFSYNC
#define POSIX_FILE_FULL_SYNC(fd) (fcntl((fd), F_FULLFSYNC) == 0)
#else
#define POSIX_FILE_FULL_SYNC(fd) 0
#endif

int Port_FileSync(PortFile *file)
{
    if (!posixFileAllows(file, PORT_FILE_WRITE))
        return 0;

    if (POSIX_FILE_FULL_SYNC((int)file->handle) || fsync((int)file->handle) == 0)
        return 1;

    file->platformErrno = (uint32_t)errno;

    return 0;
}

int Port_FileDelete(const char *path)
{
    return path != 0 && unlink(path) == 0;
}

int Port_FileRename(const char *from, const char *to)
{
    return from != 0 && to != 0 && rename(from, to) == 0;
}

int Port_FileExists(const char *path)
{
    struct stat st;

    return path != 0 && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}
