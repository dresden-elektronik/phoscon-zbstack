#ifndef PORT_FILE_H
#define PORT_FILE_H

#include <stdint.h>

/* Files, for an application on a target that has them (docs/porting.md §3): the backend the build links defines
   these calls as it defines Port_NowMs, and no band of the library calls them. Each answers 1 for success and 0 for
   failure, a count comes back through its argument, and a failure leaves the platform's error in `platformErrno`. */

/* An open file: the platform's handle kept as an opaque integer, a descriptor on one target and a handle on
   another, as Port keeps its device. `mode` is 0 while the file is closed. */
typedef struct PortFile
{
    uintptr_t handle;
    uint32_t mode;
    uint32_t platformErrno;
} PortFile;

enum
{
    PORT_FILE_READ = 1,             /* an existing file, read only */
    PORT_FILE_WRITE = 2,            /* created or emptied, write only */
    PORT_FILE_READ_WRITE = 3        /* created if missing and kept if not, read and write */
};

/* Opens `path` in one of the three modes; a file that fails to open is left closed. */
int Port_FileOpen(PortFile *file, const char *path, uint32_t mode);

/* Reads up to `cap` octets at the file's position; at the end of the file it succeeds with `*got` 0. */
int Port_FileRead(PortFile *file, uint8_t *buf, uint32_t cap, uint32_t *got);

/* Writes all `len` octets or fails; `*written` says how many went out before a failure. */
int Port_FileWrite(PortFile *file, const uint8_t *bytes, uint32_t len, uint32_t *written);

/* Moves the position to `offset` octets from the start. */
int Port_FileSeek(PortFile *file, uint32_t offset);

/* The file's size in octets; a file of 4 GiB or more fails. */
int Port_FileSize(PortFile *file, uint32_t *size);

/* Writes what the file holds through to its storage, past the system's caches, so a power cut keeps it: a save that
   syncs before it renames is never lost half-written. */
int Port_FileSync(PortFile *file);

/* Closes the file; closing a closed file does nothing. */
void Port_FileClose(PortFile *file);

/* Removes the file at `path`. */
int Port_FileDelete(const char *path);

/* Gives the file at `from` the name `to`, replacing a file already there in one step: a reader finds the old file or
   the new one, never neither. Both names are on one file system. */
int Port_FileRename(const char *from, const char *to);

/* 1 when `path` names a regular file. */
int Port_FileExists(const char *path);

#endif /* PORT_FILE_H */
