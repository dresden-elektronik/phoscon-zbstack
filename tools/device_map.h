#ifndef DEVICE_MAP_H
#define DEVICE_MAP_H
/*
 * A bench's RCPs by the names its user gives them, read from the file the environment variable
 * ZB_DEVICE_MAP names: one `name path` pair per line, `#` starting a comment. Nothing is built in,
 * because a port name belongs to one machine; `--path` (or `usb-serial:<serial>`) works everywhere.
 * `deviceMapResolve` answers the path a name maps to and otherwise the spelling unchanged, so `--path`
 * still opens a driver node or a symlink the file never names. `deviceMapLookup` answers 0 for a name
 * the file does not hold, or when there is no file, which is what `--device` refuses.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum
{
    DEVICE_MAP_LINE_MAX = 512
};

static const char *deviceMapLookup(const char *spelling)
{
    static char found[DEVICE_MAP_LINE_MAX];
    char line[DEVICE_MAP_LINE_MAX];
    const char *mapPath = getenv("ZB_DEVICE_MAP");
    FILE *file;

    if (mapPath == 0 || mapPath[0] == 0 || spelling == 0)
        return 0;

    file = fopen(mapPath, "r");

    if (file == 0)
        return 0;

    while (fgets(line, (int)sizeof line, file) != 0)
    {
        char name[DEVICE_MAP_LINE_MAX];

        if (line[0] == '#')
            continue;

        if (sscanf(line, "%511s %511s", name, found) == 2 && strcmp(name, spelling) == 0)
        {
            fclose(file);
            return found;
        }
    }

    fclose(file);
    return 0;
}

static const char *deviceMapResolve(const char *spelling)
{
    const char *path = deviceMapLookup(spelling);

    return path ? path : spelling;
}

#endif
