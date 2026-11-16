#include "port_locate.h"
#include "zb_utils.h"

/* The selector and its match, the same on every target: what a serial names is the platform's to enumerate. */

typedef struct LocateMatch
{
    const char *serial;
    char *device;
    uint32_t capacity;
    uint32_t matches;
    int present;
} LocateMatch;

static int locateEqual(const char *a, const char *b)
{
    uint32_t len = Zb_strlen(a, PORT_LOCATED_MAX);

    return len == Zb_strlen(b, PORT_LOCATED_MAX) && Zb_memcmp(a, b, len) == 0;
}

int PortLocate_IsSelector(const char *path)
{
    uint32_t len = (uint32_t)sizeof PORT_LOCATE_PREFIX - 1;

    return path != 0 && Zb_strlen(path, len) == len && Zb_memcmp(path, PORT_LOCATE_PREFIX, len) == 0;
}

uint32_t PortLocate_Each(const char *root, PortLocate_Visit visit, void *context)
{
    if (root != 0)
        return PortLocate_EachSysfs(root, visit, context);

    return PortLocate_EachPlatform(visit, context);
}

static void locateMatch(void *context, const PortLocate_Candidate *candidate)
{
    LocateMatch *match = (LocateMatch *)context;
    uint32_t len;

    if (!locateEqual(candidate->serial, match->serial))
        return;

    match->matches++;
    match->present = candidate->present;
    len = Zb_strlen(candidate->device, match->capacity - 1);
    Zb_memcpy(match->device, candidate->device, len);
    match->device[len] = 0;
}

ZbStatus PortLocate_Resolve(const char *root, const char *selector, char *device, uint32_t capacity,
                            uint32_t *matches)
{
    LocateMatch match;

    if (matches != 0)
        *matches = 0;

    if (!PortLocate_IsSelector(selector) || device == 0 || capacity == 0)
        return ZB_ERR_BAD_ARGUMENT;

    device[0] = 0;
    match.serial = selector + sizeof PORT_LOCATE_PREFIX - 1;
    match.device = device;
    match.capacity = capacity;
    match.matches = 0;
    match.present = 0;

    if (match.serial[0] == 0)
        return ZB_ERR_BAD_ARGUMENT;

    (void)PortLocate_Each(root, locateMatch, &match);

    if (matches != 0)
        *matches = match.matches;

    if (match.matches > 1)
        return ZB_ERR_BAD_ARGUMENT;

    return match.matches == 1 && match.present ? ZB_OK : ZB_ERR_NO_DEVICE;
}
