#include <stdio.h>
#include <string.h>

#include "port_locate.h"

/* Which node a `usb-serial:` selector names on this system, and every USB serial device looked at on the way. It opens
   nothing, so it may run beside the program that holds a stick (D-282). */

typedef struct FindRun
{
    const char *serial;
    uint32_t listed;
} FindRun;

static void usage(void)
{
    printf("usage: port_find [--root <dir>] [usb-serial:<serial>]\n"
           "       with no selector, lists every USB serial device; --root reads a sysfs-shaped tree instead\n");
}

static void findShow(void *context, const PortLocate_Candidate *candidate)
{
    FindRun *run = (FindRun *)context;
    const char *mark = run->serial != 0 && strcmp(run->serial, candidate->serial) == 0 ? "*" : " ";

    printf("%s %-32s serial %-20s %04x:%04x %-28s%s\n", mark, candidate->device, candidate->serial,
           candidate->vendorId, candidate->productId, candidate->product, candidate->present ? "" : "  (no node here)");
    run->listed++;
}

int main(int argc, char **argv)
{
    char device[PORT_LOCATED_MAX];
    const char *root = 0;
    const char *selector = 0;
    FindRun run;
    uint32_t matches = 0;
    ZbStatus status;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = argv[++i];
        else if (PortLocate_IsSelector(argv[i]) && selector == 0)
            selector = argv[i];
        else
        {
            usage();
            return 2;
        }
    }

    run.serial = selector != 0 ? selector + sizeof PORT_LOCATE_PREFIX - 1 : 0;
    run.listed = 0;
    (void)PortLocate_Each(root, findShow, &run);
    printf("%u USB serial device(s)\n", (unsigned)run.listed);

    if (selector == 0)
        return 0;

    status = PortLocate_Resolve(root, selector, device, (uint32_t)sizeof device, &matches);

    if (status == ZB_OK)
    {
        printf("%s -> %s\n", selector, device);
        return 0;
    }

    if (matches > 1)
        printf("%s: %u devices carry this serial, so it names none of them\n", selector, (unsigned)matches);
    else if (matches == 1)
        printf("%s: the device is attached, but its node %s is not here (a container that did not map it?)\n",
               selector, device);
    else
        printf("%s: no USB serial device carries this serial\n", selector);

    return 1;
}
