#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_map.h"
#include "port.h"
#include "port_posix.h"

/* Bench tool: open a stick's link exclusively, read it, and report what the port
   delivered. It never writes to the device, and it refuses the port another project
   owns (docs/internals/hardware.md §8). No clock is used: the run ends on a byte count or on
   a streak of empty reads. */

#define PROBE_BUF 256

static void usage(void)
{
    printf("usage: port_probe --path <path>|--device <name> [--baud n]\n"
           "                  [--bytes n] [--idle n] [--rx-ring n] [--tx-ring n]\n");
}

int main(int argc, char **argv)
{
    Port port;
    PortConfig config;
    const char *path;
    uint8_t buf[PROBE_BUF];
    uint32_t total;
    uint32_t idle;
    uint32_t got;
    ZbStatus status;
    int i;

    path = 0;
    config.baud = 0;
    config.rxRingSize = 0;
    config.txRingSize = 0;
    config.exclusive = 1;
    total = 0;
    idle = 0;

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc)
            path = deviceMapResolve(argv[++i]);
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc)
        {
            const char *named = deviceMapLookup(argv[++i]);

            if (!named)
            {
                printf("--device takes a name the file ZB_DEVICE_MAP names; give --path otherwise\n");
                return 2;
            }

            path = named;
        }
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < argc) config.baud = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--bytes") == 0 && i + 1 < argc) total = (uint32_t)strtoul(argv[++i], 0, 10) + total;
        else if (strcmp(argv[i], "--idle") == 0 && i + 1 < argc) idle = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--rx-ring") == 0 && i + 1 < argc) config.rxRingSize = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--tx-ring") == 0 && i + 1 < argc) config.txRingSize = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--no-exclusive") == 0) config.exclusive = 0;
        else
        {
            usage();
            return 2;
        }
    }

    if (!path)
    {
        printf("a device is required: --path <path>, or --device with a name the file ZB_DEVICE_MAP holds;\n"
               "no port is ever defaulted (docs/internals/hardware.md §8)\n");
        usage();
        return 2;
    }

    if (idle == 0)
        idle = 8;

    if (total == 0)
        total = 4096;

    status = Port_Init(&port, PortPosixOps());

    if (status != ZB_OK)
        return 1;

    status = Port_Open(&port, path, &config);

    if (status != ZB_OK)
    {
        printf("open %s refused: status %d, fault %d, platform errno %u\n",
               path, (int)status, (int)Port_Fault(&port), Port_PlatformErrno(&port));
        return 1;
    }

    printf("opened %s as target \"%s\", rx ring %u, tx ring %u\n",
           Port_Path(&port), Port_TargetName(&port),
           Port_RxRingSize(&port), Port_TxRingSize(&port));

    {
        uint32_t limit;
        limit = total;
        total = 0;

        while (total < limit && idle > 0)
        {
            status = Port_Read(&port, buf, sizeof buf, &got);

            if (status != ZB_OK)
            {
                printf("read failed: status %d, fault %d, platform errno %u\n",
                       (int)status, (int)Port_Fault(&port), Port_PlatformErrno(&port));
                Port_Close(&port);
                return 1;
            }

            if (got == 0)
            {
                idle--;
                continue;
            }

            idle = 4;

            {
                uint32_t j;

                for (j = 0; j < got; j += 16)
                {
                    uint32_t k;
                    printf("%04x ", total + j);

                    for (k = 0; k < 16 && j + k < got; k++)
                        printf("%02x ", buf[j + k]);

                    printf("\n");
                }
            }

            total += got;
        }
    }

    printf("read %u bytes; drops %u; refusals %u; tx pending %u; state %d\n",
           total, Port_Drops(&port), Port_Refusals(&port), Port_TxPending(&port),
           (int)Port_State(&port));
    Port_Close(&port);
    return 0;
}
