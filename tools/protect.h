#ifndef PROTECT_H
#define PROTECT_H
/*
 * The channels and PANs a bench tool must not arm on or compose for: a network of the user's own that
 * shares the air. Nothing is protected by default, because which networks a bench hears is that bench's;
 * `--protect-channel <n>` and `--protect-pan <id>` each add one, and may be given more than once.
 * An armed RCP acknowledges frames addressed to it, which is a transmission by the device rather than by
 * the tool, so a protected channel is refused even for a run that sends nothing.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum
{
    PROTECT_PAN_MAX = 8
};

typedef struct Protect
{
    uint32_t channelMask;             /* bit n: channel n is protected */
    uint32_t panCount;
    uint16_t pans[PROTECT_PAN_MAX];
} Protect;

/* Reads argv[i] and its value when it is one of the two options: 1 taken (the caller steps past the value),
   0 not this option's, -1 refused. */
static int protectOption(Protect *protect, int argc, char **argv, uint32_t i)
{
    unsigned long value;
    char *end;

    if (strcmp(argv[i], "--protect-channel") != 0 && strcmp(argv[i], "--protect-pan") != 0)
        return 0;

    if (i + 1 >= (uint32_t)argc)
        return -1;

    value = strtoul(argv[i + 1], &end, strcmp(argv[i], "--protect-pan") == 0 ? 16 : 10);

    if (end == argv[i + 1] || *end != 0)
        return -1;

    if (strcmp(argv[i], "--protect-channel") == 0)
    {
        if (value < 11 || value > 26)
            return -1;

        protect->channelMask |= (uint32_t)1 << value;
    }
    else
    {
        if (value > 0xffff || protect->panCount >= PROTECT_PAN_MAX)
            return -1;

        protect->pans[protect->panCount++] = (uint16_t)value;
    }

    return 1;
}

static int protectChannel(const Protect *protect, uint32_t channel)
{
    return channel < 32 && (protect->channelMask & ((uint32_t)1 << channel)) != 0;
}

static int protectPan(const Protect *protect, uint32_t pan)
{
    uint32_t k;

    for (k = 0; k < protect->panCount; k++)
    {
        if (protect->pans[k] == pan)
            return 1;
    }

    return 0;
}

#endif
