#ifndef HEARING_H
#define HEARING_H

#include <stdint.h>

#include "radio.h"

/* A device made deaf to devices in range, at the radio seam, so RCPs that all hear each other can stand for a mesh that
   has to route. It judges the hop and never the originator, so what an ignored device originates arrives through a relay.
   docs/internals/testing.md §7 says how a run uses it; docs/internals/decisions.md says why it is here. */

/* A device is named by its extended address, its short address learned from its first NWK-secured frame, whose auxiliary
   header names the hop (4.3.2). A beacon names neither, so a short address known ahead, the coordinator's, is named too. */
enum
{
    HEARING_IGNORED_MAX = 8,
    HEARING_UNHEARD_MAX = 8
};

typedef struct Hearing_Ignored
{
    uint64_t ieee;
    uint16_t shortAddress;
    int shortKnown;
} Hearing_Ignored;

/* The RCP acknowledges in firmware before the host can drop a frame, so a unicast to an ignored device never reaches
   the air: `unheard` holds those transmits until their NO_ACK is collected, and `observe` is a tool's trace, 0 for none.
   `framesDropped` counts frames heard from an ignored device and `framesUnsent` the unicasts kept off the air. */
typedef struct Hearing
{
    Radio_Radio *backend;
    Radio_Radio seam;
    Hearing_Ignored ignored[HEARING_IGNORED_MAX];
    uint32_t ignoredCount;
    Radio_Handle unheard[HEARING_UNHEARD_MAX];
    uint32_t nextUnheard;
    void (*observe)(const uint8_t *mpdu, uint32_t len, int sent, int cut, ZbStatus status);
    uint32_t framesDropped;
    uint32_t framesUnsent;
} Hearing;

void Hearing_Init(Hearing *self, Radio_Radio *backend);

/* ZB_ERR_NO_SPACE past HEARING_IGNORED_MAX. */
ZbStatus Hearing_IgnoreIeee(Hearing *self, uint64_t ieee);
ZbStatus Hearing_IgnoreShort(Hearing *self, uint16_t shortAddress);

Radio_Radio *Hearing_Seam(Hearing *self);

#endif /* HEARING_H */
