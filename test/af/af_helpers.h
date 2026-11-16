/* The `af` suite's shared machinery: the band-A rig with an APS service on it and the framework on that, one
   endpoint descriptor builder, and the handler a case records its deliveries through. */

#ifndef AF_HELPERS_H
#define AF_HELPERS_H

#include <stdint.h>

#include "af.h"
#include "aps.h"
#include "rig_band_a.h"

#define AF_OWN_SHORT 0xdead
#define AF_PAN_ID 0xbeef
#define AF_PEER_SHORT 0x0011
#define AF_PROFILE 0x0104
#define AF_CLUSTER 0x0006

typedef struct Af_Rig
{
    Test_BandA stack;
    Aps_Aps aps;
    Af_Af af;
} Af_Rig;

/* What a case's handler was given, one per call: the framework's own record of a delivery. */
#define AF_SEEN_MAX 4

typedef struct Af_Seen
{
    uint32_t count;
    Af_Indication indications[AF_SEEN_MAX];
} Af_Seen;

void afRigBuild(Af_Rig *rig, uint16_t own);

/* Table 2-40's descriptor for one endpoint, with one input and one output cluster. */
Af_SimpleDescriptor afDescriptor(uint8_t endpoint, uint16_t profile, uint16_t inputCluster);

/* The handler a case passes when it wants the deliveries recorded rather than dispatched to a real endpoint. */
void afRecord(void *context, const Af_Indication *indication);

/* One indication into the APS service's ring, the way the reception path puts it there: the ring is the module's
   published state and the framework's turn reads nothing else. */
void afInjectIndication(Aps_Aps *aps, const Aps_Indication *indication);

#endif
