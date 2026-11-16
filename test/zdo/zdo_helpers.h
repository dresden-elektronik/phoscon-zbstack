/* The `zdo` suite's shared machinery: the band-A rig with an APS service, the framework and the device object on
   it, and the request builders the cases send through the framework's own dispatch. */

#ifndef ZDO_HELPERS_H
#define ZDO_HELPERS_H

#include <stdint.h>

#include "af.h"
#include "aps.h"
#include "rig_band_a.h"
#include "zdo.h"

#define ZDO_OWN_SHORT 0xdead
#define ZDO_OWN_IEEE 0x00212effff048a12
#define ZDO_PAN_ID 0xbeef
#define ZDO_PEER_SHORT 0x0011
#define ZDO_PEER_ENDPOINT 0x01

typedef struct Zdo_Rig
{
    Test_BandA stack;
    Aps_Aps aps;
    Af_Af af;
    Zdo_Zdo zdo;
} Zdo_Rig;

void zdoRigBuild(Zdo_Rig *rig);

/* A ZDP command as an application endpoint would hand it to the device object: the transaction sequence number,
   then the command's own fields. */
void zdoDeliver(Zdo_Rig *rig, uint16_t cluster, const uint8_t *asdu, uint32_t asduLength, uint32_t nowMs);

/* The request an APS indication for endpoint 0 is made of, delivered through the framework's dispatch. */
void zdoDeliverCommand(Zdo_Rig *rig, uint16_t cluster, const uint8_t *payload, uint32_t payloadLen, uint32_t nowMs);

/* The same command as it arrives at a broadcast destination, which several of them refuse to process. */
void zdoDeliverBroadcast(Zdo_Rig *rig, uint16_t cluster, const uint8_t *payload, uint32_t payloadLen,
                         uint32_t nowMs);

#endif
