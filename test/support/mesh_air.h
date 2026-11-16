/* Several band-A devices on one simulated air, and a say over who hears whom.

   Each device's radio tells this air of a transmit as it is issued, and the frame arrives in front of every device
   that hears the sender, at the LQI of that one link. A unicast is acknowledged only when the two hear each other, so
   a device that transmits across a gap learns of it as it would on a real network. Everyone hears everyone until a
   case says otherwise, and hearing is one direction at a time, which is how an asymmetric link is stated.

   A test instrument: the stack under test knows nothing of it (docs/internals/testing.md). */

#ifndef MESH_AIR_H
#define MESH_AIR_H

#include <stdint.h>

#include "rig_band_a.h"

enum
{
    MESH_AIR_REFUSALS = 1000,   /* no run asks a busy radio this often */
    MESH_AIR_NODE_MAX = 6,
    MESH_AIR_DEFAULT_LQI = 200,
    MESH_AIR_RSSI_DBM = -60
};

typedef struct Mesh_Air Mesh_Air;

typedef struct Mesh_AirPort
{
    Mesh_Air *air;
    uint32_t index;
} Mesh_AirPort;

struct Mesh_Air
{
    Test_BandA *nodes[MESH_AIR_NODE_MAX];
    Mesh_AirPort ports[MESH_AIR_NODE_MAX];
    uint32_t count;
    uint8_t hears[MESH_AIR_NODE_MAX][MESH_AIR_NODE_MAX];    /* [listener][talker] */
    uint8_t lqi[MESH_AIR_NODE_MAX][MESH_AIR_NODE_MAX];      /* [listener][talker] */
    uint32_t delivered;
    uint32_t notHeard;
    uint32_t busyTurns;                                     /* a transmit holds a radio for this many turns after its own */
    uint32_t busyFor[MESH_AIR_NODE_MAX];
};

void MeshAir_Init(Mesh_Air *air);

/* Puts a built device on the air and answers its index, the name the two calls below take. */
uint32_t MeshAir_Add(Mesh_Air *air, Test_BandA *node);

/* `listener` no longer hears `talker`, in that direction only. */
void MeshAir_Deaf(Mesh_Air *air, uint32_t listener, uint32_t talker);

/* A radio takes one frame at a time, as an RCP does: a transmit refuses the next ones for no room, for the rest of this
   turn and `turns` more. */
void MeshAir_OneFrameAtATime(Mesh_Air *air, uint32_t turns);

/* What `listener` measures of `talker`. */
void MeshAir_Lqi(Mesh_Air *air, uint32_t listener, uint32_t talker, uint8_t lqi);

/* One turn of every device at `nowMs`, a frame sent on it arriving by the next. */
void MeshAir_Turn(Mesh_Air *air, uint32_t nowMs);

/* Turns every `stepMs` from `fromMs` up to and including `toMs`, the time the run reached being the answer. */
uint32_t MeshAir_Run(Mesh_Air *air, uint32_t fromMs, uint32_t toMs, uint32_t stepMs);

#endif /* MESH_AIR_H */
