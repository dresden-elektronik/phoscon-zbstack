#include "mesh_air.h"

#include "mac_frame.h"
#include "zb_utils.h"

/* The device a unicast is addressed to, or the node count when no device on this air holds that address. */
static uint32_t meshAirNodeAt(const Mesh_Air *air, uint16_t shortAddress)
{
    uint32_t i;

    for (i = 0; i < air->count; i++)
    {
        if (Mac_Pib((Mac_Mac *)&air->nodes[i]->mac)->shortAddress == shortAddress)
            return i;
    }

    return air->count;
}

static void meshAirDeliver(Mesh_Air *air, uint32_t talker, const uint8_t *mpdu, uint32_t len)
{
    Loopback_FrameSpec spec;
    uint32_t i;

    for (i = 0; i < air->count; i++)
    {
        if (i == talker)
            continue;

        if (!air->hears[i][talker])
        {
            air->notHeard++;
            continue;
        }

        Zb_memset(&spec, 0, (uint32_t)sizeof spec);

        spec.len = len;
        spec.bytes = mpdu;
        spec.rssiDbm = MESH_AIR_RSSI_DBM;
        spec.lqi = air->lqi[i][talker];
        spec.stampTicks = 2;

        if (LoopbackRadio_Inject(&air->nodes[i]->model, &spec, 1) == ZB_OK)
            air->delivered++;
    }
}

/* An acknowledgement crosses the link the other way, so a unicast needs both directions: an unheard one ends as the
   RCP reports it, not answered. */
static void meshAirAnswer(const Mesh_Air *air, uint32_t talker, const uint8_t *mpdu, uint32_t len, int ackRequest,
                          Loopback_Outcome *outcome)
{
    Mac_Frame header;
    Mac_FrameRefusal refusal;
    const uint8_t *payload;
    uint32_t payloadLen;
    uint32_t to;

    if (!ackRequest)
        return;

    if (MacFrame_Parse(mpdu, len, air->nodes[talker]->model.caps.psduIncludesFcs, &header, &payload, &payloadLen,
                       &refusal) != ZB_OK)
        return;

    to = meshAirNodeAt(air, header.destShort);

    if (to < air->count && air->hears[to][talker] && air->hears[talker][to])
        return;

    outcome->status = ZB_ERR_DEVICE;
    outcome->isAcked = 0;
}

static void meshAirTx(void *context, const uint8_t *mpdu, uint32_t len, int ackRequest, Loopback_Outcome *outcome)
{
    Mesh_AirPort *port = (Mesh_AirPort *)context;

    meshAirDeliver(port->air, port->index, mpdu, len);
    meshAirAnswer(port->air, port->index, mpdu, len, ackRequest, outcome);

    if (port->air->busyTurns != 0)
    {
        port->air->busyFor[port->index] = port->air->busyTurns;
        LoopbackRadio_RefuseTx(&port->air->nodes[port->index]->model, ZB_ERR_NO_SPACE, MESH_AIR_REFUSALS);
    }
}

void MeshAir_Init(Mesh_Air *air)
{
    Zb_memset(air, 0, (uint32_t)sizeof *air);
}

uint32_t MeshAir_Add(Mesh_Air *air, Test_BandA *node)
{
    uint32_t index = air->count;
    uint32_t i;

    air->nodes[index] = node;
    air->ports[index].air = air;
    air->ports[index].index = index;
    air->count++;

    for (i = 0; i < air->count; i++)
    {
        air->hears[index][i] = 1;
        air->hears[i][index] = 1;
        air->lqi[index][i] = MESH_AIR_DEFAULT_LQI;
        air->lqi[i][index] = MESH_AIR_DEFAULT_LQI;
    }

    LoopbackRadio_SetTxObserver(&node->model, meshAirTx, &air->ports[index]);

    return index;
}

void MeshAir_Deaf(Mesh_Air *air, uint32_t listener, uint32_t talker)
{
    air->hears[listener][talker] = 0;
}

void MeshAir_Lqi(Mesh_Air *air, uint32_t listener, uint32_t talker, uint8_t lqi)
{
    air->lqi[listener][talker] = lqi;
}

void MeshAir_OneFrameAtATime(Mesh_Air *air, uint32_t turns)
{
    air->busyTurns = turns;
}

void MeshAir_Turn(Mesh_Air *air, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < air->count; i++)
    {
        if (air->busyFor[i] != 0)
            air->busyFor[i]--;
        else if (air->busyTurns != 0)
            LoopbackRadio_RefuseTx(&air->nodes[i]->model, ZB_OK, 0);

        (void)Nwk_Step(&air->nodes[i]->nwk, nowMs);
        Test_NwkTake(&air->nodes[i]->nwk);
    }
}

uint32_t MeshAir_Run(Mesh_Air *air, uint32_t fromMs, uint32_t toMs, uint32_t stepMs)
{
    uint32_t at = fromMs;

    while (at <= toMs)
    {
        MeshAir_Turn(air, at);
        at += stepMs;
    }

    return at;
}
