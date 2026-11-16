/* The band-A rig of the host suites.
   See rig_band_a.h for the contract. */

#include "rig_band_a.h"

#include "zb_utils.h"

/* Every band-A rig in this tree arms channel 26: a channel this PAN is not on, so nothing a suite composes
   could be taken for measured traffic if the model were ever an RCP (docs/internals/hardware.md §7). */
#define RIG_BAND_A_CHANNEL 26

/* RADIO_CAPS as both ConBee IIs report it (docs/internals/hardware.md §4): TRANSMIT, PHY_FCS, ACK_TIMEOUT and the
   count's own bit. */
#define RIG_BAND_A_CAPS 0x10d
#define RIG_BAND_A_CAPS_NO_ACK_TIMEOUT 0x10c

void Test_BandACapsAcks(Radio_Caps *outCaps)
{
    Zb_memset(outCaps, 0, (uint32_t)sizeof *outCaps);
    outCaps->radioCaps = RIG_BAND_A_CAPS;
    outCaps->hasTransmit = 1;
    outCaps->psduIncludesFcs = 1;
    outCaps->handlesAckTimeout = 1;
}

void Test_BandACapsPendingTable(Radio_Caps *outCaps)
{
    Test_BandACapsAcks(outCaps);

    outCaps->hasPendingTable = 1;
}

void Test_BandACapsNoAcks(Radio_Caps *outCaps)
{
    Test_BandACapsAcks(outCaps);

    outCaps->radioCaps = RIG_BAND_A_CAPS_NO_ACK_TIMEOUT;
    outCaps->handlesAckTimeout = 0;
}

void Test_BandADefaults(Test_BandAConfig *cfg)
{
    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);

    Test_BandACapsAcks(&cfg->caps);
    cfg->deviceType = NWK_DEVICE_ROUTER;
    cfg->rxOnWhenIdle = 1;
    cfg->hearsWhileAsleep = 1;
    cfg->joinSeed = 0;              /* 3.6.1.8: the house constant, which keeps a case's addresses the same run to run */
}

ZbStatus Test_BandABuild(Test_BandA *rig, const Test_BandAConfig *cfg)
{
    Radio_Radio *seam;
    Radio_Pib pib;
    Mac_Config macCfg;
    Nwk_Config nwkCfg;
    ZbStatus status;
    uint32_t i;

    /* The DSN is the application's seed. A config that names none is dsnStart 0, which `mac`
       states is the same default as passing no config at all. */
    Zb_memset(&macCfg, 0, (uint32_t)sizeof macCfg);
    macCfg.dsnStart = (uint8_t)cfg->dsnStart;
    macCfg.log = cfg->log;
    macCfg.hearsWhileAsleep = cfg->hearsWhileAsleep;

    /* The three things the network layer reads about itself, and the receiver duty Table 3-80 prints one of its
       five destination groups as and 3.6.6 opens its sleepy-copy paragraph with. */
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE
        | RADIO_PIB_EXTENDED_ADDRESS;
    pib.shortAddress = cfg->ownAddress;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
    {
        pib.extendedAddress[i] = (uint8_t)((cfg->ownExtended >> (8 * i)) & 0xff);
    }

    pib.panId = cfg->panId;
    pib.channel = RIG_BAND_A_CHANNEL;
    pib.rxOnWhenIdle = cfg->rxOnWhenIdle;

    Zb_memset(&nwkCfg, 0, (uint32_t)sizeof nwkCfg);
    nwkCfg.deviceType = cfg->deviceType;
    nwkCfg.seqStart = cfg->seqStart;
    nwkCfg.jitterSeed = cfg->jitterSeed;
    nwkCfg.joinSeed = cfg->joinSeed;
    nwkCfg.trustCenterIeee = cfg->trustCenterIeee;

    /* Each stage's status is folded into the one this returns, and a stage after the one that refused is not
       attempted: a caller asserting ZB_OK learns which stage said no, and nothing is written into a device that
       is not there. */
    status = LoopbackRadio_Init(&rig->model, &cfg->caps);
    seam = LoopbackRadio_Seam(&rig->model);

    if (status == ZB_OK)
        status = Mac_Init(&rig->mac, seam, &macCfg);

    if (status == ZB_OK)
        status = Mac_SetPib(&rig->mac, &pib);

    if (status == ZB_OK)
        status = Nwk_Init(&rig->nwk, &rig->mac, &nwkCfg);

    Test_NwkForget(&rig->nwk);

    return status;
}

void Test_BandASeedNeighbor(Nwk_Nwk *nwk, uint16_t addr, uint32_t deviceType, int rxOnWhenIdle,
                            uint32_t relationship)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwk->neighbors[i].inUse)
            break;
    }

    if (i == NWK_NEIGHBOR_MAX)
        return;

    nwk->neighbors[i].inUse = 1;
    nwk->neighbors[i].networkAddress = addr;
    nwk->neighbors[i].ieeeKnown = 0;
    nwk->neighbors[i].deviceType = deviceType;
    nwk->neighbors[i].rxOnWhenIdle = rxOnWhenIdle;
    nwk->neighbors[i].relationship = relationship;
}

/* The layer above a device's network layer, played by the case: what the receive held, kept until the case polls */
#define TEST_NWK_DEVICES 8
#define TEST_NWK_KEPT 32

typedef struct TestNwkUpper
{
    const Nwk_Nwk *nwk;
    Nwk_DataIndicationParameters ind[TEST_NWK_KEPT];
    uint8_t nsdu[TEST_NWK_KEPT][NWK_NSDU_MAX];
    uint32_t head;
    uint32_t count;
} TestNwkUpper;

static TestNwkUpper s_upper[TEST_NWK_DEVICES];
static uint32_t s_upperNext;

/* A device's queue, or the longest-held one handed to a device not seen before, emptied */
static TestNwkUpper *testNwkUpper(const Nwk_Nwk *nwk)
{
    TestNwkUpper *upper;
    uint32_t i;

    for (i = 0; i < TEST_NWK_DEVICES; i++)
    {
        if (s_upper[i].nwk == nwk)
            return &s_upper[i];
    }

    upper = &s_upper[s_upperNext];
    s_upperNext = (s_upperNext + 1) % TEST_NWK_DEVICES;
    upper->nwk = nwk;
    upper->head = 0;
    upper->count = 0;

    return upper;
}

void Test_NwkForget(const Nwk_Nwk *nwk)
{
    TestNwkUpper *upper = testNwkUpper(nwk);

    if (upper != 0)
    {
        upper->head = 0;
        upper->count = 0;
    }
}

void Test_NwkTake(Nwk_Nwk *nwk)
{
    TestNwkUpper *upper = testNwkUpper(nwk);
    const Nwk_DataIndicationParameters *held;
    uint32_t slot;

    while ((held = Nwk_Indication(nwk)) != 0)
    {
        if (upper != 0 && upper->count < TEST_NWK_KEPT)
        {
            slot = (upper->head + upper->count) % TEST_NWK_KEPT;
            upper->ind[slot] = *held;

            if (held->nsduLength != 0)
                Zb_memcpy(upper->nsdu[slot], held->nsdu, held->nsduLength);

            upper->ind[slot].nsdu = upper->nsdu[slot];
            upper->count++;
        }

        Nwk_IndicationDone(nwk);
    }
}

ZbStatus Test_NwkStep(Nwk_Nwk *nwk, uint32_t nowMs)
{
    ZbStatus status = Nwk_Step(nwk, nowMs);

    Test_NwkTake(nwk);

    return status;
}

uint32_t Test_NwkPoll(Nwk_Nwk *nwk, Nwk_DataIndicationParameters *out, uint32_t max)
{
    TestNwkUpper *upper;
    uint32_t taken = 0;

    Test_NwkTake(nwk);
    upper = testNwkUpper(nwk);

    while (upper != 0 && taken < max && upper->count > 0)
    {
        out[taken] = upper->ind[upper->head];
        upper->head = (upper->head + 1) % TEST_NWK_KEPT;
        upper->count--;
        taken++;
    }

    return taken;
}
