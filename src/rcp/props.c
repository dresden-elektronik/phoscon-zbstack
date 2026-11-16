#include "props.h"
#include "zb_utils.h"

/*
 * Two tables, one per dialect, both built from what was read or written on a real RCP (docs/internals/protocol.md
 * §7.1, §7.2 and docs/internals/hardware.md §3). Where a property exists upstream but was never read from
 * an RCP here it is left out: an entry is a claim about a device, and a claim that has not
 * earned is a gap in the table rather than an assumption.
 */

static const Prop_Entry openthreadCatalogue[] =
{
    { PROP_LAST_STATUS,            PROPS_OP_NOTIFY, PROP_KIND_PACKED_U,       0,                              "LAST_STATUS" },
    { PROP_PROTOCOL_VERSION,       PROPS_OP_GET,    PROP_KIND_ARRAY_PACKED_U, 0,                              "PROTOCOL_VERSION" },
    { PROP_NCP_VERSION,            PROPS_OP_GET,    PROP_KIND_UTF8,           0,                              "NCP_VERSION" },
    { PROP_INTERFACE_TYPE,         PROPS_OP_GET,    PROP_KIND_U8,             0,                              "INTERFACE_TYPE" },
    { PROP_CAPS,                   PROPS_OP_GET,    PROP_KIND_ARRAY_PACKED_U, 0,                              "CAPS" },
    { PROP_HWADDR,                 PROPS_OP_GET,    PROP_KIND_ADDR_BE,        0,                              "HWADDR" },
    { PROP_PHY_ENABLED,            PROPS_OP_RW,     PROP_KIND_BOOL,           0,                              "PHY_ENABLED" },
    { PROP_PHY_CHAN,               PROPS_OP_RW,     PROP_KIND_U8,             RADIO_PIB_CHANNEL,              "PHY_CHAN" },
    { PROP_PHY_CHAN_SUPPORTED,     PROPS_OP_GET,    PROP_KIND_ARRAY_U8,       0,                              "PHY_CHAN_SUPPORTED" },
    { PROP_PHY_CCA_THRESHOLD,      PROPS_OP_GET,    PROP_KIND_I8,             RADIO_PIB_CCA_THRESHOLD_DBM,    "PHY_CCA_THRESHOLD" },
    { PROP_MAC_15_4_LADDR,         PROPS_OP_RW,     PROP_KIND_ADDR_BE,        RADIO_PIB_EXTENDED_ADDRESS,     "MAC_15_4_LADDR" },
    { PROP_MAC_15_4_SADDR,         PROPS_OP_RW,     PROP_KIND_U16_LE,         RADIO_PIB_SHORT_ADDRESS,        "MAC_15_4_SADDR" },
    { PROP_MAC_15_4_PANID,         PROPS_OP_RW,     PROP_KIND_U16_LE,         RADIO_PIB_PAN_ID,               "MAC_15_4_PANID" },
    { PROP_MAC_RAW_STREAM_ENABLED, PROPS_OP_RW,     PROP_KIND_BOOL,           0,                              "MAC_RAW_STREAM_ENABLED" },
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_OP_RW,     PROP_KIND_U8,             0,                              "MAC_PROMISCUOUS_MODE" },
    { PROP_STREAM_RAW,             PROPS_OP_WR,     PROP_KIND_DATA,           0,                              "STREAM_RAW" },
    { PROP_RCP_API_VERSION,        PROPS_OP_GET,    PROP_KIND_PACKED_U,       0,                              "RCP_API_VERSION" },
    { PROP_RCP_MIN_HOST_API_VERSION, PROPS_OP_GET,  PROP_KIND_PACKED_U,       0,                              "RCP_MIN_HOST_API_VERSION" },
    { PROP_UNSOL_UPDATE_FILTER,    PROPS_OP_IR,     PROP_KIND_ARRAY_PACKED_U, 0,                              "UNSOL_UPDATE_FILTER" },
    { PROP_RADIO_CAPS,             PROPS_OP_GET,    PROP_KIND_PACKED_U,       0,                              "RADIO_CAPS" }
};

/*
 * The AT86RF233 build. PHY_TX_POWER, PHY_RSSI and PHY_RX_SENSITIVITY are here because a GET was
 * answered for each; PHY_RSSI answers -128 on an idle radio, which is a sentinel and not a
 * measurement, and that is a reason to read the shape as signed rather than trust the octet.
 * PHY_TX_POWER and PHY_CCA_THRESHOLD carry a write each: both were written and read back, and the
 * RCP echoed both (docs/internals/protocol.md §7.4.3). The CCA threshold is offered no guard by the device
 * (it stored +127 dBm), so the range in this table is band B's own.
 *
 * MAC_RX_ON_WHEN_IDLE exists here and not on the OpenThread build (docs/internals/hardware.md §3): the
 * same PIB field is carried by one RCP and refused by the other.
 *
 * The scan group is in this table because the current revision answers it: a GET of 0x30, 0x31 and
 * 0x32 each returned a value, and each accepted a write (docs/internals/hardware.md §3, docs/internals/protocol.md
 * §7.4). MAC_SCAN_BEACON (0x33) stays in the absent group: a GET of it was refused. The result id
 * 0x39 is a notification, not a readable property (a GET of it answers PROP_NOT_FOUND) and its
 * value is the channel octet followed by a signed level, so the kind names the level, which is the
 * one band B carries upward (docs/internals/protocol.md §7.4.1). RCP_LOG_CRASH_DUMP arrives unsolicited on
 * this build from the moment the port opens: band B recognises the id and
 * discards what it carries, and never writes it, because silencing it would change what the radio
 * records for whoever drives the port next.
 *
 * Being in the table is not permission to ask. A revision of this same build refused the whole group
 * (docs/internals/protocol.md §7.2), and D-123 makes the device's own answer the gate.
 *
 * The source-match family is here because the current revision answers it: a GET of 0x1303 returned `00`, and
 * 0x1304 and 0x1305 returned empty lists. It is the lever 10.22.3's Frame Pending bit
 * needs, and it is absent from the OpenThread table because it has not been read there.
 */
static const Prop_Entry dspinelCatalogue[] =
{
    { PROP_LAST_STATUS,            PROPS_OP_NOTIFY, PROP_KIND_PACKED_U,       0,                              "LAST_STATUS" },
    { PROP_PROTOCOL_VERSION,       PROPS_OP_GET,    PROP_KIND_ARRAY_PACKED_U, 0,                              "PROTOCOL_VERSION" },
    { PROP_NCP_VERSION,            PROPS_OP_GET,    PROP_KIND_UTF8,           0,                              "NCP_VERSION" },
    { PROP_INTERFACE_TYPE,         PROPS_OP_GET,    PROP_KIND_U8,             0,                              "INTERFACE_TYPE" },
    { PROP_CAPS,                   PROPS_OP_GET,    PROP_KIND_ARRAY_PACKED_U, 0,                              "CAPS" },
    { PROP_HWADDR,                 PROPS_OP_GET,    PROP_KIND_ADDR_BE,        0,                              "HWADDR" },
    { PROP_PHY_ENABLED,            PROPS_OP_RW,     PROP_KIND_BOOL,           0,                              "PHY_ENABLED" },
    { PROP_PHY_CHAN,               PROPS_OP_RW,     PROP_KIND_U8,             RADIO_PIB_CHANNEL,              "PHY_CHAN" },
    { PROP_PHY_CCA_THRESHOLD,      PROPS_OP_RW,     PROP_KIND_I8,             RADIO_PIB_CCA_THRESHOLD_DBM,    "PHY_CCA_THRESHOLD" },
    { PROP_PHY_TX_POWER,           PROPS_OP_RW,     PROP_KIND_I8,             0,                              "PHY_TX_POWER" },
    { PROP_PHY_RSSI,               PROPS_OP_GET,    PROP_KIND_I8,             0,                              "PHY_RSSI" },
    { PROP_PHY_RX_SENSITIVITY,     PROPS_OP_GET,    PROP_KIND_I8,             0,                              "PHY_RX_SENSITIVITY" },
    { PROP_MAC_15_4_LADDR,         PROPS_OP_RW,     PROP_KIND_ADDR_BE,        RADIO_PIB_EXTENDED_ADDRESS,     "MAC_15_4_LADDR" },
    { PROP_MAC_15_4_SADDR,         PROPS_OP_RW,     PROP_KIND_U16_LE,         RADIO_PIB_SHORT_ADDRESS,        "MAC_15_4_SADDR" },
    { PROP_MAC_15_4_PANID,         PROPS_OP_RW,     PROP_KIND_U16_LE,         RADIO_PIB_PAN_ID,               "MAC_15_4_PANID" },
    { PROP_MAC_RAW_STREAM_ENABLED, PROPS_OP_RW,     PROP_KIND_BOOL,           0,                              "MAC_RAW_STREAM_ENABLED" },
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_OP_RW,     PROP_KIND_U8,             0,                              "MAC_PROMISCUOUS_MODE" },
    { PROP_MAC_SCAN_STATE,         PROPS_OP_RW,     PROP_KIND_U8,             0,                              "MAC_SCAN_STATE" },
    { PROP_MAC_SCAN_MASK,          PROPS_OP_RW,     PROP_KIND_ARRAY_U8,       0,                              "MAC_SCAN_MASK" },
    { PROP_MAC_SCAN_PERIOD,        PROPS_OP_RW,     PROP_KIND_U16_LE,         0,                              "MAC_SCAN_PERIOD" },
    { PROP_MAC_ENERGY_SCAN_RESULT, PROPS_OP_NOTIFY, PROP_KIND_I8,             0,                              "MAC_ENERGY_SCAN_RESULT" },
    { PROP_MAC_RX_ON_WHEN_IDLE,    PROPS_OP_RW,     PROP_KIND_BOOL,           RADIO_PIB_RX_ON_WHEN_IDLE,      "MAC_RX_ON_WHEN_IDLE" },
    { PROP_STREAM_RAW,             PROPS_OP_WR,     PROP_KIND_DATA,           0,                              "STREAM_RAW" },
    { PROP_RCP_API_VERSION,        PROPS_OP_GET,    PROP_KIND_PACKED_U,       0,                              "RCP_API_VERSION" },
    { PROP_RCP_MIN_HOST_API_VERSION, PROPS_OP_GET,  PROP_KIND_PACKED_U,       0,                              "RCP_MIN_HOST_API_VERSION" },
    { PROP_RCP_LOG_CRASH_DUMP,     PROPS_OP_NOTIFY, PROP_KIND_U8,             0,                              "RCP_LOG_CRASH_DUMP" },
    { PROP_RADIO_CAPS,             PROPS_OP_GET,    PROP_KIND_PACKED_U,       0,                              "RADIO_CAPS" },
    { PROP_MAC_SRC_MATCH_ENABLED,  PROPS_OP_RW,     PROP_KIND_BOOL,           0,                              "MAC_SRC_MATCH_ENABLED" },
    { PROP_MAC_SRC_MATCH_SHORT_ADDRESSES, PROPS_OP_RW | PROPS_OP_IR, PROP_KIND_ARRAY_U16_LE, 0,                   "MAC_SRC_MATCH_SHORT_ADDRESSES" },
    { PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES, PROPS_OP_RW | PROPS_OP_IR, PROP_KIND_ARRAY_ADDR_BE, 0,                "MAC_SRC_MATCH_EXTENDED_ADDRESSES" }
};

static const Prop_Step openthreadArmSteps[] =
{
    { PROP_PHY_ENABLED,            1 },
    { PROP_PHY_CHAN,               PROPS_STEP_RUNTIME },
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_PROMISCUOUS_FULL },
    { PROP_MAC_RAW_STREAM_ENABLED, 1 }
};

static const Prop_Step dspinelArmSteps[] =
{
    { PROP_PHY_ENABLED,            1 },
    { PROP_PHY_CHAN,               PROPS_STEP_RUNTIME },
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_PROMISCUOUS_FULL },
    { PROP_MAC_RX_ON_WHEN_IDLE,    1 },
    { PROP_MAC_RAW_STREAM_ENABLED, 1 }
};

/* Order is the point: the raw stream goes off last (docs/internals/protocol.md §6). */
static const Prop_Step teardownSteps[] =
{
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_PROMISCUOUS_OFF },
    { PROP_PHY_ENABLED,            0 },
    { PROP_MAC_RAW_STREAM_ENABLED, 0 }
};

/*
 * The same order with the one write this dialect needs and the other does not have. Three §6 writes
 * leave MAC_RX_ON_WHEN_IDLE set on the AT86RF233 build, which the next opener
 * of the port inherits. It goes before PHY_ENABLED rather than after it because the radio is still on
 * there, and after promiscuous mode because §6's order is what keeps a teardown from answering BUSY.
 */
static const Prop_Step dspinelTeardownSteps[] =
{
    { PROP_MAC_PROMISCUOUS_MODE,   PROPS_PROMISCUOUS_OFF },
    { PROP_MAC_RX_ON_WHEN_IDLE,    0 },
    { PROP_PHY_ENABLED,            0 },
    { PROP_MAC_RAW_STREAM_ENABLED, 0 }
};

static const char versionPrefixOpenThread[] = "SL-OPENTHREAD";
static const char versionPrefixDspinel[] = "DSPINEL";

static const Prop_Entry *dialectTable(Props_Dialect dialect, uint32_t *outLen);

static int surfaceBit(Props_Dialect dialect, uint32_t id, uint32_t *outBit)
{
    const Prop_Entry *table;
    uint32_t count;
    uint32_t i;

    table = dialectTable(dialect, &count);

    if (table == 0)
        return 0;

    for (i = 0; i < count; i++)
    {
        if (table[i].id == id)
        {
            if (i >= PROPS_SURFACE_WIDTH)
                return 0;

            *outBit = i;
            return 1;
        }
    }

    return 0;
}

void Props_SurfaceInit(Prop_Surface *surface)
{
    if (surface == 0)
        return;

    surface->known = 0;
    surface->absent = 0;
}

void Props_SurfaceNote(Prop_Surface *surface, Props_Dialect dialect, uint32_t id, int answered)
{
    uint32_t bit;

    if (surface == 0 || !surfaceBit(dialect, id, &bit))
        return;

    if (answered)
        surface->known |= (uint64_t)1 << bit;
    else
        surface->absent |= (uint64_t)1 << bit;
}

int Props_SurfaceState(const Prop_Surface *surface, Props_Dialect dialect, uint32_t id)
{
    uint32_t bit;

    if (surface == 0 || !surfaceBit(dialect, id, &bit))
        return PROPS_SURFACE_UNKNOWN;

    if (surface->known & ((uint64_t)1 << bit))
        return PROPS_SURFACE_KNOWN;

    if (surface->absent & ((uint64_t)1 << bit))
        return PROPS_SURFACE_ABSENT;

    return PROPS_SURFACE_UNKNOWN;
}

uint32_t Props_SurfaceIndex(Props_Dialect dialect, uint32_t id)
{
    uint32_t bit;

    if (!surfaceBit(dialect, id, &bit))
        return PROPS_SURFACE_NONE;

    return bit;
}

static const Prop_Entry *dialectTable(Props_Dialect dialect, uint32_t *outLen)
{
    *outLen = 0;

    if (dialect == PROPS_DIALECT_OPENTHREAD)
    {
        *outLen = (uint32_t)(sizeof openthreadCatalogue / sizeof openthreadCatalogue[0]);
        return openthreadCatalogue;
    }

    if (dialect == PROPS_DIALECT_DSPINEL)
    {
        *outLen = (uint32_t)(sizeof dspinelCatalogue / sizeof dspinelCatalogue[0]);
        return dspinelCatalogue;
    }

    return 0;
}

const Prop_Entry *Props_Catalogue(Props_Dialect dialect, uint32_t *outLen)
{
    if (outLen == 0)
        return 0;

    return dialectTable(dialect, outLen);
}

const Prop_Entry *Props_Find(Props_Dialect dialect, uint32_t id)
{
    const Prop_Entry *table;
    uint32_t count;
    uint32_t i;

    table = dialectTable(dialect, &count);

    if (table == 0)
        return 0;

    for (i = 0; i < count; i++)
    {
        if (table[i].id == id)
            return &table[i];
    }

    return 0;
}

int Props_Supports(Props_Dialect dialect, uint32_t id, uint16_t op)
{
    const Prop_Entry *entry = Props_Find(dialect, id);

    if (entry == 0)
        return 0;

    return (entry->ops & op) != 0;
}

int Props_Known(Props_Dialect dialect)
{
    return dialect == PROPS_DIALECT_OPENTHREAD || dialect == PROPS_DIALECT_DSPINEL;
}

ZbStatus Props_ForPib(Props_Dialect dialect, uint32_t pibField, Prop_Entry *out)
{
    const Prop_Entry *table;
    uint32_t count;
    uint32_t i;

    if (out == 0 || pibField == 0)
        return ZB_ERR_BAD_ARGUMENT;

    table = dialectTable(dialect, &count);

    if (table == 0)
        return ZB_ERR_UNSUPPORTED;

    for (i = 0; i < count; i++)
    {
        if (table[i].pib == pibField)
        {
            *out = table[i];
            return ZB_OK;
        }
    }

    return ZB_ERR_UNSUPPORTED;
}

uint32_t Props_KindBytes(uint8_t kind)
{
    if (kind == PROP_KIND_BOOL || kind == PROP_KIND_U8 || kind == PROP_KIND_I8)
        return 1;

    if (kind == PROP_KIND_U16_LE)
        return 2;

    if (kind == PROP_KIND_ADDR_BE)
        return RADIO_ADDR_LEN;

    return 0;
}

ZbStatus Props_KindRange(uint8_t kind, int32_t *outMin, int32_t *outMax)
{
    if (outMin == 0 || outMax == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (kind == PROP_KIND_BOOL)
    {
        *outMin = 0;
        *outMax = 1;
        return ZB_OK;
    }

    if (kind == PROP_KIND_U8)
    {
        *outMin = 0;
        *outMax = 255;
        return ZB_OK;
    }

    if (kind == PROP_KIND_I8)
    {
        *outMin = -128;
        *outMax = 127;
        return ZB_OK;
    }

    if (kind == PROP_KIND_U16_LE)
    {
        *outMin = 0;
        *outMax = 65535;
        return ZB_OK;
    }

    return ZB_ERR_UNSUPPORTED;
}

static int hasPrefix(const uint8_t *text, uint32_t len, const char *prefix, uint32_t cap)
{
    uint32_t width = Zb_strlen(prefix, cap);

    if (len < width)
        return 0;

    return Zb_memcmp(text, (const uint8_t *)prefix, width) == 0;
}

Props_Dialect Props_Detect(const uint8_t *ncpVersion, uint32_t len)
{
    if (ncpVersion == 0)
        return PROPS_DIALECT_UNKNOWN;

    if (hasPrefix(ncpVersion, len, versionPrefixOpenThread,
                  (uint32_t)sizeof versionPrefixOpenThread))
        return PROPS_DIALECT_OPENTHREAD;

    if (hasPrefix(ncpVersion, len, versionPrefixDspinel,
                  (uint32_t)sizeof versionPrefixDspinel))
        return PROPS_DIALECT_DSPINEL;

    return PROPS_DIALECT_UNKNOWN;
}

uint32_t Props_RadioCapsUnknown(uint32_t radioCaps)
{
    uint32_t named;
    uint32_t i;

    named = 0;

    for (i = 0; i < PROPS_RADIO_CAP_NAMED; i++)
        named |= (1 << i);

    return radioCaps & ~named;
}

ZbStatus Props_DeriveCaps(Props_Dialect dialect, uint32_t radioCaps, Radio_Caps *out)
{
    if (out == 0 || !Props_Known(dialect))
        return ZB_ERR_UNSUPPORTED;

    out->radioCaps = radioCaps;
    out->hasEnergyScan = (radioCaps & (1 << PROPS_RADIO_CAP_ENERGY_SCAN)) != 0;
    out->handlesAckTimeout = (radioCaps & (1 << PROPS_RADIO_CAP_ACK_TIMEOUT)) != 0;
    out->hasTransmit = Props_Supports(dialect, PROP_STREAM_RAW, PROPS_OP_SET);
    out->hasAckMetadata = 0;

    /* A table the dialect can write is not a table this device has: the discovery read of
       0x1303 narrows this to what the RCP answered (D-123). */
    out->hasPendingTable = Props_Supports(dialect, PROP_MAC_SRC_MATCH_ENABLED, PROPS_OP_SET);

    out->psduIncludesFcs = dialect == PROPS_DIALECT_DSPINEL;

    return ZB_OK;
}

int Props_ChannelsDiscoverable(Props_Dialect dialect)
{
    return Props_Supports(dialect, PROP_PHY_CHAN_SUPPORTED, PROPS_OP_GET);
}

int Props_ChannelValid(Props_Dialect dialect, uint32_t channel)
{
    if (!Props_Known(dialect))
        return 0;

    return channel >= PROPS_CHANNEL_MIN && channel <= PROPS_CHANNEL_MAX;
}

const Prop_Step *Props_ArmSteps(Props_Dialect dialect, uint32_t *outLen)
{
    if (outLen == 0)
        return 0;

    *outLen = 0;

    if (dialect == PROPS_DIALECT_OPENTHREAD)
    {
        *outLen = (uint32_t)(sizeof openthreadArmSteps / sizeof openthreadArmSteps[0]);
        return openthreadArmSteps;
    }

    if (dialect == PROPS_DIALECT_DSPINEL)
    {
        *outLen = (uint32_t)(sizeof dspinelArmSteps / sizeof dspinelArmSteps[0]);
        return dspinelArmSteps;
    }

    return 0;
}

const Prop_Step *Props_TeardownSteps(Props_Dialect dialect, uint32_t *outLen)
{
    if (outLen == 0)
        return 0;

    *outLen = 0;

    if (dialect == PROPS_DIALECT_DSPINEL)
    {
        *outLen = (uint32_t)(sizeof dspinelTeardownSteps / sizeof dspinelTeardownSteps[0]);
        return dspinelTeardownSteps;
    }

    if (!Props_Known(dialect))
        return 0;

    *outLen = (uint32_t)(sizeof teardownSteps / sizeof teardownSteps[0]);
    return teardownSteps;
}
