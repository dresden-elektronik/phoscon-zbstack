/* Suite for the dialect table: the measured presence of every property this stack drives, the
   value shapes that follow from the octets the RCPs answered, the capability derivation, and
   the arm and teardown orders docs/internals/protocol.md §6 requires. */

#include <stdio.h>

#include "props.h"
#include "spinel.h"

#define TABLE_LEN(table) (sizeof table / sizeof table[0])

static int s_failures;

static void expect(int condition, const char *what)
{
    if (!condition)
    {
        printf("FAIL: %s\n", what);
        s_failures++;
    }
}

static void expectOp(Props_Dialect dialect, uint32_t id, uint16_t ops, const char *what)
{
    const Prop_Entry *entry = Props_Find(dialect, id);

    if (ops == 0)
    {
        expect(entry == 0, what);
        return;
    }

    expect(entry != 0 && entry->ops == ops, what);
}

/* Facts read off the RCPs: docs/internals/protocol.md §7.2 (the GET sweep), §7.1 and docs/internals/hardware.md §3. */
static void caseMeasuredPresence(void)
{
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_CHAN_SUPPORTED, 0,
             "PHY_CHAN_SUPPORTED is answered PROP_NOT_FOUND on the AT86RF233 build");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_PHY_CHAN_SUPPORTED, PROPS_OP_GET,
             "and answered on the OpenThread build");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_VENDOR_ID, 0, "no vendor id");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_INTERFACE_COUNT, 0, "no interface count");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_FREQ, 0, "no frequency read-out: channel only");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE, PROPS_OP_RW,
             "the current revision answers a scan state, read and written");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_MASK, PROPS_OP_RW,
             "a scan mask, count byte and channel list");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_PERIOD, PROPS_OP_RW,
             "and a scan period");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_BEACON, 0,
             "while the beacon result is still refused (docs/internals/protocol.md §7.4)");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_ENERGY_SCAN_RESULT, PROPS_OP_NOTIFY,
             "and the energy result arrives as a notification, never as a read");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_RCP_LOG_CRASH_DUMP, PROPS_OP_NOTIFY,
             "as this build's own record stream does");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_DATA_POLL_PERIOD, 0, "no host-set poll period");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SRC_MATCH_ENABLED, PROPS_OP_RW,
             "the source-match enable bit is read and written on the revision measured now");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SRC_MATCH_SHORT_ADDRESSES,
             PROPS_OP_RW | PROPS_OP_INSERT | PROPS_OP_REMOVE,
             "and the short-address list is read, replaced whole, and patched one entry at a time");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES,
             PROPS_OP_RW | PROPS_OP_INSERT | PROPS_OP_REMOVE, "as is the extended-address list");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_MAC_SRC_MATCH_ENABLED, 0,
             "while no read of that family on the other build is in this table");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_UNSOL_UPDATE_FILTER, 0, "no unsolicited-update filter");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_UNSOL_UPDATE_LIST, 0, "no unsolicited-update list");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_RCP_TIMESTAMP, 0, "no RCP timestamp");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_RCP_CSL_ACCURACY, 0, "no CSL accuracy");

    expectOp(PROPS_DIALECT_DSPINEL, PROP_HWADDR, PROPS_OP_GET, "HWADDR answered, eight octets");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_TX_POWER, PROPS_OP_RW,
             "PHY_TX_POWER answered 0 dBm and took +2 back (docs/internals/protocol.md §7.4.3)");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_RSSI, PROPS_OP_GET, "PHY_RSSI answered -128");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_RX_SENSITIVITY, PROPS_OP_GET, "PHY_RX_SENSITIVITY answered -96");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_RCP_API_VERSION, PROPS_OP_GET, "RCP_API_VERSION answered 4");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_RCP_MIN_HOST_API_VERSION, PROPS_OP_GET, "RCP_MIN_HOST answered 4");
    expectOp(PROPS_DIALECT_DSPINEL, 0xB3, 0, "Phoscon RCP 0.1.0 refuses the id upstream leaves undefined");
    expectOp(PROPS_DIALECT_DSPINEL, PROP_MAC_RX_ON_WHEN_IDLE, PROPS_OP_RW, "a real property here");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_MAC_RX_ON_WHEN_IDLE, 0, "and absent on the other build");

    /* Written and read back on the AT86RF233 build; read only, so far, on the other. The device offered
       no guard for the value it was given (+127 dBm was stored), so the range in this table is band B's
       own (docs/internals/protocol.md §7.4.3). */
    expectOp(PROPS_DIALECT_DSPINEL, PROP_PHY_CCA_THRESHOLD, PROPS_OP_RW, "CCA written as well as read here");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_PHY_CCA_THRESHOLD, PROPS_OP_GET, "CCA read there, never written");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_PHY_TX_POWER, 0, "never read on the OpenThread build");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_PHY_RSSI, 0, "never read on the OpenThread build");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_PHY_RX_SENSITIVITY, 0, "never read on the OpenThread build");

    /* UNSOL_UPDATE_FILTER exists on the radio build only as INSERT and REMOVE (§7.1). */
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_UNSOL_UPDATE_FILTER,
             PROPS_OP_INSERT | PROPS_OP_REMOVE, "filterable only through INSERT and REMOVE");

    /* STREAM_RAW is a notification and a write on both, and no GET is offered anywhere: the
       AT86RF233 build answers PROP_NOT_FOUND for it, and the other has never been asked. */
    expectOp(PROPS_DIALECT_DSPINEL, PROP_STREAM_RAW, PROPS_OP_SET | PROPS_OP_NOTIFY,
             "STREAM_RAW is written, never read");
    expectOp(PROPS_DIALECT_OPENTHREAD, PROP_STREAM_RAW, PROPS_OP_SET | PROPS_OP_NOTIFY,
             "the same shape on the other dialect");
    expect(!Props_Supports(PROPS_DIALECT_DSPINEL, PROP_STREAM_RAW, PROPS_OP_GET),
           "and a GET on it is refused before a frame is composed");
}

static void caseCatalogueIntegrity(void)
{
    static const uint32_t pibFields[] =
    {
        0, RADIO_PIB_CHANNEL, RADIO_PIB_PAGE, RADIO_PIB_PAN_ID, RADIO_PIB_SHORT_ADDRESS,
        RADIO_PIB_EXTENDED_ADDRESS, RADIO_PIB_RX_ON_WHEN_IDLE, RADIO_PIB_MAX_CSMA_BACKOFFS,
        RADIO_PIB_MAX_FRAME_RETRIES, RADIO_PIB_ACK_WAIT_MS, RADIO_PIB_CCA_THRESHOLD_DBM
    };
    Props_Dialect dialects[] = { PROPS_DIALECT_OPENTHREAD, PROPS_DIALECT_DSPINEL };
    const Prop_Entry *table;
    uint32_t count;
    uint32_t steps;
    const Prop_Step *arm;
    uint32_t d;
    uint32_t i;
    uint32_t j;
    int known;

    for (d = 0; d < 2; d++)
    {
        table = Props_Catalogue(dialects[d], &count);
        expect(table != 0 && count > 0, "every known dialect has a catalogue");
        expect(Props_Catalogue(PROPS_DIALECT_UNKNOWN, &count) == 0 && count == 0,
               "and an unknown one has none");

        for (i = 0; i < count; i++)
        {
            expect(table[i].name != 0 && table[i].name[0] != 0, "every entry is named");
            expect(table[i].ops != 0, "and says what it accepts");
            expect(table[i].kind < PROP_KIND_COUNT, "with a shape this module knows");
            expect(Spinel_PackedUintBytes(table[i].id) <= SPINEL_PACKED_UINT_MAX_BYTES,
                   "and an id that fits a packed uint");

            known = 0;

            for (j = 0; j < TABLE_LEN(pibFields); j++)
            {
                if (table[i].pib == pibFields[j])
                    known = 1;
            }

            expect(known, "and a PIB field this stack defines");

            for (j = i + 1; j < count; j++)
            {
                if (table[i].id == table[j].id)
                    expect(0, "no id appears twice in one dialect");
            }
        }

        arm = Props_ArmSteps(dialects[d], &steps);
        expect(arm != 0 && steps > 0, "every known dialect has an arm sequence");

        for (i = 0; i < steps; i++)
            expect(Props_Supports(dialects[d], arm[i].id, PROPS_OP_SET),
                   "and every arm step is a property that dialect accepts a write for");

        arm = Props_TeardownSteps(dialects[d], &steps);
        expect(arm != 0 && steps > 0, "and every known dialect has a teardown sequence");

        for (i = 0; i < steps; i++)
            expect(Props_Supports(dialects[d], arm[i].id, PROPS_OP_SET),
                   "written against properties that dialect accepts a write for as well");
    }
}

static void casePibMapping(void)
{
    Prop_Entry entry;
    ZbStatus status;

    status = Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_CHANNEL, &entry);
    expect(status == ZB_OK && entry.id == PROP_PHY_CHAN, "the channel rides on PHY_CHAN here");
    expect(entry.kind == PROP_KIND_U8 && Props_KindBytes(entry.kind) == 1, "as one octet");

    status = Props_ForPib(PROPS_DIALECT_OPENTHREAD, RADIO_PIB_PAN_ID, &entry);
    expect(status == ZB_OK && entry.kind == PROP_KIND_U16_LE, "a PAN id is two little-endian octets");
    expect(entry.id == PROP_MAC_15_4_PANID, "on MAC_15_4_PANID");

    status = Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_SHORT_ADDRESS, &entry);
    expect(status == ZB_OK && entry.id == PROP_MAC_15_4_SADDR, "the short address likewise");

    status = Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_EXTENDED_ADDRESS, &entry);
    expect(status == ZB_OK && entry.kind == PROP_KIND_ADDR_BE,
           "an extended address is eight octets in address order, on both dialects");
    expect(Props_KindBytes(entry.kind) == RADIO_ADDR_LEN, "and the seam's address length is that width");

    status = Props_ForPib(PROPS_DIALECT_OPENTHREAD, RADIO_PIB_CCA_THRESHOLD_DBM, &entry);
    expect(status == ZB_OK && entry.kind == PROP_KIND_I8,
           "a dBm value is signed: the AT86RF233 answers 0xb9 for -71");

    status = Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_CCA_THRESHOLD_DBM, &entry);
    expect(status == ZB_OK && entry.id == PROP_PHY_CCA_THRESHOLD
           && Props_Supports(PROPS_DIALECT_DSPINEL, entry.id, PROPS_OP_SET),
           "and on this dialect that field is one a host can write as well as read");

    /* The asymmetry is measured, not inferred: one RCP carries this PIB field, the other does
       not, and band B answers ZB_ERR_UNSUPPORTED rather than approximating it. */
    status = Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_RX_ON_WHEN_IDLE, &entry);
    expect(status == ZB_OK && entry.id == PROP_MAC_RX_ON_WHEN_IDLE, "present on DSPINEL");
    status = Props_ForPib(PROPS_DIALECT_OPENTHREAD, RADIO_PIB_RX_ON_WHEN_IDLE, &entry);
    expect(status == ZB_ERR_UNSUPPORTED, "absent on the OpenThread build");

    expect(Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_MAX_CSMA_BACKOFFS, &entry) == ZB_ERR_UNSUPPORTED,
           "no measured property carries the backoff count");
    expect(Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_MAX_FRAME_RETRIES, &entry) == ZB_ERR_UNSUPPORTED,
           "nor the retry count");
    expect(Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_ACK_WAIT_MS, &entry) == ZB_ERR_UNSUPPORTED,
           "nor the acknowledgment wait");
    expect(Props_ForPib(PROPS_DIALECT_UNKNOWN, RADIO_PIB_CHANNEL, &entry) == ZB_ERR_UNSUPPORTED,
           "and an unknown dialect carries nothing");
    expect(Props_ForPib(PROPS_DIALECT_DSPINEL, 0, &entry) == ZB_ERR_BAD_ARGUMENT
           && Props_ForPib(PROPS_DIALECT_DSPINEL, RADIO_PIB_CHANNEL, 0) == ZB_ERR_BAD_ARGUMENT,
           "with the argument errors stated");
}

static void caseKindRanges(void)
{
    int32_t lo;
    int32_t hi;

    expect(Props_KindRange(PROP_KIND_BOOL, &lo, 0) == ZB_ERR_BAD_ARGUMENT
           && Props_KindRange(PROP_KIND_BOOL, 0, &hi) == ZB_ERR_BAD_ARGUMENT,
           "a range request with nowhere to put an answer is an argument error");

    expect(Props_KindRange(PROP_KIND_BOOL, &lo, &hi) == ZB_OK && lo == 0 && hi == 1,
           "a bool is 0 or 1, never a non-zero octet in a write");
    expect(Props_KindRange(PROP_KIND_U8, &lo, &hi) == ZB_OK && lo == 0 && hi == 255, "u8");
    expect(Props_KindRange(PROP_KIND_I8, &lo, &hi) == ZB_OK && lo == -128 && hi == 127,
           "i8 spans -128, which is what a PHY_RSSI of 0x80 means on an idle radio");
    expect(Props_KindRange(PROP_KIND_U16_LE, &lo, &hi) == ZB_OK && lo == 0 && hi == 65535, "u16");
    expect(Props_KindRange(PROP_KIND_ADDR_BE, &lo, &hi) == ZB_ERR_UNSUPPORTED
           && Props_KindRange(PROP_KIND_UTF8, &lo, &hi) == ZB_ERR_UNSUPPORTED
           && Props_KindRange(PROP_KIND_DATA, &lo, &hi) == ZB_ERR_UNSUPPORTED,
           "and a shape with no single range says so instead of inventing one");
}

static void caseDetect(void)
{
    static const char ot[] = "SL-OPENTHREAD/2.3.2.0";
    static const char dz[] = "DSPINEL/1.0; AT86RF233";
    static const char other[] = "something else entirely";
    static const char shortish[] = "DSPIN";

    expect(Props_Detect((const uint8_t *)ot, (uint32_t)sizeof ot - 1) == PROPS_DIALECT_OPENTHREAD,
           "the version string the ConBee III answered selects its dialect");
    expect(Props_Detect((const uint8_t *)dz, (uint32_t)sizeof dz - 1) == PROPS_DIALECT_DSPINEL,
           "and the one the ConBee II answered selects the other");
    expect(Props_Detect((const uint8_t *)other, (uint32_t)sizeof other - 1) == PROPS_DIALECT_UNKNOWN,
           "an unrecognised build is unknown rather than guessed at");
    expect(Props_Detect((const uint8_t *)shortish, (uint32_t)sizeof shortish - 1) == PROPS_DIALECT_UNKNOWN,
           "and a truncated prefix is not a match");
    expect(Props_Detect(0, 0) == PROPS_DIALECT_UNKNOWN, "no string is no dialect");
    expect(!Props_Known(PROPS_DIALECT_UNKNOWN), "which the table then refuses to consult");
}

static void caseRadioCaps(void)
{
    Radio_Caps caps;

    /* 0x10d, the bitmap both ConBee IIs answered at the revision docs/internals/protocol.md §7.2 read: ACK_TIMEOUT,
       TRANSMIT_RETRIES, CSMA_BACKOFF and RX_ON_WHEN_IDLE, and no energy scan (docs/internals/hardware.md §4). */
    expect(Props_DeriveCaps(PROPS_DIALECT_DSPINEL, 0x10d, &caps) == ZB_OK, "the measured bitmap decodes");
    expect(caps.radioCaps == 0x10d, "passed through uninterpreted for a device that wants the raw value");
    expect(caps.hasEnergyScan == 0, "no radio-level energy scan in that bitmap");
    expect(caps.hasTransmit == 1, "the dialect's table offers the raw-stream write");
    expect(caps.psduIncludesFcs == 1, "and the delivered PSDU still carries its own FCS");
    expect(caps.hasAckMetadata == 0, "no acknowledgment metadata has ever been seen here");
    expect(caps.hasPendingTable == 1,
           "and the source-match family is in this dialect's table, which is what a radio that composes its own Ack offers");
    expect(caps.handlesAckTimeout == 1,
           "and the acknowledgment wait is the radio's, which is the fact band A branches on rather than the bitmap that says it");
    expect(Props_RadioCapsUnknown(0x10d) == 0, "with every bit named");

    /* 0x10f, the same build's bitmap at the current revision: the one bit that moved is ENERGY_SCAN
       (docs/internals/hardware.md §3, §4). A capability flag is what the silicon claims; it is not permission to
       ask, and it is not the gate band B uses for a scan (D-123). */
    expect(Props_DeriveCaps(PROPS_DIALECT_DSPINEL, 0x10f, &caps) == ZB_OK, "the revised bitmap decodes");
    expect(caps.hasEnergyScan == 1, "and claims an energy scan");
    expect(caps.handlesAckTimeout == 1 && caps.psduIncludesFcs == 1,
           "while everything else the dialect derives stands where it was");
    expect(Props_RadioCapsUnknown(0x10f) == 0, "with every bit named there too");

    /* Bit 0 cleared and the same RCP becomes a radio that cannot report whether a frame was answered. */
    expect(Props_DeriveCaps(PROPS_DIALECT_DSPINEL, 0x10c, &caps) == ZB_OK && caps.handlesAckTimeout == 0,
           "without ACK_TIMEOUT the derived flag says so, and band A stops trusting a completion it cannot read that way");

    /* 0xff, measured on the ConBee III: ENERGY_SCAN among them, and FCS stripped from a PSDU. */
    expect(Props_DeriveCaps(PROPS_DIALECT_OPENTHREAD, 0xff, &caps) == ZB_OK, "the other bitmap decodes");
    expect(caps.hasEnergyScan == 1, "that build reports an energy scan");
    expect(caps.handlesAckTimeout == 1, "and it carries the acknowledgment timeout too");
    expect(caps.psduIncludesFcs == 0, "and strips the FCS");
    expect(caps.hasPendingTable == 0,
           "with no source-match entry in its table: the family has not been read on that build, and a table names what it earned");
    expect(Props_RadioCapsUnknown(0xff) == 0, "every bit named here as well");

    expect(Props_RadioCapsUnknown(0x1000) == 0x1000,
           "a bit this stack has no name for is reported, not dropped");
    expect(Props_DeriveCaps(PROPS_DIALECT_DSPINEL, 0, &caps) == ZB_OK
           && caps.hasEnergyScan == 0 && caps.psduIncludesFcs == 1,
           "a bare bitmap still carries the dialect's own facts");
    expect(Props_DeriveCaps(PROPS_DIALECT_UNKNOWN, 0x10d, &caps) == ZB_ERR_UNSUPPORTED,
           "and an unknown dialect derives nothing");
    expect(Props_DeriveCaps(PROPS_DIALECT_DSPINEL, 0x10d, 0) == ZB_ERR_UNSUPPORTED,
           "with the argument error stated");
}

static void caseChannels(void)
{
    uint32_t channel;

    expect(Props_ChannelsDiscoverable(PROPS_DIALECT_OPENTHREAD) == 1,
           "one dialect reports its supported channels");
    expect(Props_ChannelsDiscoverable(PROPS_DIALECT_DSPINEL) == 0,
           "the other answers PROP_NOT_FOUND, so band B takes the set from the PHY instead");

    for (channel = PROPS_CHANNEL_MIN; channel <= PROPS_CHANNEL_MAX; channel++)
        expect(Props_ChannelValid(PROPS_DIALECT_DSPINEL, channel), "16 channels on the standard's list");

    expect(PROPS_CHANNELS_2G4 == PROPS_CHANNEL_MAX - PROPS_CHANNEL_MIN + 1,
           "the count and the range are the same fact (802.15.4-2024 §11.1.3.3)");
    expect(!Props_ChannelValid(PROPS_DIALECT_DSPINEL, PROPS_CHANNEL_MIN - 1), "one below the list is refused");
    expect(!Props_ChannelValid(PROPS_DIALECT_DSPINEL, PROPS_CHANNEL_MAX + 1), "one above is refused");
    expect(!Props_ChannelValid(PROPS_DIALECT_DSPINEL, 0), "so is 0, which no PHY numbers");
    expect(!Props_ChannelValid(PROPS_DIALECT_UNKNOWN, 15), "and an unknown dialect validates nothing");
}

static void caseSequences(void)
{
    const Prop_Step *steps;
    uint32_t count;
    uint32_t i;
    int sawRuntimeChannel;
    int sawRxOnWhenIdle;

    steps = Props_ArmSteps(PROPS_DIALECT_OPENTHREAD, &count);
    expect(count == 4, "the OpenThread build arms in four writes");
    sawRuntimeChannel = 0;
    sawRxOnWhenIdle = 0;

    for (i = 0; i < count; i++)
    {
        if (steps[i].id == PROP_PHY_CHAN && steps[i].value == PROPS_STEP_RUNTIME)
            sawRuntimeChannel = 1;

        if (steps[i].id == PROP_MAC_RX_ON_WHEN_IDLE)
            sawRxOnWhenIdle = 1;
    }

    expect(steps[0].id == PROP_PHY_ENABLED && steps[0].value == 1, "phy first");
    expect(sawRuntimeChannel, "the channel comes from the PIB, not the table");
    expect(!sawRxOnWhenIdle, "and this dialect has no such property");
    expect(steps[count - 1].id == PROP_MAC_RAW_STREAM_ENABLED && steps[count - 1].value == 1,
           "the raw stream opens last");

    steps = Props_ArmSteps(PROPS_DIALECT_DSPINEL, &count);
    expect(count == 5, "the AT86RF233 build arms in five");
    expect(steps[3].id == PROP_MAC_RX_ON_WHEN_IDLE && steps[3].value == 1,
           "with rx-on-when-idle before the raw stream opens");

    steps = Props_TeardownSteps(PROPS_DIALECT_OPENTHREAD, &count);
    expect(count == 3, "three writes tear the OpenThread build down");
    expect(steps[0].id == PROP_MAC_PROMISCUOUS_MODE && steps[0].value == PROPS_PROMISCUOUS_OFF,
           "promiscuous mode goes off first");
    expect(steps[1].id == PROP_PHY_ENABLED && steps[1].value == 0, "then the phy");
    expect(steps[2].id == PROP_MAC_RAW_STREAM_ENABLED && steps[2].value == 0,
           "and the raw stream last: off earlier and some firmware answers BUSY");

    /* The measured reason for a dialect's own teardown list: the three §6 writes leave
       MAC_RX_ON_WHEN_IDLE set on this build, and an RCP that stays listening is an RCP the next
       opener inherits a configuration from. */
    steps = Props_TeardownSteps(PROPS_DIALECT_DSPINEL, &count);
    expect(count == 4, "the dialect that carries the property tears down in four");
    expect(steps[0].id == PROP_MAC_PROMISCUOUS_MODE && steps[0].value == PROPS_PROMISCUOUS_OFF,
           "in the same order at the front");
    expect(steps[1].id == PROP_MAC_RX_ON_WHEN_IDLE && steps[1].value == 0,
           "with rx-on-when-idle cleared while the phy is still on");
    expect(steps[2].id == PROP_PHY_ENABLED && steps[2].value == 0, "then the phy");
    expect(steps[3].id == PROP_MAC_RAW_STREAM_ENABLED && steps[3].value == 0,
           "and the raw stream last on either dialect");

    expect(Props_TeardownSteps(PROPS_DIALECT_UNKNOWN, &count) == 0 && count == 0,
           "an unknown dialect has no order to follow");
}


/*
 * The table says what a build may be asked about; a surface says what the device on
 * this port answered. Only `PROP_NOT_FOUND` records absence, and an id no catalogue
 * names has no bit at all, so the record can never turn a bad request, or a property
 * outside the table, into a statement about the device (docs/internals/decisions.md D-123).
 */
static void caseSurfaceRecordsAnswers(void)
{
    Prop_Surface surface;

    Props_SurfaceInit(&surface);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_PHY_CCA_THRESHOLD) == PROPS_SURFACE_UNKNOWN,
           "never asked is not absence");
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_UNKNOWN,
           "the scan group is unknown until asked");

    Props_SurfaceNote(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE, 0);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_ABSENT,
           "one PROP_NOT_FOUND answer is recorded");

    Props_SurfaceNote(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE, 1);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_KNOWN,
           "and an answer after that replaces it");

    /* A surface belongs to a dialect as well as to a device: the OpenThread table does not name the scan group
       at all, so there is no bit for it there, and an id both tables name is a different entry in each. */
    Props_SurfaceNote(&surface, PROPS_DIALECT_OPENTHREAD, PROP_MAC_SCAN_STATE, 1);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_OPENTHREAD, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_UNKNOWN,
           "a group only this dialect's table names has no record in the other one");
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_KNOWN,
           "and the record in the dialect that does name it stands");

    Props_SurfaceNote(&surface, PROPS_DIALECT_OPENTHREAD, PROP_PHY_CCA_THRESHOLD, 0);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_OPENTHREAD, PROP_PHY_CCA_THRESHOLD) == PROPS_SURFACE_ABSENT,
           "one dialect's record says that device refused it");
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_PHY_CCA_THRESHOLD) == PROPS_SURFACE_UNKNOWN,
           "and the same id in the other dialect was never asked");

    /* The bits are catalogue positions, so an id a catalogue does not name has no bit and stays unknown:
       recording it would invent a fact about a device that was never asked. */
    Props_SurfaceNote(&surface, PROPS_DIALECT_OPENTHREAD, PROP_MAC_SCAN_PERIOD, 1);
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_OPENTHREAD, PROP_MAC_SCAN_PERIOD) == PROPS_SURFACE_UNKNOWN,
           "a property only the other dialect lists is not recorded here");
    expect(Props_SurfaceState(&surface, PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_PERIOD) == PROPS_SURFACE_UNKNOWN,
           "and the dialect that does list it has not been asked either");
}

/*
 * A surface is two masks over catalogue positions, so a catalogue longer than the mask would drop entries
 * silently. Both catalogues fit today; this is what fails loudly when one stops fitting.
 */
static void caseSurfaceCoversEveryTableEntry(void)
{
    const Prop_Entry *table;
    uint32_t count;
    uint32_t i;
    Props_Dialect dialects[2] = { PROPS_DIALECT_OPENTHREAD, PROPS_DIALECT_DSPINEL };

    for (i = 0; i < 2; i++)
    {
        table = Props_Catalogue(dialects[i], &count);
        expect(table != 0, "a known dialect has a catalogue");
        expect(count <= PROPS_SURFACE_WIDTH, "every entry of a catalogue has a bit in a surface");
    }
}
int main(void)
{
    caseMeasuredPresence();
    caseCatalogueIntegrity();
    casePibMapping();
    caseKindRanges();
    caseDetect();
    caseRadioCaps();
    caseChannels();
    caseSequences();
    caseSurfaceRecordsAnswers();
    caseSurfaceCoversEveryTableEntry();

    if (s_failures != 0)
    {
        printf("props: %d failures\n", s_failures);
        return 1;
    }

    printf("props: ok\n");
    return 0;
}
