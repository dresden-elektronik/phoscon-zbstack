#ifndef PROPS_H
#define PROPS_H

/*
 * Band B: what each measured dialect actually answers, in what shape, and in which order.
 * The catalogue holds a property id, the operations a dialect accepts for it, the value shape,
 * and the seam PIB field it carries. The driver consults it instead of assuming Spinel's
 * numbering exists on a device or that two firmwares implement the same property
 * (docs/internals/protocol.md §7, docs/internals/hardware.md §3).
 *
 * A property outside the catalogue is not claimed absent: the catalogue covers what this stack
 * drives, and Props_Find answers 0 for anything it does not know. The measured property sets of
 * both dialects are in docs/internals/protocol.md §7.1 and §7.2; an entry is present here only where this
 * bench read the property or wrote it.
 */

#include <stdint.h>
#include "radio.h"
#include "zb_status.h"

typedef enum PropsDialect
{
    PROPS_DIALECT_OPENTHREAD = 0,   /* SL-OPENTHREAD radio build, RCP API 9 */
    PROPS_DIALECT_DSPINEL = 1,      /* DSPINEL 1.0 on an AT86RF233, RCP API 4 */
    PROPS_DIALECT_UNKNOWN = 2
} Props_Dialect;

/* Property ids this stack drives. Values are Spinel's, measured to be honoured on both RCPs. */
enum
{
    PROP_LAST_STATUS = 0x00,
    PROP_PROTOCOL_VERSION = 0x01,
    PROP_NCP_VERSION = 0x02,
    PROP_INTERFACE_TYPE = 0x03,
    PROP_CAPS = 0x05,
    PROP_HWADDR = 0x08,
    PROP_PHY_ENABLED = 0x20,
    PROP_PHY_CHAN = 0x21,
    PROP_PHY_CHAN_SUPPORTED = 0x22,
    PROP_PHY_CCA_THRESHOLD = 0x24,
    PROP_PHY_TX_POWER = 0x25,
    PROP_PHY_RSSI = 0x26,
    PROP_PHY_RX_SENSITIVITY = 0x27,
    PROP_MAC_15_4_LADDR = 0x34,
    PROP_MAC_15_4_SADDR = 0x35,
    PROP_MAC_15_4_PANID = 0x36,
    PROP_MAC_RAW_STREAM_ENABLED = 0x37,
    PROP_MAC_PROMISCUOUS_MODE = 0x38,
    PROP_MAC_SCAN_STATE = 0x30,
    PROP_MAC_SCAN_MASK = 0x31,
    PROP_MAC_SCAN_PERIOD = 0x32,
    PROP_MAC_ENERGY_SCAN_RESULT = 0x39,
    PROP_MAC_RX_ON_WHEN_IDLE = 0x3B,
    PROP_STREAM_RAW = 0x71,
    PROP_RCP_API_VERSION = 0xB0,
    PROP_RCP_MIN_HOST_API_VERSION = 0xB1,
    PROP_RCP_LOG_CRASH_DUMP = 0xB2,
    PROP_UNSOL_UPDATE_FILTER = 0x1008,
    PROP_RADIO_CAPS = 0x120B,

    /* Upstream's SPINEL_PROP_MAC_EXT__BEGIN + 3, + 4 and + 5: the source-match family a coordinator's
       acknowledgment takes its Frame Pending bit from (docs/internals/protocol.md §7.4, docs/internals/conformance.md §1). Read
       and written on the AT86RF233 build at the revision measured now, which composes the Ack itself. */
    PROP_MAC_SRC_MATCH_ENABLED = 0x1303,
    PROP_MAC_SRC_MATCH_SHORT_ADDRESSES = 0x1304,
    PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES = 0x1305,

    /* Ids named here so a table can say they are absent. Upstream defines each of them; this
       bench measured the answer `PROP_NOT_FOUND` (docs/internals/protocol.md §7.2) or never read them. An id
       moved out of this group only when an RCP answered a read or a write of it. */
    PROP_VENDOR_ID = 0x04,
    PROP_INTERFACE_COUNT = 0x06,
    PROP_PHY_FREQ = 0x23,
    PROP_MAC_SCAN_BEACON = 0x33,
    PROP_MAC_DATA_POLL_PERIOD = 0x3A,
    PROP_UNSOL_UPDATE_LIST = 0x1009,
    PROP_RCP_TIMESTAMP = 0x802,
    PROP_RCP_CSL_ACCURACY = 0x804
};

/* Operations a dialect accepts. A write this table does not offer is refused before a frame is
   composed, which is cheaper than learning it from a LAST_STATUS. */
enum
{
    PROPS_OP_GET = 1,
    PROPS_OP_SET = 2,
    PROPS_OP_INSERT = 4,
    PROPS_OP_REMOVE = 8,
    PROPS_OP_NOTIFY = 16,     /* arrives unsolicited; a host never reads it */

    /* The combinations a table row actually uses, named so a driver compares against the same
       words the table does. */
    PROPS_OP_RW = PROPS_OP_GET | PROPS_OP_SET,
    PROPS_OP_WR = PROPS_OP_SET | PROPS_OP_NOTIFY,
    PROPS_OP_IR = PROPS_OP_INSERT | PROPS_OP_REMOVE
};

/* The value shape, named after the Spinel type letter of docs/internals/protocol.md §4. */
typedef enum PropKind
{
    PROP_KIND_BOOL = 0,           /* b: one octet 0 or 1 */
    PROP_KIND_U8,                 /* C */
    PROP_KIND_I8,                 /* c: signed, which is how a dBm value arrives */
    PROP_KIND_U16_LE,             /* S */
    PROP_KIND_ADDR_BE,            /* E: eight octets in address order */
    PROP_KIND_PACKED_U,           /* i */
    PROP_KIND_ARRAY_PACKED_U,     /* A(i) */
    PROP_KIND_ARRAY_U8,           /* A(C) */
    PROP_KIND_ARRAY_U16_LE,       /* A(S): concatenated 16-bit addresses, little-endian, no count prefix */
    PROP_KIND_ARRAY_ADDR_BE,      /* A(E): concatenated 8-octet addresses in address order, no count prefix */
    PROP_KIND_UTF8,               /* U: zero terminated */
    PROP_KIND_DATA,               /* D: length-prefixed octets */
    PROP_KIND_COUNT
} Prop_Kind;

enum
{
    PROPS_PROMISCUOUS_OFF = 0,
    PROPS_PROMISCUOUS_NETWORK = 1,
    PROPS_PROMISCUOUS_FULL = 2,
    PROPS_CHANNEL_MIN = 11,
    PROPS_CHANNEL_MAX = 26,
    PROPS_CHANNELS_2G4 = 16,      /* 802.15.4-2024 §11.1.3.3 */
    PROPS_STEP_RUNTIME = 0xff     /* the value comes from the PIB when the step runs */
};

/*
 * The bit positions of RADIO_CAPS. The wire value is OpenThread's otRadioCaps enum cast
 * straight through, on a firmware that is not OpenThread as well (docs/internals/hardware.md §4): the
 * measured 0x10d decodes only under this numbering.
 */
enum
{
    PROPS_RADIO_CAP_ACK_TIMEOUT = 0,
    PROPS_RADIO_CAP_ENERGY_SCAN = 1,
    PROPS_RADIO_CAP_TRANSMIT_RETRIES = 2,
    PROPS_RADIO_CAP_CSMA_BACKOFF = 3,
    PROPS_RADIO_CAP_SLEEP_TO_TX = 4,
    PROPS_RADIO_CAP_TRANSMIT_SEC = 5,
    PROPS_RADIO_CAP_TRANSMIT_TIMING = 6,
    PROPS_RADIO_CAP_RECEIVE_TIMING = 7,
    PROPS_RADIO_CAP_RX_ON_WHEN_IDLE = 8,

    /* How many bits have names above. A RADIO_CAPS value with a bit at or beyond this position is
       not a fault: it is a capability this stack has no name for yet, and Props_RadioCapsUnknown
       reports it instead of dropping it. */
    PROPS_RADIO_CAP_NAMED = 9
};

typedef struct PropEntry
{
    uint32_t id;
    uint16_t ops;
    uint8_t kind;
    uint16_t pib;         /* the RADIO_PIB_* field this property carries, 0 if none */
    const char *name;
} Prop_Entry;

/* One write of an arm or teardown sequence (docs/internals/protocol.md §6). */
typedef struct PropStep
{
    uint32_t id;
    uint8_t value;        /* PROPS_STEP_RUNTIME, or the octet this dialect requires */
} Prop_Step;

const Prop_Entry *Props_Catalogue(Props_Dialect dialect, uint32_t *outLen);
const Prop_Entry *Props_Find(Props_Dialect dialect, uint32_t id);
int Props_Supports(Props_Dialect dialect, uint32_t id, uint16_t op);
int Props_Known(Props_Dialect dialect);

/* A PIB field this dialect can carry, copied out so the caller owns it. ZB_ERR_UNSUPPORTED when
   the property is not in the dialect's table, which is a measured fact, not a guess. */
ZbStatus Props_ForPib(Props_Dialect dialect, uint32_t pibField, Prop_Entry *out);

/* Fixed width in octets, 0 for a shape the value itself sizes. */
uint32_t Props_KindBytes(uint8_t kind);

/* The span a value of this shape can hold, so a PIB value is refused before it is written.
   ZB_ERR_UNSUPPORTED for a shape with no single range. */
ZbStatus Props_KindRange(uint8_t kind, int32_t *outMin, int32_t *outMax);

/* Which dialect an RCP is, from the string it answered NCP_VERSION with. */
Props_Dialect Props_Detect(const uint8_t *ncpVersion, uint32_t len);

/* Bits of a RADIO_CAPS value this stack has no name for: a capability that appears on a new
   firmware is counted here rather than vanishing from the decode (docs/internals/hardware.md §4). */
uint32_t Props_RadioCapsUnknown(uint32_t radioCaps);

/*
 * The seam's capabilities, derived rather than assumed. hasTransmit means the dialect's table offers a
 * write to STREAM_RAW (which is what a capability report is for) and is not a claim about what has been
 * sent: transmits have been authorised and measured.
 * hasAckMetadata is 0 for both dialects because no acknowledgment frame is delivered to the host
 * (docs/internals/protocol.md §10 question 11). The Ack's Frame Pending bit is reported per completion
 * instead (docs/internals/protocol.md §8.3).
 */
ZbStatus Props_DeriveCaps(Props_Dialect dialect, uint32_t radioCaps, Radio_Caps *out);

/* 1 when this dialect reports its supported channels as a property, 0 when band B has to take
   them from the PHY it targets instead. */
int Props_ChannelsDiscoverable(Props_Dialect dialect);
int Props_ChannelValid(Props_Dialect dialect, uint32_t channel);

/*
 * What a device answered, kept beside the table rather than inside it (docs/internals/decisions.md D-123).
 *
 * The table says what a build may be asked about. A surface says what *this* device answered when it was
 * asked, which is the only thing that can tell one revision of a build from another: the same name answered
 * `PROP_NOT_FOUND` for the scan group at one revision and a value at the next (docs/internals/hardware.md §3).
 *
 * Bits stand for positions in the dialect's own catalogue, so a surface is only meaningful with the dialect it
 * was built against, and an id the catalogue does not name has no index and is not asked about. A lookup
 * answers `PROPS_SURFACE_UNKNOWN` for anything never asked: absence is a recorded answer, not an inference
 * from silence. PROPS_SURFACE_WIDTH is how many entries a surface can hold, and the props suite pins that
 * every catalogue still fits inside it.
 */
#define PROPS_SURFACE_WIDTH 64

typedef struct PropSurface
{
    uint64_t known;     /* bit i: this device answered a read or a write of the entry at index i */
    uint64_t absent;    /* bit i: this device answered PROP_NOT_FOUND for that entry */
} Prop_Surface;

enum
{
    PROPS_SURFACE_UNKNOWN = 0,
    PROPS_SURFACE_KNOWN = 1,
    PROPS_SURFACE_ABSENT = 2
};

void Props_SurfaceInit(Prop_Surface *surface);

/* Index of an id in its dialect's catalogue, or PROPS_SURFACE_NONE when the catalogue does not name it. A
   macro rather than an enum member, because the value is the whole width of a uint32_t (docs/internals/coding-rules.md
   §6). */
#define PROPS_SURFACE_NONE 0xffffffff
uint32_t Props_SurfaceIndex(Props_Dialect dialect, uint32_t id);

/* Record what the device answered. An id no catalogue names is not recorded, because there is no bit for it. */
void Props_SurfaceNote(Prop_Surface *surface, Props_Dialect dialect, uint32_t id, int answered);

int Props_SurfaceState(const Prop_Surface *surface, Props_Dialect dialect, uint32_t id);

const Prop_Step *Props_ArmSteps(Props_Dialect dialect, uint32_t *outLen);

/* A dialect's own teardown: the §6 order, plus the writes only that dialect's table can carry. The
   AT86RF233 build has a property the other does not, and leaving it set leaves the next opener of the
   port holding a configuration nobody in this session asked for. */
const Prop_Step *Props_TeardownSteps(Props_Dialect dialect, uint32_t *outLen);

#endif /* PROPS_H */
