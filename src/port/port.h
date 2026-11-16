#ifndef PORT_H
#define PORT_H

#include <stdint.h>

#include "zb_status.h"

/*
 * One maximum Spinel/HDLC frame, including its FCS (docs/internals/protocol.md §2). The bound is on the
 * frame as the peer's decoder reassembles it: escaping is applied on the way out, so the octets
 * this host puts on the wire can be up to twice the frame maximum. A transmit ring sized for the
 * unescaped frame would refuse a legal frame that happens to escape, and a ring that refused
 * whole frames is the same fault as one that split them (docs/internals/coding-rules.md §7), so the transmit
 * ring is sized for the escaped form.
 */
#define PORT_FRAME_MAX       256
#define PORT_TX_RING_MAX     1024   /* 2 x (frame + FCS) + both flags: the worst escaping */
#define PORT_RX_RING_DEFAULT 512
#define PORT_TX_RING_DEFAULT PORT_TX_RING_MAX
#define PORT_PATH_MAX        4096     /* a device path and its terminator: Linux's PATH_MAX, the larger of the POSIX
                                         hosts' (macOS's is 1024), so a /dev/serial/by-id/ name fits */
#define PORT_LOCATED_MAX     128      /* the node a `usb-serial:` selector resolved to: /dev/ and the name the system chose */
#define PORT_BAUD_LINK       115200   /* docs/internals/hardware.md §2 */
#define PORT_ENTROPY_MAX     256      /* the most octets one `Port_Entropy` call may ask for. getentropy(2) prints the
                                         same ceiling (a request for more than 256 octets fails with EIO) and the door
                                         here is what lets every target answer an oversized request the same way, without
                                         one backend half-filling a buffer and another refusing it */

typedef enum PortState
{
    PORT_STATE_CLOSED = 0,
    PORT_STATE_READY = 1,
    PORT_STATE_FAULT = 2
} PortState;

typedef enum PortFault
{
    PORT_FAULT_NONE = 0,
    PORT_FAULT_OPEN = 1,
    PORT_FAULT_READ = 2,
    PORT_FAULT_WRITE = 3,
    PORT_FAULT_DEVICE_GONE = 4
} PortFault;

typedef struct PortConfig
{
    uint32_t baud;        /* 0 selects PORT_BAUD_LINK */
    uint32_t rxRingSize;  /* 0 selects PORT_RX_RING_DEFAULT; power of two */
    uint32_t txRingSize;  /* 0 selects PORT_TX_RING_DEFAULT; power of two */
    int exclusive;        /* 0/1: refuse a second opener of the same device */
} PortConfig;

struct PortDeviceOps;

/* Caller-owned state: two ports coexist in one process, and a suite resets one
   without restarting (docs/internals/coding-rules.md §4.2). */
typedef struct Port
{
    const struct PortDeviceOps *ops;
    void *implData;

    uint8_t rxRing[PORT_RX_RING_DEFAULT];
    uint8_t txRing[PORT_TX_RING_MAX];
    uint32_t rxRingSize;
    uint32_t txRingSize;
    uint32_t rxWrite;
    uint32_t rxRead;
    uint32_t txWrite;
    uint32_t txRead;

    uint32_t drops;          /* inbound bytes lost to a full ring */
    uint32_t refusals;       /* outbound writes refused for want of space */
    uint32_t platformErrno;

    uintptr_t device;
    PortState state;
    PortFault fault;
    char path[PORT_PATH_MAX];
    char located[PORT_LOCATED_MAX];   /* where the last open of a selector found its device; empty for a plain path */
} Port;

/* Device-side half of a port: the only code that may know a platform exists. */
typedef struct PortDeviceOps
{
    const char *name;
    ZbStatus (*open)(Port *port, const char *path, const PortConfig *config);
    void (*close)(Port *port);
    int (*pump)(Port *port);                 /* device → ring, never blocks */
    ZbStatus (*drain)(Port *port);           /* ring → device, never blocks */
    ZbStatus (*lastFault)(const Port *port);
    ZbStatus (*entropy)(Port *port, uint8_t *out, uint32_t len);   /* the target's entropy source: it fills `len` octets or writes nothing at all. 0 where the target has no honest answer, which the contract reports as ZB_ERR_UNSUPPORTED (docs/internals/coding-rules.md §1) */
    ZbStatus (*wait)(Port *port, uint32_t maxMs);                 /* sleeps until the device has something to read or `maxMs` has passed. 0 where the target cannot block on its device, which the contract reports as ZB_ERR_UNSUPPORTED */
} PortDeviceOps;

/* The ops of the platform this build links: the one place a host program learns which target it runs on, so it names
   no platform header. Each target's backend defines it (docs/porting.md §3); a target that links none fails to link. */
const PortDeviceOps *Port_DefaultOps(void);

ZbStatus Port_Init(Port *port, const PortDeviceOps *ops);
ZbStatus Port_Open(Port *port, const char *path, const PortConfig *config);
void     Port_Close(Port *port);

ZbStatus Port_Write(Port *port, const uint8_t *bytes, uint32_t len, uint32_t *written);
ZbStatus Port_Read(Port *port, uint8_t *buf, uint32_t cap, uint32_t *got);

/* Ring access for a device-ops implementation. */
uint32_t Port_PushRx(Port *port, const uint8_t *bytes, uint32_t len);
uint32_t Port_RxPending(const Port *port);
const uint8_t *Port_TxHead(const Port *port, uint32_t *contiguous);
void     Port_ConsumeTx(Port *port, uint32_t len);
uint32_t Port_TxPending(const Port *port);

uint32_t Port_Drops(const Port *port);
uint32_t Port_Refusals(const Port *port);
uint32_t Port_RxRingSize(const Port *port);
uint32_t Port_TxRingSize(const Port *port);
PortState Port_State(const Port *port);
int      Port_IsOpen(const Port *port);               /* 0/1 */
const char *Port_Path(const Port *port);
const char *Port_Device(const Port *port);            /* the node opened: the path, or what a selector resolved to */
const char *Port_TargetName(const Port *port);
PortFault Port_Fault(const Port *port);
uint32_t Port_PlatformErrno(const Port *port);

/*
 * The target's entropy source, for an application or a tool: `len` octets in `out`, or nothing written
 * and a status that says why.
 *
 * It is on this contract and not inside a protocol module: the randomness the
 * layers of band A need arrives there as a seed in their own configuration and is
 * derived there, band A never includes a port header (docs/internals/coding-rules.md §4.6),
 * and this call is the platform-facing half, the one a host may make for itself.
 *
 * One call fills the whole request or none of it. A refusal leaves `out` exactly as it was, so there is no
 * half-filled buffer to mistake for entropy.
 *
 * The refusal vocabulary is the contract's own, and each answer is a contract answer rather than a failure
 * of the port: ZB_ERR_UNSUPPORTED from a target that cannot honestly provide entropy, an unimplemented
 * target refuses, it does not approximate (§1), ZB_ERR_NO_SPACE from a source that has run out of what it
 * has, ZB_ERR_BAD_ARGUMENT for a request the contract cannot express (no buffer, `len` above
 * PORT_ENTROPY_MAX), ZB_ERR_INTERNAL for a target whose own entropy call failed, its platform error carried
 * out by Port_PlatformErrno as every other platform fault here is carried out. A zero length writes nothing
 * and answers ZB_OK: a request for nothing is answered by writing nothing.
 *
 * The port is not asked to be open. Entropy is not the byte stream: this call touches no ring, sets no
 * `PortFault` and no `PortState`, and moves neither `drops` nor `refusals`; a refusal here is not a write
 * that found a device busy, and counting it as one would put two different facts in one number.
 */
ZbStatus Port_Entropy(Port *port, uint8_t *out, uint32_t len);

/*
 * The target's clock, in milliseconds: monotonic, free-running, an epoch of the target's own choosing that no
 * caller may read anything from (no wall-clock time, no duration between two epochs) and one wrap every 2^32
 * ms, 49.7 days. Those are the only facts the layers above may hold of it, and they are what lets a deadline
 * be a `uint32_t` compared as a distance (Zb_timeReached and Zb_timeWithin, src/utils/zb_time.h).
 *
 * It is the platform's and not a port's, so it takes none: the backend the build links defines it, as it defines
 * Port_DefaultOps (D-277). A target with no monotonic clock defines no Port_NowMs and fails to link, rather than
 * answering wall-clock time: a deadline computed from a clock that steps backwards never expires.
 */
uint32_t Port_NowMs(void);

/* Sleep `ms` with no port to wait on: the platform's, beside Port_NowMs, so a loop whose RCP is gone waits instead
   of spinning. Port_Wait is the call while a port is open. */
void Port_SleepMs(uint32_t ms);

/* Sleep until the device has something to read or `maxMs` has passed, draining the transmit ring first so a half-
   written frame leaves while the host sleeps; octets already on the ring answer at once. NOT_OPEN when closed,
   UNSUPPORTED where the target cannot block on its device, INTERNAL with Port_PlatformErrno when the platform fails. */
ZbStatus Port_Wait(Port *port, uint32_t maxMs);

/* Suite hook: prime the ring indices so the counter wrap of docs/porting.md §2 is reachable in a
   test instead of in four billion pushes. */
void Port_TestPrimeRing(Port *port, uint32_t rxWrite, uint32_t rxRead);

#endif /* PORT_H */
