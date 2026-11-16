#ifndef NWK_RX_H
#define NWK_RX_H

/*
 * The receive stages of 3.6.2.2's order; docs/internals/conformance.md §2 owns their contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "security.h"
#include "zb_status.h"

enum
{
    /* 3.6.2.3: "Routers and Coordinators need to allow for sufficient time (as an example 1 second) for the APS
       layer to process the message and examine whether the stack has an address conflict" */
    NWK_LOST_CHILD_EVALUATION_MS = 1000,

    /* Figure 2-8's APS command header as 3.6.2.2 reads it: the frame control's type in bits 0-1, then the counter,
       then Table 4-31's identifier */
    NWK_RX_APS_FRAME_TYPE_MASK = 0x03,
    NWK_RX_APS_FRAME_TYPE_COMMAND = 0x01,
    NWK_RX_APS_FCF_SECURITY = 0x20,      /* Figure 2-4: the APS frame control's Security sub-field, bit 5 */
    NWK_RX_APS_COMMAND_ID_OFFSET = 2,
    NWK_RX_APS_CMD_TRANSPORT_KEY = 0x05
};

/* What a consumed frame says about the device that sent it this hop: the entry for `hopAddr`, created with only what
   the frame states or refreshed (8166-8167), and the LQI the carrier carried. `*addRefusedOut` is the refusal the
   caller counts (Table 3-84). */
void Nwk_RxObserve(Nwk_NeighborTableEntry *neighbors, const Nwk_Frame *frame, uint16_t hopAddr, uint32_t lqi,
                   uint64_t hopIeee, int hopIeeeKnown, uint32_t nowMs, int *addRefusedOut);

/* 4.3.1.2 step 8 over every entry matching the hop the security module named (4.5.1.3): the hop secured the
   frame, the NWK header names the device that originated it. The step has no failure to report. */
void Nwk_RxAuthenticateHop(Nwk_NeighborTableEntry *neighbors, const Security_Result *result);

/* 3.6.2.3's lost-child observation: the entry keyed on the frame's NWK source, its device type, and the MAC
   source that carried it. `deviceType` is this device's own, because the clause belongs to a router or
   coordinator; the stage marks the entry and stamps the moment the clause's own paragraph re-evaluates it. */
void Nwk_RxExamineParents(Nwk_NeighborTableEntry *neighbors, uint32_t deviceType, const Mac_DataIndicationParameters *ind,
                          const Nwk_Frame *frame, uint32_t nowMs);

/* 3.6.2.3's last paragraph: every entry still marked 0x07 once the window has passed is deleted, and counted. */
uint32_t Nwk_RxReleaseLostChildren(Nwk_NeighborTableEntry *neighbors, uint32_t nowMs);

/* 3.6.2.2's unsecured discard: only the rejoin request, and only for the device it is addressed to: "destined
   to itself, that is, if it does not need to be forwarded to another device" (docs/internals/conformance.md §2) */
/* Whether the APDU behind this NWK payload is Table 4-31's Transport Key command, which 3.6.2.2 accepts unsecured at
   a device that is not joined and authenticated. */
int Nwk_RxCarriesTransportKey(const uint8_t *payload, uint32_t payloadLen);

int Nwk_RxUnsecuredAccepted(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                            int destinedToSelf);

/* The octets a relay puts on the air: the frame as read, its radius already paid for, and nothing else rewritten;
   the caller clears 3.3.1.1.8's End Device Initiator bit in the frame first, where it applies. */
ZbStatus Nwk_RxForwardCopy(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                           uint8_t *npdu, uint32_t npduMax, uint32_t *outLen);

/* 3.6.4.3.2's four outcomes for a source-routed data frame, decided from the sub-frame and this device's own address:
   delivered here, relayed straight to the header's destination, relayed on to the previous relay, or dropped. */
typedef enum Nwk_SourceRouteVerdict
{
    NWK_SR_DELIVER = 0,        /* relay index 0 and the destination is this device */
    NWK_SR_RELAY_DIRECT = 1,   /* relay index 0, somebody else's destination, and this device has routing duty */
    NWK_SR_RELAY_ONWARD = 2,   /* the index names this device, which is to relay to the relay before it */
    NWK_SR_DROP = 3            /* the index names another device, or an end device must not relay */
} Nwk_SourceRouteVerdict;

/* 3.6.4.3.2 over one frame: `nextHopOut` is where a relay goes, and 0 when the verdict is DELIVER or DROP. The
   end-device-child case is the clause's own: the frame is unicast to that child rather than relayed onward. */
Nwk_SourceRouteVerdict Nwk_RxSourceRoute(const Nwk_Frame *frame, uint16_t ownAddr, uint32_t deviceType,
                                         const Nwk_NeighborTableEntry *neighbors, uint16_t *nextHopOut);

#endif /* NWK_RX_H */
