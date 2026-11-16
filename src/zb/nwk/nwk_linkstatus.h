#ifndef NWK_LINKSTATUS_H
#define NWK_LINKSTATUS_H

/* 3.4.8's link status command and the two metrics 3.6.4.4.2 derives from it, which 3.6.4.4.3's ranking is made
   of; docs/internals/conformance.md owns the clause marks and docs/internals/conformance.md §2 the deferrals. */

#include <stdint.h>

#include "nwk_neighbor.h"
#include "zb_status.h"

enum
{
    NWK_LINK_STATUS_ENTRY_MAX = 31,   /* Figure 3-20's five-bit entry count */
    NWK_LINK_STATUS_ENTRY_LEN = 3,    /* Figure 3-21: the address, least significant octet first, then the status octet */
    NWK_LINK_STATUS_COST_MAX = 7,     /* 3.4.8.3.2: "a value between 1 and 7", which 3.6.4.4.2 subtracts from 7 */
    NWK_LINK_STATUS_RADIUS = 1,       /* 3.4.8.2: a link status is a one-hop broadcast */

    NWK_LINK_STATUS_OPTIONS_FIRST = 0x20,   /* Figure 3-20 bit 5 */
    NWK_LINK_STATUS_OPTIONS_LAST = 0x40     /* Figure 3-20 bit 6 */
};

/* One entry of Figure 3-21: the neighbour, and the two costs the status octet carries in bits 0-2 and 4-6. */
typedef struct Nwk_LinkStatusEntry
{
    uint16_t networkAddress;
    uint32_t incomingCost;
    uint32_t outgoingCost;
} Nwk_LinkStatusEntry;

/* Figure 3-19's payload: the options octet and the list it counts. */
typedef struct Nwk_LinkStatus
{
    uint32_t count;
    int firstFrame;
    int lastFrame;
    Nwk_LinkStatusEntry entries[NWK_LINK_STATUS_ENTRY_MAX];
} Nwk_LinkStatus;

/* The command's payload as Figure 3-19 and Figure 3-20 print it: the entry count bounds the list, and a list that
   does not fill the count is refused rather than read short. */
ZbStatus Nwk_LinkStatusParse(const uint8_t *payload, uint32_t payloadLen, Nwk_LinkStatus *out);

/* 3.6.4.4.2 step 2: the sum over the entries with a non-zero outgoing cost of 7 less the larger of the two costs. */
uint32_t Nwk_LinkStatusConnectivity(const Nwk_LinkStatus *list);

/* 3.6.4.4.2 step 3: the same sum over the advertised neighbours this device does not itself hold with a non-zero
   outgoing cost, which is how different the sender's neighbourhood is from this one. */
uint32_t Nwk_LinkStatusDiversity(const Nwk_LinkStatus *list, const Nwk_NeighborTableEntry *pool);

/* 3.6.4.4.2 over the neighbour table: RouterAge and the two metrics on the sender's first frame, then the range check,
   then the sender's outgoing cost. `senderWasKnown` is 0 for an entry this frame made, whose RouterAge 8954 starts at 0.
   0 when this device lies outside the frame's range, 1 when it was searched. */
int Nwk_LinkStatusApply(Nwk_NeighborTableEntry *pool, uint16_t sender, uint16_t own, const Nwk_LinkStatus *list,
                        int senderWasKnown, uint32_t nowMs);

/* One frame of 3.6.4.4.1's list from this device's own table: Figure 3-19's options octet, then the router entries at or
   above `fromAddress`, sorted by address as 3.4.8.3.2 requires, as many as `outCap` octets hold. `*lastFrame` says the
   list ended; otherwise the next frame takes `*lastAddress`, the address this one ended on, as its `fromAddress`. */
ZbStatus Nwk_LinkStatusCompose(const Nwk_NeighborTableEntry *pool, int firstFrame, uint16_t fromAddress, uint8_t *out,
                               uint32_t outCap, uint32_t *outLen, uint32_t *entryCount, int *lastFrame,
                               uint16_t *lastAddress);

/* 3.6.4.4.3's printed rank, the four terms with their coefficients. */
uint32_t Nwk_NeighborRank(const Nwk_NeighborTableEntry *entry);

/* The assessment pool: the siblings whose age is past nwkcMinRouterObservationTime, as indices into `pool`. */
uint32_t Nwk_NeighborAssessmentPool(const Nwk_NeighborTableEntry *pool, uint32_t minObservationAge, int *out,
                                    uint32_t outMax);

/* 3.6.4.4.3.1's removal: the lowest-ranked entry that is neither a backbone mesh sibling nor an end-device child
   and has been observed past `minObservationAge`, or -1 when every entry is one this device may not drop. */
int Nwk_NeighborMakeRoom(const Nwk_NeighborTableEntry *pool, uint32_t minObservationAge);

/* 3.6.4.4.3.1's promotion over the backbone siblings and the assessment pool together: the top `backboneMax` of the
   combined set become backbone mesh siblings and the rest siblings. Answers how many entries changed. */
uint32_t Nwk_NeighborPromoteBackbone(Nwk_NeighborTableEntry *pool, uint32_t formationAge, uint32_t backboneMax);

#endif
