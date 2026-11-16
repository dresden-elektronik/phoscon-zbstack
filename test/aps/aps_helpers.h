/* The `aps` suite's shared machinery.

   What two or more of the suite's topic case files use, once: the rigs and the peers, the request builders, the
   air log and the accessors it is read through, the data header and the acknowledgement a case compares against
   a composition the service did not make, the hand-over a peer's frame arrives by, and the one turn. The cast of
   addresses, the two Frame Control Field families and the octet offsets every frame of this suite is read at are
   here for the same reason: they are the suite's own reading of band A's APS service, and every topic file reads
   them.

   Nothing here is state two cases share: every rig is caller-owned storage on the case's own stack, and there is
   no file-scope object at all. */

#ifndef APS_HELPERS_H
#define APS_HELPERS_H

#include <stdint.h>

#include "aps.h"
#include "aps_frame.h"
#include "loopback_radio.h"
#include "nwk.h"
#include "rig_band_a.h"

/* A, B and C: the three devices the cases need. A is the device under test in every case: a router, listening,
   with routing duties (3.6.2.2, 3.6.6), because a coordinator-shaped or sleepy device changes what the network
   layer below does with a broadcast and none of that is this module's decision. B is the peer the acknowledged
   transactions are aimed at and the device that answers them. C exists for one case only: an acknowledgement
   that matches on every APS field and comes from a device that is not the one the transaction addressed. */
#define OWN_SHORT 0xdead
#define ADDR_PEER 0x0011
#define OWN_IEEE 0x00212effff048a12
#define ADDR_THIRD 0x0022
#define PAN_ID 0xbeef
#define UNSEEN 0x9999
#define GROUP_ID 0x1234

/* The SAP fields every case uses unless it says otherwise: an application endpoint at each end (0x00 is the
   ZDO, 2.2.5.1.2), a profile and a cluster the
   acknowledgement has to repeat (2.2.5.2.3.1). */
#define SRC_EP 0x01
#define DST_EP 0x02
#define PROFILE_ID 0x0104
#define CLUSTER_ID 0x0006

#define ASDU_LEN 6
#define AIR_LOG_MAX 24

/* The frames of this PAN as nwk/ in test/ records them (docs/internals/protocol.md §9.1): a unicast asks the MAC to
   acknowledge it (3.6.4.3's own decision, made by the layer below and unchanged by an APS AR bit) and a
   broadcast never does, 3.6.6's "Broadcast transmissions SHALL NOT use the MAC sub-layer acknowledgement". */
#define AIR_UNICAST_FCF 0x8861
#define AIR_BROADCAST_FCF 0x8841

/* The Frame Control Field of the minimal NWK data frame the layer below writes: frame type Data in bits 0-1,
   nwkcProtocolVersion 0x02 in bits 2-5, and the route-discovery ask 2.2.8.4.1 obliges a unicast to carry in bit 6.
   The security sub-field is set only where the network holds the key 4.2.2 asks for and these rigs hold none. Low
   octet first, as 3.3 orders it (Figure 3-5). */
#define NWK_FCF_DATA 0x08
#define NWK_FCF_DATA_DISCOVERING 0x48

/* The APS Frame Control Fields this slice writes, spelled out from Figure 2-4: bits 0-1 frame type, 2-3
   delivery mode, 4 ack format, 5 security, 6 ack request, 7 extended header. A data frame this module composes
   is unsecured (FCF bit 5 is 0 on every frame the first slice writes) and never fragmented
   (bit 7). */
#define APS_FCF_DATA_UNICAST 0x00
#define APS_FCF_DATA_UNICAST_ACKED 0x40
#define APS_FCF_DATA_BROADCAST 0x08
#define APS_FCF_DATA_GROUP 0x0c
#define APS_FCF_ACK 0x02        /* frame type 0b10 in bits 0-1 and nothing else set: delivery mode 0b00, ACK
                                   format 0 (2.2.5.1.1.3), security 0, ACK request 0 (2.2.8.4.3). This is the
                                   octet the codec writes for the shape `ackApdu` composes, and it is asserted
                                   from case 14 on: the value this define carried before the reception slice
                                   landed was 0x20, which is FCF bit 5, the security sub-field, and nothing in the
                                   suite ever read the field to notice */

/* The counter octet of the two data forms this slice writes: Figure 2-3's column order puts it last, at offset
   7 of the unicast and broadcast header (fcf, dst endpoint, cluster, profile, src endpoint) and at offset 8 of
   the group header, which replaces the destination endpoint with a two-octet group address. */
/* The two data-header forms this slice writes, in octets: Figure 2-3 with Figure 2-7's columns (frame control,
   destination endpoint, cluster, profile, source endpoint, APS counter) and the group form, which replaces the
   destination endpoint with a two-octet group address and so runs one octet longer. A data unicast/broadcast
   header and an ACK format 0 header are the same eight octets, column for column, which is why one name serves
   both here. */
#define APS_HEADER_UNICAST_FORM 8
#define APS_HEADER_GROUP_FORM 9

#define APS_COUNTER_OCTET_UNICAST 7
#define APS_COUNTER_OCTET_GROUP 8

/* One frame this module put on the air, kept by the case that has to read it after the answer that reclaimed
   the backend's record. */
typedef struct Air
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    int ackRequest;
} Air;

/* A device under test: the band-A device the shared rig builds (test/support/rig_band_a.h: a backend, a MAC
   on it and a network layer on that) and the APS service on top of it. Every field is caller-owned storage on
   the case's stack, as docs/internals/coding-rules.md §4.3 requires of the modules themselves. */
typedef struct Rig
{
    Test_BandA stack;
    Aps_Aps aps;
} Rig;

void rigBuild(Rig *rig, uint16_t own);
void peerBuild(Test_BandA *peer, uint16_t own);
void seedNeighbor(Nwk_Nwk *nwk, uint16_t addr);

Nwk_DataRequestParameters nldeReq(uint16_t dst, const uint8_t *what, uint32_t len);
Aps_ApsdeReq sapReq(uint32_t dstAddrMode, uint16_t dstAddress, uint8_t dstEndpoint, uint16_t clusterId,
                    const uint8_t *asdu, uint32_t asduLength, uint32_t txOptions);

void scriptOutcomes(Loopback_Radio *model, uint32_t count, int answered);

void harvestAir(Loopback_Radio *model, Air *log, uint32_t *count);
uint16_t fcfOf(const Air *air);
uint16_t airDestOf(const Air *air);
const uint8_t *npduOf(const Air *air);
const uint8_t *apduOf(const Air *air);
uint32_t apduLenOf(const Air *air);
uint8_t nwkSeqOf(const Air *air);

void dataHeader(Aps_Frame *frame, uint32_t deliveryMode, int ackRequest, uint8_t apsCounter,
                uint8_t dstEndpoint, uint16_t clusterId);
uint32_t ackApdu(uint8_t *out, uint8_t apsCounter, uint8_t srcEndpoint, uint8_t dstEndpoint,
                 uint16_t clusterId);

void handOver(Loopback_Radio *from, Loopback_Radio *to);
void peerSends(Test_BandA *peer, Loopback_Radio *to, uint16_t dst, const uint8_t *apdu,
               uint32_t apduLen, uint32_t nowMs);
void peerDelivers(Test_BandA *peer, Loopback_Radio *to, uint16_t dst, const uint8_t *apdu,
                  uint32_t apduLen, uint32_t nowMs);
uint32_t composeApdu(const Aps_Frame *frame, const uint8_t *asdu, uint32_t asduLength, uint8_t *out);

void stepAt(Rig *rig, Air *air, uint32_t *airCount, uint32_t nowMs);

#endif /* APS_HELPERS_H */
