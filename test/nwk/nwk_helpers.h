/* The band-A device rig and the frame vocabulary the `nwk` suite's topic case files and the `nwk_routeflow`
   suite's initiation half share.

   What two or more case files use, once: the one frame record a case reads after its
   answer was taken and the accessors it reads it through, the rigs, the request and NPDU builders, the
   injection path a received frame arrives by, and the accessors a case asserts a table through. The cast of
   addresses, the octet offsets every frame of this suite is read at and the Frame Control Field values a
   hand-written NPDU needs are here for the same reason: they are the suite's own reading of band A, and every
   topic file reads them.

   Nothing here is state two cases share: every rig is caller-owned storage on the case's own stack, and the
   two file-scope objects are the suite's vocabulary, not its memory. */

#ifndef NWK_HELPERS_H
#define NWK_HELPERS_H

#include <stdint.h>

#include "loopback_radio.h"
#include "mac_frame.h"
#include "nwk.h"
#include "rig_band_a.h"

/* This device, and the addresses the cases need. A router rather than a coordinator, because the transmit
   half's rules (relaying, copying, retrying) are a router's, and 3.6.6 gives a coordinator the same ones.
   SLEEPY is an end device child with macRxOnWhenIdle FALSE, which is the only device 3.2.1.1.3 item 7 and
   3.6.6 step 1 copy a broadcast to. UNSEEN has no neighbor entry and no route. */
#define OWN_SHORT 0xdead
#define PAN_ID 0xbeef
#define NEIGHBOR 0x1234
#define SLEEPY 0x1357
#define ROUTER_NEIGHBOR 0x2468
#define UNSEEN 0x9999
#define HOP 0x7777

#define NSDU_LEN 6
#define AIR_LOG_MAX 20

/* The FCF of this PAN's two data-frame classes, as `mac`'s suite records them (docs/internals/protocol.md §9.1):
   0x8861 is data with an acknowledgment asked and one PAN field, 0x8841 is data nobody is asked to answer. */
#define AIR_UNICAST_FCF 0x8861
#define AIR_BROADCAST_FCF 0x8841

/* A data frame with short addressing at both ends and one PAN field: 2 + 1 + 2 + 2 + 2 octets of MAC header,
   which is where the NWK frame the MAC is carrying begins. Every frame this suite reads is that shape,
   because 3.6.4.3 pins both address modes to 0x02 and both PAN fields to macPANId, so compression is always
   available here. */
#define NPDU_OFFSET 9
#define FCS_OCTETS 2

/* Inside an NPDU, the octet order Figure 3-4 prints: Frame control (2), Destination address (2), Source
   address (2), Radius (1), Sequence number (1). */
#define NPDU_RADIUS_OCTET 6
#define NPDU_SEQ_OCTET 7

/* The Frame Control Field of the minimal NWK data frame this stack writes: frame type Data in bits 0-1,
   nwkcProtocolVersion 0x02 in bits 2-5, every other sub-field zero (Figure 3-5). Low octet first, which is
   3.3's own order for a field longer than one octet. */
#define NWK_FCF_DATA 0x08

/* The Frame Control Field values a hand-written NPDU needs. Figure 3-5: bits 0-1 frame type, 2-5 protocol
   version, 9 security, 13 End Device Initiator. */
#define NWK_FCF_DATA_V1 0x0004        /* frame type Data, protocol version 0x01 (Table 1-5's Zigbee 2004) */
#define NWK_FCF_DATA_V3 0x000e        /* protocol version 0x03, Green Power, Annex G */
#define NWK_FCF_DATA_SECURED 0x0208   /* a data frame at nwkcProtocolVersion 0x02 with the security sub-field set: a whole Frame Control Field, and the form the codec now reads while this module, with no key material, cannot */
#define NWK_FCF_SECURITY_BIT 0x0200     /* Figure 3-5 bit 9 alone, which is the mask a Frame Control Field is tested with */
#define NWK_FCF_RESERVED_TYPE 0x000a  /* frame type 0b10, which Table 3-52 prints Reserved */
#define NWK_FCF_END_DEVICE 0x2000     /* bit 13, the End Device Initiator sub-field (3.3.1.1.8) */
#define NWK_FCF_DISCOVER_ENABLE 0x0040 /* bits 6-7 at 01, Discover Route enabled (Table 3-53) */

/* How many octets two NPDUs differ in. A relay may change the radius and nothing else, so the answer a case
   wants is usually "one" together with "and it is the radius octet". Two NPDUs of different lengths are not the
   same frame at all, and the answer for that is a number no comparison of octets can produce. */
#define NPDU_LENGTHS_DIFFER 0xffffffff

/* The NSDU every accepted request carries, defined in `nwk_helpers.c`: its octets are the point of two
   assertions, the NPDU payload is the NSDU untouched, and a retry re-offers the same octets. */
extern const uint8_t nsdu[NSDU_LEN];

/* One frame this module put on the air, kept by the case that has to read it after its answer was taken. */
typedef struct Air
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    int ackRequest;
} Air;

/* The rigs: this suite's reading of what the shared band-A build produced, the PIB the backend took, the
   network layer on the MAC by pointer and not by copy, and the device type and the numbering the config
   named. A router rather than a coordinator, because the transmit half's rules (relaying, copying,
   retrying) are a router's and 3.6.6 gives a coordinator the same ones. */
void rigAtSeed(Test_BandA *rig, uint16_t own, uint16_t panId, uint32_t deviceType, int rxOnWhenIdle,
               uint32_t seqStart, uint32_t jitterSeed);

/* The extended address the device's own PIB reports, written after the rig is built: the 64-bit identity
   3.4.1.2 and 3.4.2.2 make a command frame carry, which a rig that names none leaves as zeros. */
void setOwnIeee(Test_BandA *rig, uint64_t ieee);
void rigAt(Test_BandA *rig, uint16_t own, uint16_t panId, uint32_t deviceType, int rxOnWhenIdle);
void rig(Test_BandA *rig, uint16_t own, uint16_t panId);
void seedNeighbor(Nwk_Nwk *nwk, uint16_t addr, uint32_t deviceType, int rxOnWhenIdle,
                  uint32_t relationship);

/* A request, and the scripted answers a radio gives the transmits it causes. */
Nwk_DataRequestParameters nldeReq(uint16_t dst, const uint8_t *what, uint32_t len, uint8_t radius);
void scriptOutcomes(Loopback_Radio *model, uint32_t count, int answered);

/* The air log, and the fields of one logged frame this suite reads. A frame is copied out of the backend after
   the answer that reclaimed its record, so a case can keep reading it; an injected frame never appears in it,
   which is what makes "not relayed" mean one thing in every case. */
void harvestAir(Loopback_Radio *model, Air *log, uint32_t *count);
uint16_t fcfOf(const Air *air);
uint8_t dsnOf(const Air *air);
uint16_t airDestOf(const Air *air);
uint16_t airSrcOf(const Air *air);
const uint8_t *npduOf(const Air *air);
uint32_t npduLenOf(const Air *air);
uint32_t airBroadcastCount(const Air *air, uint32_t count, uint16_t dest);
/* The frames of the log a Table 3-80 class names: the class rides the NWK header's destination field and the
   MAC destination is 0xffff for every one of them (3.2.1.1.3 step 6 a.3), so a count by class reads the NPDU. */
uint32_t airClassCount(const Air *air, uint32_t count, uint16_t nwkDest);

/* The child side of the indirect copy: 10.22.4.1's poll, composed by the suite because the suite is what puts
   it in front of the device holding the copy, addressed to OWN_SHORT or, by `composePollTo`, to `dst`. */
void composePoll(Loopback_Radio *model, uint8_t dsn, uint16_t src);
void composePollTo(Loopback_Radio *model, uint8_t dsn, uint16_t src, uint16_t dst);

/* An NPDU this stack can compose and one the codec will not, and the three ways one arrives as a neighbor's
   frame: clean, with its footer damaged, and addressed by an extended source. The MAC frame the NPDU travels in
   is the helper's business (3.4.1.1) and its destination follows from the NPDU: 0xFFFF when the NWK header names
   one of 3.6.6's broadcast addresses (3.2.1.1.3 step 6 a.3, 6.2), this device's own address when the frame is a
   unicast, because the device it arrives at is its next hop. */
uint32_t makeNpdu(uint8_t *out, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                  uint32_t frameType, uint32_t endDeviceInitiator, const uint8_t *payload,
                  uint32_t payloadLen);

/* 3.4.6's NWK Rejoin Request (Figure 3-17: Command ID 0x06 and one Capability Information octet) as an NPDU a
   neighbour's frame carries: the two IEEE address sub-fields present, because 3.4.6.2 pins both, and a radius of
   one, which is 3.4.6.2's own rule for the pair. The sequence number is the suite's and counts up, so two requests
   one case builds are never the same frame. The caller injects it through `injectNpdu`: this is an NPDU, and the
   MAC frame it travels in is `injectNpdu`'s business (3.4.1.1). */
uint32_t makeRejoinNpdu(uint8_t *out, uint16_t dst, uint16_t src, uint64_t srcIeee, uint64_t dstIeee,
                        uint8_t capability);
uint32_t rawNpdu(uint8_t *out, uint16_t fcf, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                 const uint8_t *payload, uint32_t payloadLen, uint32_t truncateTo);
void injectNpduAs(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, Mac_AddrMode srcAddrMode,
                  uint16_t macSrc);
void injectNpdu(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, uint16_t macSrc);
void injectBrokenNpdu(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, uint16_t macSrc);

/* What a case reads off the octets and off the two tables a received frame writes. */
uint32_t npduDiffCount(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen);
Nwk_NeighborTableEntry *neighborAt(Nwk_Nwk *nwk, uint16_t address);
Nwk_BroadcastTransactionRecord *bttFor(Nwk_Nwk *nwk, uint16_t src, uint8_t seq);
uint16_t nwkFcfOf(const uint8_t *npdu);

#endif /* NWK_HELPERS_H */
