/* The `mac` suite's shared machinery.

   What three or more of the suite's topic case files use, once: the rigs, the request builders, the poll the
   suite composes and injects, the air log and the accessors it is read through, and the cast of addresses and
   Frame Control Field values every file names. `payload` is here for the same reason: every request builder
   carries it, and a case that reads a composed frame back compares those eight octets.

   Nothing here is state two cases share: every rig is the caller's own storage on the case's own stack, and the
   one file-scope object is the suite's vocabulary (the payload every request is built on) not its memory. */

#ifndef MAC_HELPERS_H
#define MAC_HELPERS_H

#include <stdint.h>

#include "loopback_radio.h"
#include "mac.h"
#include "rig_band_a.h"

#define AIR_UNICAST_FCF 0x8861      /* data, ack requested, one PAN field, 16-bit addresses both ends */
#define AIR_BROADCAST_FCF 0x8841    /* data, nobody asked to answer */
#define AIR_POLL_FCF 0x8863         /* MAC command, ack requested */

/* FCF subfield masks: the positions Figure 7-2 gives them and `mac_frame` writes them at, so an
   assertion can name the field it is about instead of a shift. */
#define FCF_FRAME_PENDING_BIT 0x10      /* bit 4 */
#define FCF_ACK_REQUEST_BIT 0x20        /* bit 5 */
#define FCF_PAN_COMPRESSION_BIT 0x40    /* bit 6 */

/* The poll cases stand in for both halves at once, so the rig is a coordinator rather than a child: this
   device's own short address is 0x0000, which is what a child's poll carries in its Destination Address
   field and what 10.22.4.1 pins its Destination PAN ID to (macPanId), and what the zero-length answer is
   addressed from. A and B are the two sleepy children whose polls get injected: two devices is the
   smallest set that can show that one device's queue order is not the other's (10.22.2). */
#define COORDINATOR_SHORT 0x0000
#define PAN_ID 0xbeef
#define SLEEPY_A 0x1234
#define SLEEPY_B 0x5678

/* The eight octets every request in this suite carries, and the ones a case reads back out of a composed
   frame. Defined in `mac_helpers.c`. */
#define PAYLOAD_LEN 8
extern const uint8_t payload[PAYLOAD_LEN];

/* A frame this device put on the air, kept by the suite rather than by the backend. A record is reclaimed
   when its completion is collected: `loopbackOpCompletion` clears the handle, and the next transmit takes that
   slot, so a count or an index read after such a collection is a read of whatever frame came after it. Every
   case that has an answer collected along the way therefore harvests after each request and each turn and
   makes its claims about these copies, taken while the record they describe was still live. The ledger counts
   distinct frames (a retransmission of the same octets adds nothing to it), which is what makes "nothing new
   went on the air" a sentence with one meaning. */
typedef struct Air
{
    uint32_t len;
    int ackRequest;
    uint8_t bytes[RADIO_MPDU_MAX];
} Air;

enum
{
    AIR_LOG_MAX = 24
};

/* The device every case that names no config builds (the radio's capabilities, the address and the PAN)
   and the variant a case builds when it names a config or the radio it was handed. */
void rigConfig(Test_BandA *rig, const Radio_Caps *caps, uint16_t shortAddress, uint16_t panId,
               const Mac_Config *config);
void rig(Test_BandA *rig, uint16_t shortAddress, uint16_t panId);

/* A request: one this module is asked to send, and one meant to be queued for a device that is not there. */
Mac_DataRequestParameters dataReq(uint32_t frameType, uint32_t destMode, uint16_t destPan, uint16_t destShort,
                    uint32_t srcMode, int ackRequest);
Mac_DataRequestParameters indirectReq(uint32_t frameType, uint32_t destMode, uint16_t destPan, uint16_t destShort,
                        const uint8_t *what, uint32_t len);

/* The child side of the poll, composed by the suite because the suite is what puts a poll in front of a
   coordinator, and the two ways a frame arrives from a neighbor. */
uint32_t composePoll(uint8_t *out, uint8_t dsn, uint16_t src);
uint32_t composePollTo(uint8_t *out, uint8_t dsn, uint16_t src, uint16_t dest);
uint32_t composePollToPan(uint8_t *out, uint8_t dsn, uint64_t src);

/* The other frames this suite puts in front of a coordinator: a child's Association Request (10.21.5.1:
   extended source, the source PAN the broadcast one, the destination the coordinator's short address), a
   Data Request from a child that has no short address yet (10.22.4.1: the source is the extended address), and
   the coordinator's Association Response, which only a child's case ever sees arrive (10.21.5.2). */
uint32_t composeAssociationRequest(uint8_t *out, uint8_t dsn, uint64_t child, uint8_t capability);
uint32_t composeAssociationRequestToPan(uint8_t *out, uint8_t dsn, uint64_t child, uint8_t capability);

/* 10.21.5.2's answer, composed by the suite because the suite is what puts a coordinator's decision in front of
   an associating device: extended addressing at both ends, the destination the child, the source the parent,
   and the three content octets Table 10-102's status and the allocated short address make. */
uint32_t composeAssociationResponse(uint8_t *out, uint8_t dsn, uint64_t child, uint64_t parent,
                                    uint16_t shortAddress, uint8_t status);
uint32_t composePollExtended(uint8_t *out, uint8_t dsn, uint64_t src);
void injectFrame(Loopback_Radio *model, const uint8_t *bytes, uint32_t len, uint64_t stamp);
void injectPoll(Loopback_Radio *model, uint8_t dsn, uint16_t src, uint64_t stamp);

/* What a case reads off a frame the backend recorded and off the suite's own copy of one. */
uint16_t fcfOf(const Loopback_Sent *sent);
uint32_t sentIndexFor(const Loopback_Sent *sent, uint32_t count, uint16_t destShort, uint8_t dsn);
void harvestAir(Loopback_Radio *model, Air *log, uint32_t *count);
uint32_t airIndexOf(const Air *log, uint32_t count, uint16_t destShort, uint8_t dsn);

#endif /* MAC_HELPERS_H */
