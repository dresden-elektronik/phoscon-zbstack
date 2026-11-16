/* The `mac` suite's indirect queue: the coordinator half of 10.22.2, the
   transaction a request for a device that is not there becomes, the Data Request that extracts it, the attempts
   that are refused or time out, the empty and the full pool answers beside it, and the polls this module cannot
   answer at all. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* What a delivered transaction looks like on the wire: this PAN's captured acknowledged unicast data frame,
   0x8861 (docs/internals/protocol.md §9.1), with the Frame Pending bit 7.2.2.4 adds when 10.22.2 says another
   transaction for the same device exists, and the same pair of values for a command frame the queue
   extracted. The pending bit is the only difference from a shape the captures record; the answer itself is
   composed here, because no coordinator's reply to a poll is in the dissected set in test/fixtures/. */
#define AIR_DELIVERED_FCF 0x8871
#define AIR_DELIVERED_COMMAND_FCF 0x8873

/* The same command with its Source Address field absent, which is not one of the two forms 10.22.4.1 and
   10.22.5.2 write: a poll directed to the PAN coordinator may omit the *destination* information, while its
   Source Addressing Mode "shall be set according to the value of macShortAddress". It is here because a
   coordinator has to be able to say what it can do with a Data Request that names no device. */
uint32_t composePollWithoutSource(uint8_t *out, uint8_t dsn)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;      /* 7.2.2.6: one address present, so the single PAN field is kept */
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_NONE;
    frame.destPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                 ZB_OK, "a command frame with no source fields is a frame this stack can compose (7.2.2.11)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                 "closed by the footer those octets compute (7.2.11)");

    return len;
}

uint16_t airFcf(const Air *air)
{
    return (uint16_t)(air->bytes[0] | (air->bytes[1] << 8));
}

/* Queueing is not sending. An indirect request becomes a transaction and the transaction waits, the air
   stays empty until the device it is held for asks for it (10.22.2), and the one thing the
   call does take is a sequence number, because 6.6.3.4 makes that number belong to the transaction for its
   whole life. */
void caseIndirectEnqueue(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    const uint8_t pollCommand[1] = { MAC_CMD_POLL };
    uint8_t oversized[MAC_FRAME_MPDU_MAX];
    uint32_t got;
    uint32_t i;
    Mac_Counters counters;

    Zb_memset(oversized, 0x5a, (uint32_t)sizeof oversized);

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, (uint16_t)(0x1000 + i), payload,
                          (uint32_t)sizeof payload);
        Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100 + i), ZB_OK,
                     "an indirect request for a sleepy short address becomes a transaction (10.22.2: 'The coordinator shall begin handling a transaction on receipt of an indirect transmission request')");
    }

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == MAC_TRANSACTION_MAX, "the queue holds every one of them");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0,
           "and nothing at all went on the air from the calls that queued them: a transaction waits for a Data Request from the device it is held for (10.22.2, 10.22.3)");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == 0 && counters.confirmQueue == 0,
           "no frame was issued, so no track slot was taken and no confirmation exists to collect");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, 0x2000, payload, (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 200), ZB_ERR_TRANSACTION_OVERFLOW,
                  "the request past the pool is named rather than dropped: 10.22.2's TRANSACTION_OVERFLOW, 'there is no capacity to store another transaction', is what the full pool answers");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.refusedRequests == 1, "counted as a refusal");
    Test_Expect(counters.transactionQueue == MAC_TRANSACTION_MAX, "and it displaced nothing that was already queued");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, MAC_FRAME_ADDR_BROADCAST, payload,
                      (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 210), ZB_ERR_UNSUPPORTED,
                  "0xffff, All Devices in PAN, is refused a place in the queue: 3.2.1.1.3 item 6 sets IndirectTX FALSE for it");

    req = indirectReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, pollCommand, 1);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 220), ZB_ERR_UNSUPPORTED,
                  "a Data Request command is refused a place in the queue it would extract: 10.22.5.2, the poll is the asking device's own act");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_NONE, PAN_ID, 0, payload, (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 230), ZB_OK,
                  "and a request naming no destination has its indirect option ignored, 8.3.4's answer being a direct transmission");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, 0x2001, oversized, (uint32_t)sizeof oversized);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 240), ZB_ERR_BAD_ARGUMENT,
                  "a payload that cannot fit one 127-octet MPDU is refused at the door, the ceiling MAC_FRAME_MPDU_MAX states (13.1.3.2)");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == MAC_TRANSACTION_MAX, "none of the refusals queued anything");
    Test_Expect(counters.refusedRequests == 4, "and every one of them was counted, not swallowed");
    Test_Expect(counters.indirectIgnored == 1, "while the ignored option was counted apart, as something sent rather than refused");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1,
           "and the one frame on the air is that ignored option's, transmitted directly");

    /* The arithmetic the queue owes the direct path, read where the air can show it: the pool's queueings took
       one number each and never sent them, the refusals took nothing, and the ignored option took the next. */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 300, 0), ZB_OK, "the direct path is untouched by the queue beside it");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 2);
    Test_Expect(got == 2, "two frames on the air: the ignored option's and this one");
    Test_Expect(sent[1].bytes[2] == (uint8_t)(MAC_TRANSACTION_MAX + 1),
           "and the second carries the DSN after them: each reservation took a number, the ignored option the next, "
           "and this frame the one after (6.6.1, 7.2.3)");
}

/* 8.3.4: "if the device receiving this primitive is not a coordinator ... the indirect transmission option will be
   ignored", and an ignored option is a transmission, not a queue entry. */
void caseIndirectIgnoredWithoutRole(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    Mac_Counters counters;
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, payload, (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK,
                      "a role nobody has stated leaves the queue open, 8.3.4's question unanswered");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "so the transaction is held");

    Test_ExpectStatus(Mac_SetCoordinator(&dev.mac, 1, 0), ZB_OK, "the layer above says this device is no coordinator");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, payload, (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK,
                      "and the next indirect request is ignored rather than refused, as 8.3.4 words it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "nothing new was queued");
    Test_Expect(counters.indirectIgnored == 1, "the ignored option is counted on its own");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "and one frame went out directly, which is what an ignored indirect option means");
    Test_Expect(sent[0].len == 11 + (uint32_t)sizeof payload,
                "addressed as a direct frame is: 11 octets of header, the payload and two of footer");
}

/* The poll extracts, and 10.22.2's ordering is a per-device fact: "it shall transmit transactions for the
   same device in the order in which they arrived at the MAC sublayer". */
void casePollExtractionOrder(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Mac_DataIndicationParameters indications[8];
    Mac_PollArrival arrivals[4];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    uint8_t aFirst[2] = { 0xa1, 0x11 };
    uint8_t aSecond[2] = { 0xa2, 0x12 };
    uint8_t bFirst[2] = { 0xb1, 0x22 };
    uint8_t bSecond[2] = { 0xb2, 0x23 };
    uint16_t fcf;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    /* Interleaved on purpose: two children arriving alternately is the smallest set that can show that one
       child's arrival order is not the other's, which is all 10.22.2 claims. */
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, aFirst, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "device A's first transaction");
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, bFirst, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "device B's first");
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, aSecond, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "A's second");
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, bSecond, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "and B's second: four transactions, no frames");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 4, "the queue holds all four");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    injectPoll(&dev.model, 0x21, SLEEPY_B, 5100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "one step takes both polls and answers both");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 2, "two answers on the wire, one per poll");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "two frames in the ledger, each copied while the backend still held its handle");

    i = sentIndexFor(sent, got, SLEEPY_A, 0x00);
    Test_Expect(i < got, "A's answer is the frame addressed to A at the number A's first transaction reserved");
    fcf = fcfOf(&sent[i]);
    Test_Expect(fcf == AIR_DELIVERED_FCF,
           "0x8871: this PAN's captured 0x8861 with 10.22.2's pending bit on top, the frame shape a coordinator's answer to a poll has on this PAN");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) != 0,
           "Frame Pending one: 'For each transaction sent, if another exists for the same device, the MAC sublayer shall set its Frame Pending field to one' (10.22.2)");
    Test_Expect((fcf & FCF_ACK_REQUEST_BIT) != 0,
           "the acknowledgment asked, because an extraction only succeeded once the acknowledgment came (10.22.2)");
    Test_Expect((fcf & FCF_PAN_COMPRESSION_BIT) != 0,
           "one PAN field, the destination being a device of this PAN (7.2.2.6)");
    Test_Expect(sent[i].bytes[2] == 0x00, "the DSN the queueing reserved, not one the transmit took (6.6.3.4)");
    Test_Expect(sent[i].bytes[7] == 0x00 && sent[i].bytes[8] == 0x00,
           "from this coordinator's own short address 0x0000, which is the address the poll was directed to (10.22.4.1)");
    Test_Expect(sent[i].len == 13 && sent[i].bytes[9] == 0xa1 && sent[i].bytes[10] == 0x11,
           "and A's oldest payload, untouched: nine octets of compressed header, two of Content, two of footer");
    Test_Expect(sent[i].ackRequest == 1, "and the seam was told the ask the wire carries");

    i = sentIndexFor(sent, got, SLEEPY_B, 0x01);
    Test_Expect(i < got, "B's answer is the frame addressed to B, and it carries the number B's transaction reserved");
    fcf = fcfOf(&sent[i]);
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) != 0,
           "Frame Pending one for B too: B has a second transaction queued, and it is B's own queue that decides the bit (10.22.2)");
    Test_Expect(sent[i].bytes[2] == 0x01 && sent[i].bytes[9] == 0xb1 && sent[i].bytes[10] == 0x22,
           "B's oldest first: A's four numbers do not order B's queue, and B's answer is not A's second transaction");

    got = Mac_PollArrivals(&dev.mac, arrivals, 4);
    Test_Expect(got == 2, "and both polls are pullable as events, oldest first, the way the confirmations are pulled");
    Test_Expect(arrivals[0].addrMode == MAC_ADDR_SHORT && arrivals[0].shortAddress == SLEEPY_A,
           "R23.1 D.10.2's MLME-Poll.indication names two fields and this reports them: the AddrMode and the DeviceAddress 'of the device requesting pending data', the poll's Source Address, not its destination");
    Test_Expect(arrivals[0].extendedAddress == 0, "and no extended address claimed for a poll that carried a short one");
    Test_Expect(arrivals[0].dsn == 0x20 && arrivals[0].stampTicks == 5000,
           "plus this module's own addition, which is what makes an arrival identifiable: the DSN and the stamp of the frame the arrival was");
    Test_Expect(arrivals[1].shortAddress == SLEEPY_B && arrivals[1].dsn == 0x21 && arrivals[1].stampTicks == 5100,
           "and B's poll behind it, in detection order");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == 0, "taken once, like every other queue here");

    got = Mac_PollIndications(&dev.mac, indications, 8);
    Test_Expect(got == 2, "the raw command frames are still in the indication queue, unchanged");
    Test_Expect(indications[0].len == 12 && indications[0].headerValid == 1,
           "the twelve-octet poll as delivered, header parsed and all");
    Test_Expect(indications[0].header.frameType == MAC_FRAME_TYPE_COMMAND && indications[0].payloadLen == 1
           && indications[0].bytes[indications[0].payloadOffset] == MAC_CMD_POLL,
           "Table 7-11's 0x04 Data Request command with its zero-length Content field (10.22.4.1)");
    Test_Expect(indications[0].header.ackRequest == 1 && indications[0].header.framePending == 0,
           "AR one and Frame Pending zero, which is what 10.22.4.1 sets rather than honours");
    Test_Expect(indications[0].header.srcShort == SLEEPY_A && indications[0].rssiDbm == -70
           && indications[0].lqi == 200 && indications[0].stampTicks == 5000,
           "with the source, the link metadata and the stamp the seam delivered: answering a poll does not edit the frame it answers");

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the next step collects the two answers");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 2 && confirms[0].acked == 1 && confirms[1].acked == 1,
           "both acknowledged, which is the only proof 10.22.2 accepts for an extraction");
    Test_Expect(confirms[0].dsn == 0x00 && confirms[1].dsn == 0x01,
           "each confirmation carrying the DSN of the frame it answers, so the layer above can match it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2, "the two acknowledged transactions left: 'If the transaction was successful, the transaction information shall be discarded' (10.22.2)");
    Test_Expect(counters.transactionsExpired == 0, "and they left as successes, not as expiries");

    injectPoll(&dev.model, 0x22, SLEEPY_A, 5200);
    injectPoll(&dev.model, 0x23, SLEEPY_B, 5300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "their next polls");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 2,
           "two answers on the air and only those two: collecting the first pair's confirmations freed their records");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 4,
           "while the ledger holds four distinct frames (the pair whose records were reclaimed and this pair) so 'only those two' is a claim about this turn and not about a backend that forgot the earlier one");

    i = sentIndexFor(sent, got, SLEEPY_A, 0x02);
    Test_Expect(i < got, "A's second transaction, at the number it reserved");
    fcf = fcfOf(&sent[i]);
    Test_Expect(fcf == AIR_UNICAST_FCF,
           "0x8861 with Frame Pending zero: nothing else exists for A, and 7.2.2.4 'shall be set to zero otherwise' is what lets the child conclude there is nothing more (10.22.3)");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) == 0, "the last transaction for a device is sent with the pending bit clear");
    Test_Expect(sent[i].bytes[9] == 0xa2 && sent[i].bytes[10] == 0x12, "and A's own second payload, in A's own order (10.22.2)");

    i = sentIndexFor(sent, got, SLEEPY_B, 0x03);
    Test_Expect(i < got, "B's second at its own number, behind A's in the air but not in B's queue");
    Test_Expect((fcfOf(&sent[i]) & FCF_FRAME_PENDING_BIT) == 0, "zero on B's last too");
    Test_Expect(sent[i].bytes[9] == 0xb2 && sent[i].bytes[10] == 0x23, "and B's own payload");

    Test_ExpectStatus(Mac_Step(&dev.mac, 230), ZB_OK, "their answers collected");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 2, "two confirmations");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0, "the queue is empty again");
    Test_Expect(counters.pollsUnanswered == 0 && counters.pollsSkipped == 0,
           "and nothing was missed on either side: every poll found a slot, every step found room");
}

/* A failed attempt is not a lost transaction. 6.6.3.4 is explicit: "the coordinator shall not retransmit
   the frame. Instead, the frame shall remain in the transaction queue of the coordinator and can only be
   extracted following the reception of a new Data Request command … using the same DSN as was used in the
   original transmission", so the re-offered frame is the same frame, and the only thing that moved is the
   attempt flag. */
void caseRefusedExtractionKeepsItsNumber(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Loopback_Outcome script[1];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    uint8_t transaction[2] = { 0xa1, 0x11 };
    uint8_t firstAttempt[RADIO_MPDU_MAX];
    uint32_t firstLen;
    uint32_t airCount = 0;
    uint32_t got;
    Mac_Counters counters;

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_ERR_DEVICE;         /* what NO_ACK (17) becomes at the seam */
    script[0].isAcked = 0;
    script[0].retries = 1;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 1);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, transaction, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "one transaction queued for A");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "A's poll extracts it");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame went out");
    Test_Expect(sent[0].bytes[2] == 0x00, "at the DSN the transaction reserved");
    firstLen = sent[0].len;
    Zb_memcpy(firstAttempt, sent[0].bytes, firstLen);

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and the ledger holds it, copied before any answer can reclaim its record");

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the answer comes back as a refusal");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE && confirms[0].acked == 0,
           "the confirmation names the refusal, as R23.1 3.6.4.3 wants the layer above to retry against");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1,
           "and the transaction is still queued: 6.6.3.4, 'the frame shall remain in the transaction queue of the coordinator'");
    Test_Expect(counters.transactionsExpired == 0, "it was not discarded, because a failed attempt is not an expired transaction (10.22.2)");

    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "a step with no poll in it");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1,
           "puts nothing new on the air that the ledger did not already hold: 6.6.3.4 forbids the retransmission, and 10.22.2 makes a new Data Request the only thing that can extract the transaction");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == 0,
           "and band A holds no attempt either, which is the half a backend count cannot say once a collected record has freed its slot for the next frame");
    Test_Expect(counters.pollsUnanswered == 0, "and no poll was counted as unanswered, because no poll arrived");

    injectPoll(&dev.model, 0x21, SLEEPY_A, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 230), ZB_OK, "A polls again");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1,
           "one record on the backend, and it is this frame: the first attempt's record was collected at the turn that reported the refusal, and its slot is this transmission's to take");
    Test_Expect(sent[0].bytes[2] == 0x00,
           "with the same DSN on the wire: 'the originating device shall transmit the frame using the same DSN as was used in the original transmission' (6.6.3.4)");
    Test_Expect(sent[0].len == firstLen && Zb_memcmp(sent[0].bytes, firstAttempt, firstLen) == 0,
           "byte-identical to the frame that failed: same number, same Frame Control, same payload, because a re-extraction is the same transaction and not a new one");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == 1,
           "and it is an attempt this module now holds, which is what a re-offering costs and what the ledger alone could not tell from a copy");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1,
           "while the ledger still holds one distinct frame: the re-extraction is the same octets, and 6.6.3.4 is the clause that says so");

    /* That the module's own counter never moved is visible on the air rather than in a field: the next
       frame this device sends for itself takes the number the queueing reserved, which is 1; an attempt
       that was retransmitted, or a re-extraction that consumed a number, would show up as 2. */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 240, 0), ZB_OK, "a direct frame afterwards");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 2, "the backend holds both frames: the re-extraction whose answer is still outstanding, and this one");
    Test_Expect(sent[1].bytes[2] == 0x01,
           "at DSN 1, which is the number the enqueue took and nothing else took (7.2.3, 6.6.3.4)");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "and the ledger now holds two distinct frames, the re-offered transaction and this new one");
    Test_Expect(airIndexOf(air, airCount, SLEEPY_B, 0x01) < airCount,
           "with B's frame addressed to B at its own number, found by its octets rather than by the slot it happened to take");
}

/* A completion that never arrives releases the attempt and leaves the transaction: 6.6.1, "If the
   transmission is indirect and the CSMA-CA algorithm fails, the frame shall remain in the transaction queue
   until it is requested again and successfully transmitted or until the transaction expires". Everything
   band A already does about a stuck backend still holds. */
void caseTimedOutExtractionReleasesItsAttempt(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Loopback_Outcome script[1];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    uint8_t transaction[2] = { 0xa1, 0x11 };
    uint8_t firstAttempt[RADIO_MPDU_MAX];
    uint32_t firstLen;
    uint32_t got;
    uint32_t i;
    uint32_t matches;
    Mac_Counters counters;

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_OK;
    script[0].isAcked = 1;
    script[0].pendingPumps = 1000;        /* an answer that is never going to arrive in time */

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 1);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, transaction, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "one transaction queued for A");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "extracted by A's poll");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame on the air");
    firstLen = sent[0].len;
    Zb_memcpy(firstAttempt, sent[0].bytes, firstLen);
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == 1, "and its attempt outstanding");

    for (i = 1; i < 1000; i += 137)
    {
        Test_ExpectStatus(Mac_Step(&dev.mac, 200 + i), ZB_OK, "stepping while the answer is awaited");
        Test_Expect(Mac_CountersOf(&dev.mac).transactionQueue == 1, "the transaction is not re-offered meanwhile (6.6.3.4)");
    }

    Test_ExpectStatus(Mac_Step(&dev.mac, 1200), ZB_OK, "and past the completion deadline");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.needsRearm == 1,
           "the rearm claim is unchanged by any of this: a completion that outlived the wait is still a backend its owner has to reset");
    Test_Expect(counters.transactionQueue == 1, "while the transaction stays queued (6.6.1)");
    Test_Expect(counters.transactionsExpired == 0,
           "and it stays for the reason 6.6.1 gives and not the one 10.22.2 gives: it is the attempt that was given up on, not the persistence limit that was reached");

    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_TIMEOUT && confirms[0].acked == 0,
           "the confirmation names the timeout rather than inventing a device fault, as an unanswered direct frame does");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "and collecting it does not remove the transaction either");

    injectPoll(&dev.model, 0x21, SLEEPY_A, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1300), ZB_OK, "A's next poll extracts it again: the timeout released the attempt, which is all it was allowed to release");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 2,
           "and the backend now shows two attempts of one transaction: the frame whose answer never came is still on its record, and the new Data Request put the other there");

    matches = 0;

    for (i = 0; i < got; i++)
    {
        if (sent[i].len == firstLen && Zb_memcmp(sent[i].bytes, firstAttempt, firstLen) == 0)
            matches++;
    }

    Test_Expect(matches == 2,
           "both of them byte for byte the same frame at the same DSN: a timed-out extraction is re-offered exactly as a refused one is, and 6.6.1 is the clause that says so");
}

/* 10.22.3's honest answer to a poll that finds nothing: a Data frame with a zero-length payload, asking for
   nothing. It is the NO_DATA band A can actually deliver, because the acknowledgment the poll itself gets is
   composed by the radio and no measured property lets this module write one. */
void caseEmptyPollAnswer(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame frame;
    Mac_DataRequestParameters req;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen;
    uint16_t fcf;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "a step with nothing queued and nothing delivered");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0,
           "composes nothing: an empty queue is not answered until somebody asks");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "the poll is stepped");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one answer");
    Test_Expect(sent[0].len == 11,
           "eleven octets: nine of compressed header, no Content at all, two of footer, 'a Data frame … containing a zero-length payload' (10.22.3)");

    fcf = fcfOf(&sent[0]);
    Test_Expect(fcf == AIR_BROADCAST_FCF,
           "and the FCF this PAN's captures record for an unacknowledged compressed data frame, 0x8841 (docs/internals/protocol.md §9.1)");
    Test_Expect((fcf & FCF_ACK_REQUEST_BIT) == 0,
           "'the coordinator shall send a Data frame without requesting acknowledgment' (10.22.3): there is no delivery to confirm");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) == 0,
           "Frame Pending zero (7.2.2.4: nothing follows it), which is the field that lets the child conclude 'no data are pending' (10.22.3)");
    Test_Expect((fcf & FCF_PAN_COMPRESSION_BIT) != 0, "one PAN field: the device being answered is a device of this PAN (7.2.2.6)");

    Test_Expect(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0) == ZB_OK,
           "and the answer parses as the frame it claims to be");
    Test_Expect(payloadOutLen == 0, "with a zero-length payload, 'indicating that no data are present' (10.22.3)");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_DATA && frame.destAddrMode == MAC_ADDR_SHORT
           && frame.srcAddrMode == MAC_ADDR_SHORT,
           "a Data frame with short addressing at both ends: the coordinator's source field is chosen by 10.22.4.1's own test, 'If macShortAddress is less than 0xfffe, short addressing shall be used'");
    Test_Expect(frame.destShort == SLEEPY_A && frame.srcShort == COORDINATOR_SHORT,
           "addressed to the device that polled, from this device's own PIB address");
    Test_Expect(frame.seq == 0x00 && frame.panIdCompression == 1, "and a fresh DSN: an empty answer is not a re-extraction of anything, so it takes the next number (7.2.3, against 6.6.3.4)");

    Test_Expect(sent[0].ackRequest == 0, "and the seam was told to ask for nothing, which is the same claim the FCF makes");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0, "no transaction appeared out of the answer");
    Test_Expect(counters.pollsUnanswered == 0,
           "and the poll was answered, not counted: an unanswered poll is one this module had nowhere to put an answer for");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 300, 0), ZB_OK, "a direct frame afterwards");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 2, "the backend holds both");
    Test_Expect(sent[1].bytes[2] == 0x01,
           "and the empty answer consumed a number like any other frame, because it is one (7.2.3)");
}

/*
 * A device's own Data Request handed back to it by its radio.
 *
 * An RCP was measured doing exactly that, and before this case existed band A did this with it: the frame names a source address (this device), a destination
 * (the peer) and command id 0x04, so `macPollFromDevice` read it as a poll and this module tried to answer its
 * own poll, while the transmit it belonged to was still outstanding. The empty answer was refused, the refusal
 * left `Mac_Step`, and the caller's loop ended before the completion it was waiting for was ever collected.
 *
 * A frame cannot arrive from the device that would have transmitted it, so the frame is consumed where it is
 * read: no indication, no poll arrival, no answer, and a completion that still arrives.
 */
/* Table 10-101: 0xffff is the address of a device that is on no PAN, and the table gives it a row for MAC
   commands only. A device holding it answers no poll with a Data frame, which is the frame 10.22.3 would ask for. */
void casePollAtAnUnassociatedDeviceIsNotAnswered(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, MAC_FRAME_ADDR_BROADCAST, MAC_FRAME_PAN_BROADCAST);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = MAC_FRAME_PAN_BROADCAST;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    frame.destShort = MAC_FRAME_ADDR_BROADCAST;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x50;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 1, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a poll addressed to the broadcast PAN and the broadcast address composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "and arrives at a device that holds 0xffff for both its addresses");

    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 0,
                     "no answer is composed: Table 10-101 has no Data row for 0xffff");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.pollsUnanswered, 1, "the poll is counted where its answer was missed");
}

/* 10.22.2: "On completion of the transaction, the MAC sublayer shall indicate a Status value to the next higher
   layer. If a request primitive instigated the indirect transmission, the corresponding confirm primitive shall be
   used to convey the appropriate Status value." 8.3.5's first parameter is the MsduHandle the caller named. */
void caseTransactionConfirmsItsOutcome(void)
{
    Test_BandA dev;
    Mac_DataRequestParameters req;
    Mac_DataConfirmParameters confirms[4];
    uint8_t queued[2] = { 0xa1, 0x11 };
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, queued, 2);
    req.msduHandle = 0x42;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "a transaction queued under the caller's handle");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "issued by the poll");
    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "and collected");

    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_ExpectCount(got, 1, "one confirmation, for the transaction and not for the poll that extracted it");
    Test_ExpectCount(confirms[0].msduHandle, 0x42, "under the handle the caller named (8.3.5)");
    Test_Expect(confirms[0].status == ZB_OK && confirms[0].acked == 1,
                "and SUCCESS, which 10.22.2 makes the acknowledgment's outcome");
    Test_ExpectCount(confirms[0].frameType, (int)MAC_FRAME_TYPE_DATA, "carrying the frame type that was queued");

    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 0,
                     "the transaction is discarded on success, as 10.22.2 states");

    /* 6.6.6: "If macTransactionPersistenceTime is reached, the transaction information will be discarded, and the
       MAC sublayer will issue a failure confirmation to the next higher layer". No poll comes. */
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, queued, 2);
    req.msduHandle = 0x43;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 1000), ZB_OK, "a second transaction, never extracted");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1000 + MAC_TRANSACTION_PERSISTENCE_MS), ZB_OK,
                      "a step at the persistence limit");

    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_ExpectCount(got, 1, "one confirmation for it");
    Test_ExpectCount(confirms[0].msduHandle, 0x43, "under its own handle");
    Test_Expect(confirms[0].status == ZB_ERR_TRANSACTION_EXPIRED && confirms[0].acked == 0,
                "with 8.2.2's TRANSACTION_EXPIRED, the failure 6.6.6 owes");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionsExpired, 1, "and the expiry counted where it happened");

    /* A frame this device composed for itself owes no confirmation: the poll's zero-length answer, and the beacon. */
    Test_ExpectCount(Mac_PollConfirms(&dev.mac, confirms, 4), 0, "and nothing else is owed");
}

/* Decision 146: 10.22.3's empty answer is given to a coordinator by the clause, and no clause says what a device
   that is not one does with a Data Request it receives, so the answer is not gated on that role. */
void casePollAnsweredWithoutAParentRole(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_BeaconConfig beacon;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 0;
    Test_ExpectStatus(Mac_SetBeaconConfig(&dev.mac, &beacon), ZB_OK, "the device is configured as nobody's parent");

    injectPoll(&dev.model, 0x30, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "a Data Request addressed to it arrives");

    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1,
                "and it is answered, with 10.22.3's zero-length frame");
    Test_Expect(sent[0].len == 11 && sent[0].ackRequest == 0,
                "eleven octets at this PAN's empty-answer shape, and the acknowledgment not asked");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollsUnanswered == 0 && counters.transactionQueue == 0,
                "counted as answered, not as a poll the pools refused");
}

void caseOwnDataRequestIsNotAnswered(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame frame;
    Mac_DataRequestParameters req;
    Mac_DataConfirmParameters confirm;
    Mac_PollArrival arrivals[2];
    Loopback_FrameSpec spec;
    const uint8_t *payloadOut;
    uint8_t payload = 0x04;
    uint32_t payloadOutLen;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "a step before anything is issued");

    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, MAC_ADDR_SHORT, 1);
    req.payload = &payload;
    req.payloadLen = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_OK,
                 "a Data Request to a sleepy device, which 10.22.4.1 composes with the acknowledgment request set");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame on the air");
    Test_Expect(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0) == ZB_OK,
           "which parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.srcShort == COORDINATOR_SHORT
                 && frame.destShort == SLEEPY_A && frame.seq == 0x00,
           "as this device's own Data Request: command frame, this device as source, the peer as destination");

    /* The radio hands exactly those octets back, as an RCP was measured doing. */
    spec.len = sent[0].len;
    spec.bytes = sent[0].bytes;
    spec.rssiDbm = -94;
    spec.lqi = 200;
    spec.stampTicks = 7000;
    spec.error = ZB_OK;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK, "and the radio hands them back");

    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK,
                 "the step takes it, and does not fail: the refusal of an answer must not end the turn");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.selfEchoes == 1, "the frame is counted as an echo of this device's own transmission");
    Test_ExpectCount(Mac_PollArrivals(&dev.mac, arrivals, 2), 0,
                     "no poll arrived: this device is not a device to itself");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.indicationQueue, 0,
                     "and nothing was handed up, because a frame cannot arrive from the device that sent it");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1,
           "and nothing was composed in answer: the one frame the backend holds is the one the request composed");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollsUnanswered == 0,
           "nothing is counted as an unanswered poll either, because no poll was seen");

    Test_Expect(Mac_PollConfirms(&dev.mac, &confirm, 1) == 1, "the completion of the real transmit is collected");
    Test_Expect(confirm.dsn == 0x00 && confirm.frameType == MAC_FRAME_TYPE_COMMAND,
           "for the Data Request that was issued, not for anything the echo provoked");
}

/* A poll this module cannot answer because it has nowhere to put the answer. The extraction needs a track
   slot, an answered slot is somebody else's confirmation until it is collected, and full is the refusal and
   the count every other pool here answers with (docs/internals/coding-rules.md §4.3). */
void casePollWithTrackPoolFull(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    uint8_t transaction[2] = { 0xa1, 0x11 };
    uint32_t got;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, transaction, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "A's first transaction");
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, transaction, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "and its second");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2, "two transactions held for A");

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, 0x3000, MAC_ADDR_SHORT, 1);
        Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 110 + i, 0), ZB_OK, "a direct transmit fills the track pool");
    }

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == MAC_TX_TRACK_MAX, "eight transmits outstanding, none of them confirmed yet");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "A's poll arrives, and the eight answers arrive in the same step");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.confirmQueue == MAC_TX_TRACK_MAX && counters.outstanding == 0,
           "the slots stay held: an answered slot is a confirmation waiting to be collected, and that is the pool an extraction has to wait for");
    Test_Expect(counters.pollsUnanswered == 1, "so the poll is counted as one this module could not answer");
    Test_Expect(counters.transactionQueue == 2, "and both transactions stay queued, because nothing was sent (6.6.3.4)");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == MAC_TX_TRACK_MAX, "the backend holds exactly the eight frames it was given, and no ninth");

    for (i = 0; i < got; i++)
    {
        if (sent[i].bytes[2] == 0x00)
            break;
    }

    Test_Expect(i == got,
           "and not one frame on the air carries DSN 0, the number A's first transaction reserved: the extraction was refused before it composed anything");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == 1, "the poll itself is still reported upward");
    Test_Expect(counters.pollsSkipped == 0,
           "and it is the other counter that moved: the step did ingest, so the miss is the track pool rather than the indication queue (the same rule one layer up)");
}

/* The pool no earlier case reached: the poll-event ring. `MAC_POLL_EVENT_MAX` is band A's own
   number (802.15.4-2024 has no poll notification at all and R23.1 D.10.2 names the event
   without capping it) and full answers refusal-and-count like every other pool here. Nine polls
   from nine devices, none of them holding a transaction: one batch delivers eight of them, the
   ring keeps those eight, and the ninth is refused as an event while its frame is still reported as
   an indication and still answered on the air. The eight are counted as unanswered because the track
   pool was held by uncollected confirmations, and a poll that cannot be answered is not a poll that
   may be answered with 10.22.3's zero-length payload: that frame states "no data are present", which
   is a claim about a device's queue and not one about this module's lack of room. */
void casePollArrivalRingFull(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Mac_PollArrival arrivals[MAC_POLL_EVENT_MAX + 1];
    Mac_DataIndicationParameters indications[MAC_INDICATION_QUEUE_MAX];
    Mac_DataConfirmParameters confirms[MAC_TX_TRACK_MAX];
    Mac_DataRequestParameters req;
    uint32_t answersOnAir;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, (uint16_t)(0x3000 + i), MAC_ADDR_SHORT, 1);
        Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100 + i, 0), ZB_OK, "a direct transmit fills the track pool");
    }

    for (i = 0; i < MAC_POLL_EVENT_MAX + 1; i++)
        injectPoll(&dev.model, (uint8_t)(0x20 + i), (uint16_t)(0x1000 + i), 5000 + i);

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.outstanding == MAC_TX_TRACK_MAX, "eight transmits outstanding, none confirmed");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == MAC_POLL_EVENT_MAX + 1, "and nine polls waiting at the backend");

    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "one step: the eight answers come in and a batch delivers eight of the nine polls");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.confirmQueue == MAC_TX_TRACK_MAX && counters.outstanding == 0,
           "the track slots stay held as confirmations nobody has collected, and that is the pool an answer needs");
    Test_Expect(counters.indicationQueue == MAC_POLL_EVENT_MAX, "eight polls ingested");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 1,
           "while the ninth is still at the backend: a step pulls one batch, not everything that is waiting (RADIO_FRAME_BATCH_MAX)");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == MAC_POLL_EVENT_MAX,
           "and the event ring is exactly full: as many arrivals as it is allowed to hold");
    Test_Expect(dev.mac.polls.dropped == 0, "with nothing refused yet, because nothing beyond the ring has arrived");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollsUnanswered == MAC_POLL_EVENT_MAX,
           "and all eight polls counted as unanswered: the track an answer needs was held by eight uncollected confirmations (docs/internals/coding-rules.md §4.3)");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == MAC_TX_TRACK_MAX, "the backend holds exactly the eight frames it was given");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == MAC_TX_TRACK_MAX, "and the ledger holds the same eight, copied before the ninth transmit can take a freed slot");

    answersOnAir = 0;

    for (i = 0; i < airCount; i++)
    {
        if (air[i].len == 11)
            answersOnAir++;
    }

    Test_Expect(answersOnAir == 0,
           "and not one of them is 10.22.3's zero-length answer: no frame on the air claims 'no data are present' to a device whose queue is empty only because this module had no room to answer it");

    got = Mac_PollIndications(&dev.mac, indications, MAC_INDICATION_QUEUE_MAX);
    Test_Expect(got == MAC_POLL_EVENT_MAX, "the layer above takes the eight frames, which is what makes room for one more batch");

    got = Mac_PollConfirms(&dev.mac, confirms, MAC_TX_TRACK_MAX);
    Test_Expect(got == MAC_TX_TRACK_MAX, "and it takes the eight confirmations, which is what frees the track");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 0 && counters.confirmQueue == 0 && counters.outstanding == 0,
           "both pools empty");
    Test_Expect(counters.pollArrivalQueue == MAC_POLL_EVENT_MAX,
           "while the event ring is still full: a pool the layer above has not drained is a pool it has to drain");

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the next step pulls the ninth poll");

    Test_Expect(dev.mac.polls.dropped == 1,
           "and its arrival is refused rather than displacing one of the eight: drop-newest, docs/internals/coding-rules.md §4.3");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == MAC_POLL_EVENT_MAX, "the ring still holds eight, and they are the eight older polls");
    Test_Expect(counters.indicationQueue == 1,
           "while the refused poll's own frame is still reported: an event this module could not queue is not a frame it may discard (docs/internals/coding-rules.md §5)");
    Test_Expect(counters.pollsUnanswered == MAC_POLL_EVENT_MAX,
           "and the unanswered count did not move, because this poll found a free slot and was answered");
    Test_Expect(counters.pollsSkipped == 0,
           "and no step ever declined to ask for a batch: the miss is the event ring and not the indication queue");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == MAC_TX_TRACK_MAX,
           "the backend's record is eight frames wide: the ninth transmit took a slot its collected answer had freed");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == MAC_TX_TRACK_MAX + 1,
           "while the ledger holds nine distinct frames: the eight direct transmits and the answer to the poll whose arrival was refused");

    i = airIndexOf(air, airCount, (uint16_t)(0x1000 + MAC_POLL_EVENT_MAX), 0x08);
    Test_Expect(i < airCount,
           "and the ninth poll (the one whose arrival was refused) was answered on the air anyway: a refused event is a reporting loss, not a denial of service to the device that asked");
    Test_Expect(air[i].len == 11 && airFcf(&air[i]) == AIR_BROADCAST_FCF,
           "10.22.3's zero-length unacknowledged Data frame, which is the honest answer to a device with nothing queued for it");
    Test_Expect((airFcf(&air[i]) & FCF_FRAME_PENDING_BIT) == 0,
           "Frame Pending zero, the bit that lets that device conclude there is nothing more for it (7.2.2.4)");
    Test_Expect(air[i].ackRequest == 0, "and the seam was told to ask for nothing, as the FCF says (10.22.3)");

    got = Mac_PollArrivals(&dev.mac, arrivals, MAC_POLL_EVENT_MAX + 1);
    Test_Expect(got == MAC_POLL_EVENT_MAX, "the eight arrivals pulled, oldest first");

    for (i = 0; i < got; i++)
    {
        Test_Expect(arrivals[i].shortAddress == (uint16_t)(0x1000 + i)
               && arrivals[i].dsn == (uint32_t)(0x20 + i)
               && arrivals[i].stampTicks == (uint64_t)(5000 + i),
               "each one the poll it was, source and DSN and stamp in the order they were injected (R23.1 D.10.2)");
    }

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == 0, "taken once, like every other queue here");
    Test_Expect(counters.transactionQueue == 0 && counters.refusedRequests == 0,
           "and none of it moved Mac_RefusedRequests: an arrival the ring could not hold and a poll the track could not answer are named by their own counters");
}

/* A command is a transaction too (10.22.2 names "a request from the MLME to send a MAC command instigated
   by a primitive from the next higher layer, such as the MLME-ASSOCIATE.response") and its pending bit is
   10.22.2's rule, not the Data Request command's pin. */
void caseCommandTransactionsStatePending(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Mac_DataConfirmParameters confirms[4];
    Mac_Frame frame;
    Mac_DataRequestParameters req;
    const uint8_t *payloadOut;
    uint8_t disassociation[2] = { 0x03, 0x02 };     /* 10.21.5.3 Disassociation Notification, Reason 0x02 */
    uint32_t payloadOutLen;
    uint16_t fcf;
    uint32_t airCount = 0;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0x1234, SLEEPY_A, disassociation, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK,
                 "a Disassociation Notification is queued as a transaction: 10.22.2 forms one from an MLME request to send a MAC command");
    req = indirectReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0x1234, SLEEPY_A, disassociation, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "and a second command behind it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2, "two command transactions for one device");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "and nothing on the air for either yet (10.22.2)");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "A's poll extracts the older one");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and the ledger holds it before its answer can reclaim the record");
    fcf = fcfOf(&sent[0]);
    Test_Expect(fcf == AIR_DELIVERED_COMMAND_FCF,
           "0x8873: a MAC command asking for an acknowledgment, with one PAN field and 10.22.2's pending bit");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) != 0,
           "Frame Pending one across two command transactions: 10.22.2's bit, 7.3.4 giving a command frame no pending rule of its own");
    Test_Expect((fcf & FCF_ACK_REQUEST_BIT) != 0,
           "AR one, which is both the command pin and the extraction's own ask (10.22.2)");
    Test_Expect((fcf & FCF_PAN_COMPRESSION_BIT) != 0, "one PAN field, the recipient being a device of this coordinator's PAN (7.2.4)");
    Test_Expect(sent[0].bytes[3] == 0xef && sent[0].bytes[4] == 0xbe,
           "and that field is this device's own 0xbeef and not the 0x1234 the request named: the pending bit is the half of the pin a command transaction may state, the Destination PAN is not (10.22.4.1)");
    Test_Expect(sent[0].bytes[2] == 0x00, "at the DSN the queueing reserved (6.6.3.4)");
    Test_Expect(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0) == ZB_OK
           && frame.frameType == MAC_FRAME_TYPE_COMMAND,
           "and it parses as the command frame the request named, not as the data frame an indirect request usually becomes");
    Test_Expect(sent[0].len == 13 && sent[0].bytes[9] == 0x03 && sent[0].bytes[10] == 0x02,
           "nine octets of header, the Command ID 0x03 and its Reason, two of footer (7.3.4.3, 7.3.4.4)");

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the answer to that extraction");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].acked == 1 && confirms[0].dsn == 0, "acknowledged, at its own number");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "the acknowledged transaction left and the other is still held (10.22.2)");

    injectPoll(&dev.model, 0x21, SLEEPY_A, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "A's next poll extracts the second");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1,
           "one record on the backend: the first extraction's answer was collected on the turn that reported it, and its slot is this frame's");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2,
           "while the ledger holds both extractions, which is the only place the pair still exists together");
    Test_Expect(airIndexOf(air, airCount, SLEEPY_A, 0x00) < airCount && airIndexOf(air, airCount, SLEEPY_A, 0x01) < airCount,
           "A's two command frames at the two numbers their queueing reserved, in A's own arrival order (10.22.2)");
    fcf = fcfOf(&sent[0]);
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) == 0,
           "Frame Pending zero on the last transaction for A (10.22.2, 7.2.2.4)");
    Test_Expect(fcf == AIR_POLL_FCF,
           "and the value is the same 0x8863 a poll carries: the Frame Control says nothing about which command the Content field holds");
    Test_Expect(sent[0].bytes[2] == 0x01, "at the second transaction's own reserved DSN, in arrival order (10.22.2)");
    Test_Expect(sent[0].len == 13 && sent[0].bytes[9] == 0x03 && sent[0].bytes[10] == 0x02,
           "nine octets of header, the Command ID 0x03 and its Reason, two of footer (7.3.4.3, 7.3.4.4)");

    Test_ExpectStatus(Mac_Step(&dev.mac, 230), ZB_OK, "its answer collected");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].acked == 1, "acknowledged");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0, "and the queue is empty again");
}

/* A Data Request that names no device. 10.22.4.1 pins a poll's Source Addressing Mode to macShortAddress,
   and the poll field those clauses allow to be omitted is the destination one (10.22.5.2: "the Data Request
   command may be generated without any destination address information present"). A command carrying 0x04
   with no Source Address field is still a frame a radio delivered, so band A reports it; what it cannot do
   is drive a queue keyed on a device it cannot name. */
void caseSourcelessPoll(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataIndicationParameters indications[4];
    uint8_t frame[RADIO_MPDU_MAX];
    uint32_t len;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    len = composePollWithoutSource(frame, 0x2b);
    Test_Expect(len == 10,
           "ten octets, the destination's PAN field and address and no source fields: 7.2.2.11's zero Source Addressing Mode on a version-0 command");

    injectFrame(&dev.model, frame, len, 8888);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "one step takes it");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 1,
           "and it stays an indication: a delivered frame is a fact the layers above may need, it is only not an arrival (docs/internals/coding-rules.md §5)");
    Test_Expect(counters.pollArrivalQueue == 0,
           "but it is not an arrival: R23.1 D.10.2 names a DeviceAddress, 'the address of the device requesting pending data', and this frame carries no source to read one from");
    Test_Expect(counters.pollsUnanswered == 0,
           "and it is not an unanswered poll either, because it never became a poll this module could answer at all");
    Test_Expect(counters.transactionQueue == 0, "nothing was queued for it");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0,
           "and nothing was composed for it: no extraction, and not even 10.22.3's honest zero-length answer, because there is no device to address it to");

    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].headerValid == 1, "the frame itself is reported, header parsed");
    Test_Expect(indications[0].header.frameType == MAC_FRAME_TYPE_COMMAND && indications[0].payloadLen == 1
           && indications[0].bytes[indications[0].payloadOffset] == MAC_CMD_POLL,
           "as the Data Request command it is, Table 7-11's 0x04 with its zero-length Content field (10.22.4.1)");
    Test_Expect(indications[0].header.srcAddrMode == MAC_ADDR_NONE
           && indications[0].header.destShort == COORDINATOR_SHORT,
           "with its source fields absent and its destination this coordinator, which is exactly the reading that makes it unanswerable");
    Test_Expect(indications[0].stampTicks == 8888 && indications[0].status == ZB_OK,
           "and its stamp and its clean footer intact: refusing to act on a frame is not a reason to report it as damaged");
}

/* 6.6.2 c) and d): a Data Request addressed to another coordinator is not this device's poll. Acting on it
   would put a frame on the air the asking device never asked this device for, and could clear a transaction
   on the strength of an acknowledgment from a device polling somebody else. */
void casePollForAnotherDeviceIsNotAnswered(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    Mac_Counters counters;
    static const uint8_t payload[2] = { 0xaa, 0xbb };
    uint8_t frame[64];
    uint32_t len;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, 0x1234, payload, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "a transaction is held for 0x1234");

    len = composePollTo(frame, 0x20, 0x1234, 0x9999);
    injectFrame(&dev.model, frame, len, 8888);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "a poll from 0x1234 addressed to 0x9999 arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.pollArrivalQueue == 0, "it is not this device's poll (6.6.2 c, d)");
    Test_Expect(counters.transactionQueue == 1, "and extracts nothing");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "nothing is composed or answered");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.commandsHeard == 0, "it is a poll and not a command this module consumed");
    Test_Expect(counters.destinationMismatches == 1 && counters.indicationQueue == 0,
                "6.6.2 d) refuses the frame where it is read: dropped and counted, not delivered as a frame this device heard");
}

/* 10.22.4.1: a Data Request's Content field is zero-length. A second octet is not part of a poll, and the
   receiver must not answer a frame the clause does not define. */
void caseDataRequestWithContent(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame frame;
    uint8_t bytes[64];
    uint8_t content[2] = { MAC_CMD_POLL, 0xaa };
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcShort = 0x1234;
    frame.seq = 0x2c;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a Data Request with a trailing octet composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 8888);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.commandsHeard == 1, "it is a command, not the zero-length poll 10.22.4.1 prints");
    Test_Expect(counters.pollArrivalQueue == 0, "no arrival");
    Test_Expect(counters.outstanding == 0, "and nothing outstanding");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "nothing was answered");
}

/*
 * 13. Table 3-80's two multicast classes that IEEE does not have.
 *
 * R23.1 3.2.1.1.3 item 6 sends a frame whose NWK destination is 0xFFFD or 0xFFFC to the MAC with `DstAddr`
 * 0xFFFF, so neither class ever reaches this layer in a destination field: the class is a NWK-header fact.
 * 802.15.4-2024 prints no 0xfffc and no 0xfffd of its own (6.2 defines one broadcast short address, 0xffff, and
 * Table 10-101 puts both inside "0x0000–0xfffd", the ordinary short addresses), so a request that does name one
 * names a device, and this module treats it as one in both places the broadcast answer used to reach: it is
 * queued rather than refused, and an acknowledgment asked of it is honoured.
 */
void caseClassAddressesAreUnicast(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, MAC_ZB_ADDR_ALL_RX_ON, payload,
                      (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK,
                 "a transaction for 0xfffd is held like any other device's: 6.2 defines one broadcast short address and it is 0xffff, so there is no reason here a queue cannot name 0xfffd");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, MAC_ZB_ADDR_ALL_ROUTERS, payload,
                      (uint32_t)sizeof payload);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 101), ZB_OK,
                 "and one for 0xfffc, which Table 10-101 prints in the same range of ordinary short addresses");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2,
           "both queued: the address that names many devices at the NWK layer names one at this one (R23.1 3.2.1.1.3 item 6 never lets it down here)");
    Test_Expect(counters.refusedRequests == 0, "and neither was refused a place in the queue");

    /* The ask, which is the other half of the broadcast answer: a destination this layer reads as one device
       can be asked for an acknowledgment, and the request is composed with the AR field set (7.2.2.5). */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, MAC_ZB_ADDR_ALL_RX_ON, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 110, 0), ZB_OK,
                 "an acknowledged data frame to 0xfffd is composed, not refused as an acknowledgment nobody could answer");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame on the air");
    Test_Expect((uint16_t)(sent[0].bytes[0] | (sent[0].bytes[1] << 8)) == AIR_UNICAST_FCF && sent[0].ackRequest == 1,
           "with the acknowledgment request on it: 0x8861 is the FCF this PAN's acknowledged unicasts carry (docs/internals/protocol.md §9.1)");
    Test_Expect((uint16_t)(sent[0].bytes[5] | (sent[0].bytes[6] << 8)) == MAC_ZB_ADDR_ALL_RX_ON,
           "and the destination on the air is the one the caller named, unchanged by any reading of it as a class");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and the suite's own log holds that one frame");
}

/*
 * A poll the radio will not take the answer to. The seam can refuse the transmit itself, a device still busy with
 * the frame the poll arrived behind refuses exactly that way, and what this module owes
 * such a refusal is a count and a step that goes on, not a status that becomes the verdict of the pass. The branch
 * exists because the abort it replaced cost a whole tool session its completion; before it, a refusal the device
 * would retract by itself ended a caller's loop.
 */
void casePollAnswerRefusedByTheRadio(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataIndicationParameters indications[4];
    Mac_PollArrival arrivals[4];
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    /* A device polls and the answer cannot be composed onto the link: the session still owes the request that
       carried the frame the poll arrived behind. */
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_BUSY, 1);

    injectPoll(&dev.model, 0x31, SLEEPY_A, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 700), ZB_OK,
                      "a busy radio does not fail the step: the refusal is one poll's, not the device's");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 0,
                     "nothing went on the air for it");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.pollsUnanswered, 1,
                     "and the poll is counted where it was missed, which is all this module may do with it");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 1, "the backend refused once, as scripted");

    /* The poll itself is still reported upward: an unanswered poll is a fact the layer above has to know. */
    Test_ExpectCount(Mac_PollArrivals(&dev.mac, arrivals, 4), 1, "the arrival reached the layer above");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 4), 1, "and so did its frame");

    /* The radio takes the next one, so the refusal was not terminal: the same device's next poll is answered. */
    injectPoll(&dev.model, 0x32, SLEEPY_A, 6100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 800), ZB_OK, "the next poll is stepped");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 1,
                     "and answered with 10.22.3's zero-length frame");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.pollsUnanswered, 1, "while the unanswered count stays where the refusal left it");
}

/* 10.22.3 asks the coordinator's acknowledgment to state whether a frame is waiting, and a radio that can put
   that on the air is told which addresses to state: the same list a beacon carries, written as the queue moves. */
void casePendingTableFollowsTheQueue(void)
{
    Test_BandA dev;
    Radio_Caps caps;
    Mac_DataRequestParameters req;
    uint8_t payload[1] = { 0xa1 };

    Test_BandACapsPendingTable(&caps);
    rigConfig(&dev, &caps, COORDINATOR_SHORT, PAN_ID, 0);

    Test_ExpectCount(LoopbackRadio_PendingWrites(&dev.model), 1,
                     "adoption states the empty table, because the radio's own default claims a frame is waiting for everyone (10.22.3)");
    Test_Expect(LoopbackRadio_PendingIsComplete(&dev.model) == 1
                && LoopbackRadio_PendingShortCount(&dev.model) == 0
                && LoopbackRadio_PendingExtendedCount(&dev.model) == 0,
                "and that statement is complete and empty: nothing is queued, so the acknowledgment says zero");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, payload, 1);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "one transaction queued for A");
    Test_ExpectCount(LoopbackRadio_PendingWrites(&dev.model), 2, "states the table again");
    Test_Expect(LoopbackRadio_PendingShortCount(&dev.model) == 1
                && LoopbackRadio_PendingShort(&dev.model, 0) == SLEEPY_A,
                "with the address the frame waits for, which is what 10.22.3's bit reports");
    Test_Expect(LoopbackRadio_PendingIsComplete(&dev.model) == 0,
                "but not as a complete answer: A never associated here, so its extended form is one this MAC cannot name");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, PAN_ID, 0, payload, 1);
    req.destExtended = 0x00124a000b2c0180;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "a second, for an extended address");
    Test_Expect(LoopbackRadio_PendingShortCount(&dev.model) == 1
                && LoopbackRadio_PendingExtendedCount(&dev.model) == 1,
                "and the list holds both forms, shorts and extended apart as 7.3.1.6 prints them");

    Test_ExpectStatus(Mac_Step(&dev.mac, 110 + MAC_TRANSACTION_PERSISTENCE_MS + 1), ZB_OK,
                      "a turn past macTransactionPersistenceTime");
    Test_Expect(LoopbackRadio_PendingShortCount(&dev.model) == 0
                && LoopbackRadio_PendingExtendedCount(&dev.model) == 0
                && LoopbackRadio_PendingIsComplete(&dev.model) == 1,
                "10.22.2's expiry is a move of the queue too: the table is stated empty, or the acknowledgment keeps saying a frame waits");
}



/* 10.22.2 makes the acknowledgment the proof of an extraction "if one was requested", so a frame that asks for
   none is extracted by the transmission the radio reports, and is discarded rather than offered again. */
void caseUnacknowledgedExtractionLeavesTheQueue(void)
{
    Test_BandA dev;
    Mac_DataRequestParameters req;
    Mac_DataConfirmParameters confirms[2];
    uint8_t payload[1] = { 0xb1 };
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, payload, 1);
    req.ackRequest = 0;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK,
                      "a transaction whose frame asks for no acknowledgment is queued");

    injectPoll(&dev.model, 0x30, SLEEPY_A, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "the device polls and the frame goes out");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "it is still held while its transmission is outstanding");

    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "the radio reports the transmission");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.transactionQueue, 0,
                     "and the transaction is discarded: no acknowledgment was asked, so none was owed (10.22.2)");
    Test_ExpectCount(Mac_PollConfirms(&dev.mac, confirms, 2), 1, "one confirmation, SUCCESS");
    Test_Expect(confirms[0].status == ZB_OK && confirms[0].acked == 0,
                "carrying the status and not an acknowledgment that was never requested");
}

/* An extraction asks for its acknowledgment and is still never retransmitted: a failed attempt leaves the
   transaction queued for the device's next poll (6.6.3.4), so the radio is given no retries for it. */
void caseExtractionIsNotRetransmitted(void)
{
    Test_BandA dev;
    Loopback_Sent sent[2];
    Mac_DataRequestParameters req;
    uint8_t content[1] = { 0xc1 };

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, content, 1);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "a transaction for a sleeping device");

    injectPoll(&dev.model, 0x30, SLEEPY_A, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "the device polls and the frame goes out");

    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, 2), 1, "one extraction");
    Test_Expect(sent[0].ackRequest == 1, "asking for its acknowledgment");
    Test_ExpectCount(sent[0].maxFrameRetries, 0, "with no retransmission budget");
}
