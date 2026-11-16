/* The `mac` suite's confirmations: what came back from a transmit and how
   it is reported rather than interpreted, the acknowledgment that arrived and the one that never does, the
   attempt a device that keeps polling leaves outstanding, and the track pool those attempts are held in. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

void caseConfirmations(void)
{
    Test_BandA dev;
    Radio_Caps silent;
    Loopback_Outcome script[2];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    Radio_Handle issued;
    Mac_Counters counters;
    uint32_t got;

    Test_BandACapsNoAcks(&silent);

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_OK;
    script[0].isAcked = 1;
    script[1].status = ZB_ERR_DEVICE;      /* what NO_ACK (17) becomes at the seam */
    script[1].isAcked = 0;
    script[1].retries = 2;

    rig(&dev, 0xdead, 0xbeef);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 2);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    issued = RADIO_HANDLE_NONE;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, &issued), ZB_OK, "the acknowledged transmit");
    Test_Expect(issued != RADIO_HANDLE_NONE && issued == dev.mac.tx.track[0].handle,
           "and the request answers with the handle of the track slot its frame took, which is the fact the layer above needs and could only reach by reading that slot");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.outstanding == 1, "outstanding until the backend answers");

    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "a step");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.outstanding == 0 && counters.confirmQueue == 1, "answered, confirmation waiting");

    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].acked == 1,
           "and a radio that runs the acknowledgment wait reports the acknowledgment it got");
    Test_Expect(confirms[0].dsn == 0 && confirms[0].handle != RADIO_HANDLE_NONE,
           "the confirmation carries the DSN and handle of the frame it belongs to, which is how nwk matches it");
    Test_Expect(confirms[0].handle == issued,
           "and the handle is the one the request handed back: the two ends of one transmit named by the same number, with no reading of band A's pools needed to tie them (7.2.3, docs/internals/protocol.md §8.3)");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.confirmQueue == 0, "collected once");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x9999, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_OK,
                  "the transmit that was not answered, asked with a caller that does not want the handle at all");
    Test_ExpectStatus(Mac_Step(&dev.mac, 201), ZB_OK, "stepped");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE && confirms[0].acked == 0,
           "its confirmation is the refusal, which is what R23.1 3.6.4.3 wants nwk to retry against");
    Test_Expect(confirms[0].numBackoffs == 2,
           "and the backoff count the backend reported, whatever it is on a device that reports none");
    Test_Expect(confirms[0].dsn == 1, "with its own DSN");

    /* A radio that does not run the wait cannot report an acknowledgment, so a completion that says the
       frame was accepted says nothing about one. */
    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_OK;
    script[0].isAcked = 1;

    rigConfig(&dev, &silent, 0xdead, 0xbeef, 0);
    Test_Expect(Mac_Caps(&dev.mac)->handlesAckTimeout == 0, "a backend that claims no acknowledgment handling");
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 300, 0), ZB_OK, "a transmit");
    Test_ExpectStatus(Mac_Step(&dev.mac, 301), ZB_OK, "answered");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].acked == 0,
           "and the confirmation reports success without claiming an acknowledgment");
}

/* 10.22.3's answer to a Data Request is the Frame Pending bit of its acknowledgment: carried into the confirmation
   when the radio reports it, and never read into a completion that did not. */
void caseConfirmCarriesTheAcksFramePending(void)
{
    Test_BandA dev;
    Loopback_Outcome script[3];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    uint32_t got;

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_OK;
    script[0].isAcked = 1;
    script[0].framePendingReported = 1;
    script[0].framePending = 1;
    script[1].status = ZB_OK;
    script[1].isAcked = 1;
    script[1].framePending = 1;
    script[2].status = ZB_ERR_NO_ACK;
    script[2].framePendingReported = 1;
    script[2].framePending = 1;

    rig(&dev, 0xdead, 0xbeef);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 3);
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK, "an acknowledged transmit whose Ack said pending");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "stepped");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].acked == 1 && confirms[0].framePending == 1,
           "the confirmation carries the bit the radio reported");

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_OK, "one whose completion reported no bit");
    Test_ExpectStatus(Mac_Step(&dev.mac, 201), ZB_OK, "stepped");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].acked == 1 && confirms[0].framePending == 0,
           "reads no pending into a completion that did not state one");

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 300, 0), ZB_OK, "and one that was never acknowledged");
    Test_ExpectStatus(Mac_Step(&dev.mac, 301), ZB_OK, "stepped");
    got = Mac_PollConfirms(&dev.mac, confirms, 4);
    Test_Expect(got == 1 && confirms[0].acked == 0 && confirms[0].framePending == 0,
           "has no acknowledgment whose bit it could carry");
}

void caseCompletionThatNeverArrives(void)
{
    Test_BandA dev;
    Loopback_Outcome script[1];
    Mac_DataConfirmParameters confirms[2];
    Mac_DataRequestParameters req;
    Mac_Counters counters;
    uint32_t got;
    uint32_t i;

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_OK;
    script[0].isAcked = 1;
    script[0].pendingPumps = 100;         /* an answer that is never going to come in time */

    rig(&dev, 0xdead, 0xbeef);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 1);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK, "a transmit issued at time 0");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.needsRearm == 0, "nothing to report yet");

    for (i = 1; i < 1000; i += 137)
    {
        Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, i), ZB_OK, "pumping the backend");
        Test_ExpectStatus(Mac_Step(&dev.mac, i), ZB_OK, "and stepping band A");

        counters = Mac_CountersOf(&dev.mac);

        Test_Expect(counters.outstanding == 1 && counters.confirmQueue == 0, "still waiting");
    }

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.needsRearm == 0, "and it has not yet given up on it");

    Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, 1000), ZB_OK, "the pump at the deadline");
    Test_ExpectStatus(Mac_Step(&dev.mac, 1001), ZB_OK, "and the step past it");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.needsRearm == 1,
           "a completion that outlived the wait means the radio is stuck or the RCP reset, and band A cannot reset a backend it cannot see");

    got = Mac_PollConfirms(&dev.mac, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_TIMEOUT && confirms[0].acked == 0,
           "the confirmation names the timeout rather than inventing a device fault");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.outstanding == 0, "and the transmit stops being outstanding");
}

void caseTrackPool(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Mac_DataConfirmParameters confirms[MAC_TX_TRACK_MAX];
    Mac_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, 0xdead, 0xbeef);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
        Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100 + i, 0), ZB_OK, "a transmit fills a slot");

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_ERR_NO_SPACE,
                 "the ninth unanswered transmit is named, not dropped, and no frame was composed for it");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == MAC_TX_TRACK_MAX,
           "the backend saw exactly the transmits band A tracked");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == MAC_TX_TRACK_MAX,
           "the eight frames the backend was given, copied into the suite's ledger while every one of their handles was still live");

    got = Mac_PollConfirms(&dev.mac, confirms, MAC_TX_TRACK_MAX);
    Test_Expect(got == 0, "nothing to confirm yet: the answers are still outstanding");
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "a step answers them all");
    got = Mac_PollConfirms(&dev.mac, confirms, MAC_TX_TRACK_MAX);
    Test_Expect(got == MAC_TX_TRACK_MAX, "and every confirmation is collectable");

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
        Test_Expect(confirms[i].dsn == i, "each carrying the DSN of its own frame, oldest first");

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 400, 0), ZB_OK, "the pool is usable again once confirmations are taken");

    /* The refused request consumed no DSN, so the frame after eight is numbered 8. Searched in the ledger
       rather than in the backend: the step that collected the eight answers freed every slot, and the frame
       this request composed is the only one the backend still holds. */
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == MAC_TX_TRACK_MAX,
           "the backend still shows eight records: the ninth transmit took a slot its collected answer had freed");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == MAC_TX_TRACK_MAX + 1,
           "while the ledger holds nine distinct frames: the eight the reuse covered over and the one the freed pool bought");

    i = airIndexOf(air, airCount, 0x1234, 0x08);
    Test_Expect(i < airCount && air[i].len == 19,
           "and DSN 8 is on the wire at the length the other eight had, which is the number a refused request would have wasted");
}

/* One extraction per transaction, and no answer that contradicts the queue. A device that polls while what
   it holds is already on the air gets neither a duplicate frame nor a zero-length claim that nothing is
   pending: the data are pending, and 6.6.3.4 forbids a second frame for an attempt that has not been
   answered. */
void caseAttemptOutstanding(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Loopback_Outcome script[2];
    Mac_DataRequestParameters req;
    uint8_t first[2] = { 0xa1, 0x11 };
    uint8_t second[2] = { 0xa2, 0x12 };
    uint16_t fcf;
    Mac_Counters counters;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    Zb_memset(script, 0, (uint32_t)sizeof script);

    for (i = 0; i < 2; i++)
    {
        script[i].status = ZB_OK;
        script[i].isAcked = 1;
        script[i].pendingPumps = 100;     /* both answers stay in the air for the whole case */
    }

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    LoopbackRadio_ScriptOutcomes(&dev.model, script, 2);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, first, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "A's first transaction");
    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, second, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "and its second");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "A polls, and the older transaction goes out");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame");
    Test_Expect(sent[0].bytes[2] == 0x00, "at the first transaction's reserved DSN");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.outstanding == 1, "and its acknowledgment has not come");

    harvestAir(&dev.model, air, &airCount);

    /* 10.22.2 sends a device's transactions "in the order in which they arrived", and 6.6.3.4 forbids retransmitting
       an indirect frame, so a poll that arrives while the first attempt is still in the air can be answered with
       neither: the later transaction waits its turn rather than overtaking the one before it. */
    injectPoll(&dev.model, 0x21, SLEEPY_A, 5100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "A polls again while that attempt is still in the air");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "and nothing new goes out: the second transaction is held behind the first");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame in the ledger, the first transaction's");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pollsUnanswered == 1, "the held poll is counted unanswered, which is all band A may do with it");
    Test_Expect(counters.transactionQueue == 2, "both transactions are still queued: neither has been acknowledged (10.22.2)");
    fcf = fcfOf(&sent[0]);
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) != 0,
           "Frame Pending one on the frame that did go out: 10.22.2 states that another transaction follows it");

    injectPoll(&dev.model, 0x22, SLEEPY_A, 5200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "a third poll, with every transaction held for A mid-attempt");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "puts no new frame on the air: 6.6.3.4 forbids retransmitting an attempt that has not been answered, and the transaction behind it is held");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.outstanding == 1,
           "and the one attempt this case started is still the only one band A holds, which is the claim a backend record count cannot make on its own");
    Test_Expect(counters.pollsUnanswered == 2, "and each poll it could not answer is counted, which is all band A may do with it");
    Test_Expect(counters.transactionQueue == 2, "the queue is untouched");
    Test_Expect(counters.pollArrivalQueue == 3,
           "while all three polls were still reported upward: an unanswered poll is still a poll the layer above has to know about (R23.1 D.10.2)");

    for (i = 0; i < airCount; i++)
        Test_Expect(air[i].len != 11, "and neither frame is 10.22.3's zero-length answer: 'no data are present' is a statement this queue knows to be false");
}
