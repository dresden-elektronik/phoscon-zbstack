/* The `mac` suite's lost backend: a device that went away and came back, and
   the PIB this module re-pushes field for field when it does, the one act band A owes a backend it did not
   reset itself. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * Whether a backend holds every field a mirror claims. Asked as one question because a re-push that landed
 * half of a PIB would leave exactly the state band A is not allowed to be in: a mirror the module believes
 * and a radio that does not hold it. `ackWaitMs` is compared too, so a field this stack can name but no
 * measured RCP can carry cannot drift into a mirror and out of a backend unnoticed: a mirror only ever
 * gains the bits a backend accepted, which is why the lost-handling case never puts it in one.
 */
int backendHoldsMirror(const Radio_Pib *backend, const Radio_Pib *mirror)
{
    if (backend->channel != mirror->channel)
        return 0;

    if (backend->page != mirror->page)
        return 0;

    if (backend->panId != mirror->panId)
        return 0;

    if (backend->shortAddress != mirror->shortAddress)
        return 0;

    if (backend->rxOnWhenIdle != mirror->rxOnWhenIdle)
        return 0;

    if (backend->maxCsmaBackoffs != mirror->maxCsmaBackoffs)
        return 0;

    if (backend->maxFrameRetries != mirror->maxFrameRetries)
        return 0;

    if (backend->ackWaitMs != mirror->ackWaitMs)
        return 0;

    if (backend->ccaThresholdDbm != mirror->ccaThresholdDbm)
        return 0;

    return Zb_memcmp(backend->extendedAddress, mirror->extendedAddress, RADIO_ADDR_LEN) == 0;
}

/*
 * The half of a lost event band A is forbidden to perform, scripted by the suite instead: the device coming
 * back holding nothing it was told to hold. The model does not do this by itself (`LoopbackRadio_SetLost`
 * flushes outstanding transmits and touches no PIB, because band B's `lost` is a link fact) and the RCPs
 * this stack is built against do exactly it: the sweep in docs/internals/protocol.md §7.2, taken after a plain reset,
 * records `PHY_CHAN` and `MAC_RX_ON_WHEN_IDLE` as `0`, and §6 arms an RCP by writing them again. Clearing
 * band B's own PIB is the suite standing in for the owner of the backend; band A reaches the same state
 * only through `ops`, and only to write it back.
 *
 * The one field a reset does not lose is scripted back in: the factory address is what the part is, not what it
 * was told, and the sweep that reads it again is band B's bring-up. Leaving it there is what lets this row ask
 * the question that matters: whether band A asks for it back.
 */
void scriptResetPib(Loopback_Radio *model)
{
    uint8_t octets[RADIO_ADDR_LEN];

    Zb_memcpy(octets, model->pib.hwAddress, RADIO_ADDR_LEN);

    Zb_memset(&model->pib, 0, (uint32_t)sizeof model->pib);

    LoopbackRadio_SetFactoryAddress(model, octets);
}

/* The factory identity the model is scripted with: the ConBee II's own EUI-64 as docs/internals/protocol.md §7.2 read it
   off the RCP, laid into the PIB's octet order, which is the order `pibGet` hands it and the reverse of the
   order the wire carries it in. */
static const uint8_t factoryAddress[RADIO_ADDR_LEN] =
{
    0x12, 0x8a, 0x04, 0xff, 0xff, 0x2e, 0x21, 0x00
};

/* The device this row stands on: the model scripted with a factory identity before band A adopts it, then the MAC
   on its seam and, when the caller asks, the identity the shared rig gives its devices. The rig inits the backend
   and adopts it in one go, so it cannot take this script; the row builds those two stages and uses no network. */
void rigFactoryDevice(Test_BandA *dev, uint16_t shortAddress, uint16_t panId, int applyIdentity)
{
    Radio_Caps caps;
    Radio_Pib pib;

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(&dev->model, &caps);
    LoopbackRadio_SetFactoryAddress(&dev->model, factoryAddress);

    Test_ExpectStatus(Mac_Init(&dev->mac, LoopbackRadio_Seam(&dev->model), 0), ZB_OK,
                  "band A adopts a backend that says what it holds, the address it was built with included");

    if (!applyIdentity)
        return;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    pib.shortAddress = shortAddress;
    pib.panId = panId;
    pib.channel = 26;
    pib.rxOnWhenIdle = 1;

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK,
                  "and it is addressed as every band-A rig addresses its device, through the seam like any other write");
}

/* How many of the PIB requests the backend kept name one of these fields. The re-application is judged from the
   records the seam was handed rather than from what band A says it meant: a field band A asked for is a fact only
   where the backend has a record of being asked. */
uint32_t recordsNaming(const Radio_Pib *writes, uint32_t count, uint32_t fields)
{
    uint32_t index;
    uint32_t hits = 0;

    for (index = 0; index < count; index++)
    {
        if ((writes[index].present & fields) != 0)
            hits++;
    }

    return hits;
}

/*
 * A backend that went away and came back, which no earlier case reached. Band A asks the seam whether its device is there at the top of every step, and it
 * marks what it saw and stops for as long as the device is away: no collecting, ingesting, extracting,
 * answering or counting, and above all no attempt at the reset, because a backend's own step is not band A's
 * to call and this module does not know which backend it has. What it does owe itself is what it applied. A
 * device that came back from its own defaults does not hold the PIB band A believes it holds, and the only
 * way to find out which values it still takes is the same `Mac_SetPib` call the layer above would have made:
 * the per-field path, with its refusal semantics intact, over the mask band A asked for and not over the
 * report it adopted.
 *
 * The scripted part: `LoopbackRadio_SetLost` is a link fact and not a PIB fact (it flushes outstanding
 * transmits and touches no PIB), so `scriptResetPib` stands in for the owner's half of the event, the
 * re-arming, which is exactly the act band A is forbidden to perform. What band A does afterwards is
 * observable through the seam: the model keeps every pibSet it was handed, the declined ones included, so the
 * mask and the values handed down are read out of those records, the fields band A re-pushed are the fields a
 * later `pibGet` answers, and `LoopbackRadio_Refusals` is the record that a write really reached it. The model
 * keeps no counter of its own for a call it refused because the device was gone, so "band A did not write into
 * a closed seam" is asserted from band A's own state rather than from a receipt band B does not keep.
 *
 * The model is scripted with an RCP's factory address, because both measured builds answer one and a model
 * that hides it hides exactly the fact that makes this row worth having: an adopted report band A cannot put
 * back onto the device.
 */
void caseLostReapplication(void)
{
    Test_BandA dev;
    Radio_Radio *seam;
    Radio_Pib pib;
    Radio_Pib backend;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Air air[AIR_LOG_MAX];
    Mac_PollArrival arrivals[2];
    const Radio_Pib *mirror;
    Mac_Counters counters;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;
    uint32_t kept;

    rigFactoryDevice(&dev, COORDINATOR_SHORT, PAN_ID, 1);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                  | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE
                  | RADIO_PIB_MAX_CSMA_BACKOFFS | RADIO_PIB_MAX_FRAME_RETRIES
                  | RADIO_PIB_CCA_THRESHOLD_DBM;
    pib.channel = 15;
    pib.panId = PAN_ID;
    pib.shortAddress = COORDINATOR_SHORT;
    pib.extendedAddress[0] = 0x11;
    pib.extendedAddress[1] = 0x22;
    pib.extendedAddress[2] = 0x33;
    pib.extendedAddress[3] = 0x44;
    pib.extendedAddress[4] = 0x55;
    pib.extendedAddress[5] = 0x66;
    pib.extendedAddress[6] = 0x77;
    pib.extendedAddress[7] = 0x88;
    pib.rxOnWhenIdle = 1;
    pib.maxCsmaBackoffs = 4;
    pib.maxFrameRetries = 2;
    pib.ccaThresholdDbm = -85;

    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_OK,
                  "a PIB of values the backend was told, not defaults it was never given: RADIO_PIB_ACK_WAIT_MS alone stays out of the mirror");

    seam = LoopbackRadio_Seam(&dev.model);
    mirror = Mac_Pib(&dev.mac);

    Test_Expect((mirror->present & RADIO_PIB_HW_ADDRESS) != 0,
           "the mirror carries the factory address the model reported the way an RCP's backend reports it: the field band A adopts, reads and is never allowed to write back");
    Test_ExpectHex("read as the device's own eight octets, in the PIB's order, which is the reverse of the order the wire carries them in (docs/internals/protocol.md §7.2)",
                   mirror->hwAddress, RADIO_ADDR_LEN, "128a04ffff2e2100");
    Test_Expect(dev.mac.applied.present == pib.present
                && dev.mac.applied.channel == 15 && dev.mac.applied.panId == PAN_ID
                && dev.mac.applied.maxCsmaBackoffs == 4 && dev.mac.applied.maxFrameRetries == 2
                && dev.mac.applied.ccaThresholdDbm == -85
                && Zb_memcmp(dev.mac.applied.extendedAddress, pib.extendedAddress, RADIO_ADDR_LEN) == 0,
           "while band A's own record of what it applied holds the mask this case wrote with the values it wrote with it: eight fields, and not the ninth the device merely reported");

    Test_ExpectStatus(seam->ops->pibGet(seam, &backend), ZB_OK, "and before anything goes wrong, the backend answers a read of what it was told");
    Test_Expect(backend.channel == 15 && backendHoldsMirror(&backend, mirror),
           "field for field: channel 15 rather than the 0 an RCP that has never been armed answers (docs/internals/protocol.md §7.2)");

    LoopbackRadio_SetLost(&dev.model, 1);
    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);

    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK,
                  "a step against a backend the seam says is gone answers ZB_OK: it reports the state it reached and does nothing else");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.needsRearm == 1,
           "a device that is not there is a device its owner has to re-arm, and naming that is the whole of what band A is allowed to do about it");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 1,
           "the poll in front of it is still at the backend: band A did not ask for it, because a queue it was told is closed is not a queue it may drain");
    Test_Expect(counters.indicationQueue == 0 && counters.pollArrivalQueue == 0,
           "nothing ingested, so nothing handed up and no arrival reported: R23.1 D.10.2's event is a poll this module actually saw, and it saw none");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0,
           "nothing extracted and nothing composed: a poll answered to a radio that cannot send the answer is a frame that never arrives");
    Test_Expect(counters.pollsUnanswered == 0 && counters.pollsSkipped == 0,
           "and neither pool counter moved, because a step that took nothing missed nothing");
    Test_Expect(dev.mac.lostEpisode == 1 && dev.mac.reapplyPending == 1,
           "the episode and the debt it leaves are both recorded on the way out, so a module that only noticed the recovery could not have known there was anything to re-push");
    Test_Expect(counters.pibReapplications == 0,
           "and no mirror was re-pushed into a closed seam: pibSet while the device is gone answers ZB_ERR_NOT_OPEN, and band A does not try it");

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "a second lost turn, the same shape");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(LoopbackRadio_Queued(&dev.model) == 1 && counters.pibReapplications == 0,
           "the device still holds its frames and band A still has not touched it: an episode is not a reason to poll a closed seam");

    scriptResetPib(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);

    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "the turn the backend answers again");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 1,
           "one re-push, counted, before the completions were collected: every frame below is composed from this PIB");
    Test_Expect(dev.mac.lostEpisode == 0 && dev.mac.reapplyPending == 0,
           "the episode is closed as a fact about what band A last saw, and the debt is discharged because the backend took the write");
    Test_Expect(counters.needsRearm == 1,
           "while the rearm claim stays exactly where the episode put it: nothing in band A clears a claim only the owner of the backend can answer");
    Test_ExpectStatus(seam->ops->pibGet(seam, &backend), ZB_OK, "and the backend answers a read of its PIB again");
    Test_Expect(backend.channel == 15 && backendHoldsMirror(&backend, mirror),
           "every field the mirror names is a field the device holds once more: the reset left it holding none of them");
    Test_Expect(mirror->channel == 15 && mirror->ccaThresholdDbm == -85 && mirror->maxFrameRetries == 2,
           "and the mirror itself is unchanged by the round trip: a re-push is a write to the backend, not a re-adoption of whatever the backend answers (Mac_SetPib)");

    /* Read from the backend's own records, because the claim is about what band A handed down and not about what
       it believes it meant: one call, the mask it named, and the values it named with it. */
    kept = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(kept, 3, "three PIB requests reached the backend: the rig's identity, this case's eight fields, and the one the recovery turn handed down");

    if (kept == 3)
    {
        Test_Expect(writes[2].present == pib.present,
               "and the re-application named exactly the mask band A applied: eight fields, nothing adopted from the device added to it and nothing dropped from it");
        Test_Expect(writes[2].channel == 15 && writes[2].panId == PAN_ID
                    && writes[2].shortAddress == COORDINATOR_SHORT && writes[2].rxOnWhenIdle == 1
                    && writes[2].maxCsmaBackoffs == 4 && writes[2].maxFrameRetries == 2
                    && writes[2].ccaThresholdDbm == -85
                    && Zb_memcmp(writes[2].extendedAddress, pib.extendedAddress, RADIO_ADDR_LEN) == 0,
               "with the values band A asked for, field for field, and not the defaults the reset left the device holding");
    }

    Test_ExpectCount(recordsNaming(writes, kept, RADIO_PIB_HW_ADDRESS), 0,
           "and a factory address was never requested: not one request this seam was handed named the device's own field");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "the poll the backend had been holding was pulled on that same turn, and answered");
    i = sentIndexFor(sent, got, SLEEPY_A, 0x00);
    Test_Expect(i < got, "with the DSN a fresh frame takes (7.2.3) addressed to the device that asked");
    Test_Expect(sent[i].len == 11 && fcfOf(&sent[i]) == AIR_BROADCAST_FCF,
           "10.22.3's zero-length unacknowledged Data frame, which is what an empty queue is answered with");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and the ledger holds that answer, copied before the next turn collects it");

    got = Mac_PollArrivals(&dev.mac, arrivals, 2);
    Test_Expect(got == 1 && arrivals[0].shortAddress == SLEEPY_A && arrivals[0].dsn == 0x20,
           "and the arrival is reported as it was seen, with the DSN and stamp of the frame it was");

    injectPoll(&dev.model, 0x21, SLEEPY_B, 5100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 230), ZB_OK, "a poll that arrives after the reapplication");
    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1,
           "answered like any other poll: one record on the backend, because the earlier answer's record was collected on the way in and its slot is this frame's now");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2,
           "while the ledger holds both empty answers: two frames, two DSNs, one of them no longer visible at the backend");
    i = airIndexOf(air, airCount, SLEEPY_B, 0x01);
    Test_Expect(i < airCount && air[i].len == 11 && air[i].ackRequest == 0,
           "at its own DSN (a fresh number for a fresh frame (7.2.3)) with the same honest empty answer and no acknowledgment asked (10.22.3)");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 1,
           "while the counter did not move on a turn that found no episode: it counts re-pushes, not steps");

    LoopbackRadio_SetLost(&dev.model, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "gone again, and the same shape again");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 1, "a second episode counts nothing until its own mirror lands");

    scriptResetPib(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);
    Test_ExpectStatus(Mac_Step(&dev.mac, 310), ZB_OK, "and back a second time");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 2, "one re-push counted for it: one per episode, not one per turn");
    Test_ExpectStatus(seam->ops->pibGet(seam, &backend), ZB_OK, "read back");
    Test_Expect(backend.channel == 15 && backendHoldsMirror(&backend, mirror),
           "and the whole mirror is on the device again, eight fields it had forgotten");

    LoopbackRadio_SetLost(&dev.model, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 400), ZB_OK, "a third episode, this one scripted to refuse the write");
    scriptResetPib(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);
    LoopbackRadio_RefusePib(&dev.model, RADIO_PIB_PAN_ID);

    Test_ExpectStatus(Mac_Step(&dev.mac, 410), ZB_OK,
                  "the recovery turn where the backend refuses the re-push: the step still reports its own work, and a refusal the backend named is not re-labelled as a device fault band A invented (Mac_SetPib)");
    Test_Expect(LoopbackRadio_Refusals(&dev.model) == 1,
           "one pibSet reached the backend and one refusal was recorded: proof the re-push is a real write through the seam and not a private edit of the mirror");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 2,
           "and a re-push the backend refused counts as nothing, because the number moves only for a re-push it accepted");
    Test_Expect(dev.mac.reapplyPending == 1, "the debt stays: the next turn tries again");
    Test_Expect(dev.mac.lostEpisode == 0, "while the episode itself closed the moment the backend answered");

    kept = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(kept, 5, "and the refused re-push is in the backend's record beside the ones that landed: a call the seam was handed was still a call");
    Test_ExpectStatus(seam->ops->pibGet(seam, &backend), ZB_OK, "and the device still answers a read");
    Test_Expect(backend.channel == 0 && backend.panId == 0 && backend.rxOnWhenIdle == 0,
           "holding the defaults the reset left it with: a refused re-push stored nothing, which is the same all-or-nothing rule Mac_SetPib applies to a mirror");
    Test_Expect(counters.needsRearm == 1,
           "and the rearm claim is untouched either way: a backend that refuses the write is still a backend its owner has to re-arm");

    Test_ExpectStatus(Mac_Step(&dev.mac, 420), ZB_OK, "the next turn tries again");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.pibReapplications == 3, "and this time it lands: three episodes, three counted re-pushes");
    Test_Expect(dev.mac.reapplyPending == 0, "and the debt is discharged, so no turn after it re-pushes anything");
    Test_ExpectStatus(seam->ops->pibGet(seam, &backend), ZB_OK, "read back one last time");
    Test_Expect(backend.channel == 15 && backendHoldsMirror(&backend, mirror),
           "with the mirror back on the device field for field, which is the only state band A is allowed to compose frames from");

    kept = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(kept, 6, "six PIB requests in all: the two band A applied before any episode and one per recovery turn, the declined one included");
    Test_ExpectCount(recordsNaming(writes, kept, RADIO_PIB_HW_ADDRESS | RADIO_PIB_ACK_WAIT_MS), 0,
           "and not one of them named the device's own address or a field no backend of this seam accepts: the mask band A re-applies is the one it wrote and not the one it read");
}

/* A band A that adopted a backend and wrote nothing to it. The report it adopted names a field both backends
   refuse as a write, so a recovery built out of that report would owe a write it could never land; band A applied
   nothing, so it owes nothing: the episode is marked, the rearm claim stands, no request reaches the seam. */
void caseLostWithNothingApplied(void)
{
    Test_BandA dev;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    Loopback_Sent sent[1];
    const Radio_Pib *mirror;
    Mac_Counters counters;
    uint32_t got;

    rigFactoryDevice(&dev, COORDINATOR_SHORT, PAN_ID, 0);

    mirror = Mac_Pib(&dev.mac);

    Test_ExpectCount(mirror->present, RADIO_PIB_HW_ADDRESS,
           "a device nobody configured reports its own identity and nothing else, which is the whole of what band A adopted from it");
    Test_ExpectCount(dev.mac.applied.present, 0,
           "and band A's own record of what it applied is empty: adoption is a read, and a read owes nothing");
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX), 0,
           "and band A handed that backend no PIB request at all: adoption is a read through pibGet, not a write");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    LoopbackRadio_SetLost(&dev.model, 1);

    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "the episode is the same shape as every other: mark what was seen and do nothing else");
    Test_Expect(dev.mac.reapplyPending == 0,
           "and nothing is owed for it: the debt is what band A asked this device to hold, not what the device said about itself");

    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.needsRearm == 1, "while the claim only the owner of the backend can answer stands just the same");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 1, "and the poll in front of the device is still at the backend, untouched");

    scriptResetPib(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the turn the device answers again, holding the defaults a reset leaves it with");
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX), 0,
           "and no request of any kind was handed down on it: a recovery that owes nothing lands nothing, not even a call that would be refused");
    counters = Mac_CountersOf(&dev.mac);

    Test_ExpectCount(counters.pibReapplications, 0, "which is band A's counter moving not at all, rather than a re-push it tried and failed");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 0, "and the backend recorded no refusal either, because it was asked for nothing");
    Test_Expect(dev.mac.lostEpisode == 0 && dev.mac.reapplyPending == 0,
           "with the episode closed and no debt left standing for a later turn to try again");
    Test_ExpectCount(mirror->present, RADIO_PIB_HW_ADDRESS,
           "while the mirror is exactly what it was before the round trip: the device's own report, kept for reading and never put back");

    got = LoopbackRadio_Sent(&dev.model, sent, 1);
    Test_ExpectCount(got, 0,
           "and the held poll was not answered: the factory device reports no short address, so a Data Request naming 0x0000 is not its poll (6.6.2 c, d) and owing nothing is not standing still");
    counters = Mac_CountersOf(&dev.mac);

    Test_ExpectCount(counters.pibReapplications, 0, "with the counter still where it started");
}

/* An RCP re-arms promiscuous after a reset of its own, and a promiscuous receiver acknowledges nothing (10.23.1), so
   the delivery mode band A stated is owed again with the pending table, after the PIB and only once. */
void caseLostRestatesTheDeliveryMode(void)
{
    Test_BandA dev;
    Radio_Caps caps;
    uint32_t pendingBefore;

    Test_BandACapsPendingTable(&caps);
    LoopbackRadio_Init(&dev.model, &caps);
    Test_ExpectStatus(Mac_Init(&dev.mac, LoopbackRadio_Seam(&dev.model), 0), ZB_OK,
                      "band A adopts a backend that keeps 10.22.3's pending table");

    Test_ExpectStatus(Mac_SetPromiscuousMode(&dev.mac, 0), ZB_OK, "10.23.1's mode FALSE is stated to the radio");
    Test_Expect(dev.model.filter.isPromiscuous == 0, "and the radio holds filtered delivery");

    LoopbackRadio_SetLost(&dev.model, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "a lost turn");
    Test_Expect(dev.mac.restatePending == 1, "the episode owes the mode again, beside the PIB");

    dev.model.filter.isPromiscuous = 1;
    scriptResetPib(&dev.model);
    pendingBefore = LoopbackRadio_PendingWrites(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);

    Test_ExpectStatus(Mac_Step(&dev.mac, 210), ZB_OK, "the turn the device answers again, back in its promiscuous default");
    Test_Expect(dev.model.filter.isPromiscuous == 0,
                "10.23.1: the mode band A stated is the mode the device holds again, so it acknowledges once more");
    Test_Expect(LoopbackRadio_PendingWrites(&dev.model) == pendingBefore + 1,
                "10.22.3: and the pending table is stated once with it");
    Test_Expect(dev.mac.restatePending == 0, "the debt is discharged by a radio that took both");

    Test_ExpectStatus(Mac_Step(&dev.mac, 220), ZB_OK, "a later turn");
    Test_Expect(LoopbackRadio_PendingWrites(&dev.model) == pendingBefore + 1, "states nothing again: one restatement per episode");
}
