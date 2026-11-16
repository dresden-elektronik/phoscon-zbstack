/* A band-A device as the host suites build it.

   The stack every band-A suite stands on, in one place: `loopback_radio` as the hardware-free backend, a
   MAC on its seam, and the network layer on that MAC, each adopted by pointer, each configured the way the
   measured devices are configured, on channel 26 with the identity the caller names.

   A rig is a *constructor*, so it asserts nothing: `Test_BandABuild` reports the first status that was not
   `ZB_OK`, and the suite that cares which stage refused says so at its own assertion site. What a suite
   keeps of its own is what is genuinely its subject (a deny-tx shim, an APS service on top, a neighbour
   table seeded with IEEE addresses, an air log) and the assertions it makes about them.

   The caps are the two the RCPs report (docs/internals/hardware.md §4): 0x10d with the
   acknowledgment wait, and 0x10c without it. The config is the deterministic one
   the application supplies (a device type, a receiver duty and three seeds) and a
   field a caller does not name is 0, which is this tree's deterministic default. */

#ifndef RIG_BAND_A_H
#define RIG_BAND_A_H

#include <stdint.h>

#include "log.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "zb_status.h"

/* The three layers, caller-owned storage on the case's stack, as docs/internals/coding-rules.md §4.3 requires of the
   modules themselves. */
typedef struct Test_BandA
{
    Loopback_Radio model;
    Mac_Mac mac;
    Nwk_Nwk nwk;
} Test_BandA;

/* What the application tells a band-A device about itself: the radio it was built against, its identity in
   the PAN, the receiver duty the network layer reads back out of the PIB (Table 3-80), and the
   three seeds the application holds rather than band A. */
typedef struct Test_BandAConfig
{
    Radio_Caps caps;
    uint16_t ownAddress;
    uint16_t panId;
    uint32_t deviceType;
    int rxOnWhenIdle;
    uint32_t seqStart;
    uint32_t jitterSeed;
    uint32_t dsnStart;
    uint32_t joinSeed;
    uint64_t trustCenterIeee;
    uint64_t ownExtended;

    /* `Mac_Config.hearsWhileAsleep`, 1 by default: a frame a case injects into a device with macRxOnWhenIdle FALSE
       is one its poll's window heard, so the network layer's rules are exercised without a poll before each. */
    int hearsWhileAsleep;

    /* The diagnostics pool the MAC is handed as `Mac_Config.log`, or 0 for none: a case that reads a record
       the module wrote names its own pool here, which is the door an application uses. */
    Log_Log *log;
} Test_BandAConfig;

/* The capabilities both measured RCPs report: RADIO_CAPS 0x10d, and the acknowledgment timeout among
   them (docs/internals/hardware.md §4). */
void Test_BandACapsAcks(Radio_Caps *outCaps);

/* 0x10c: transmit retries and CSMA backoff, no acknowledgment timeout, the shape a band A that has to run
   its own acknowledgment wait would be handed. */
void Test_BandACapsNoAcks(Radio_Caps *outCaps);

/* The same pair with the pending table a radio that states 10.22.3's bit from it would report. */
void Test_BandACapsPendingTable(Radio_Caps *outCaps);

/* The deterministic config: a router, listening, with routing duties (3.6.2.2, 3.6.6), no address and no
   PAN until the caller names them, and every seed 0, which is NWK_SEQ_START and no jitter, the numbering and
   the schedules every case written before the seeds existed asserts (3.6.1.8's join seed then takes the house
   constant). `trustCenterIeee` is 0 as well, which the network layer reads as the AIB's all-ones "no trust
   centre": a case that wants one, and an accepted unsecured rejoin needs one (3.6.1.6.1.3), names it. */
void Test_BandADefaults(Test_BandAConfig *cfg);

/* Model -> seam -> MAC -> network layer, each adopted by pointer and configured from `cfg`. Returns the
   first status that was not `ZB_OK` (the model's, the MAC's, the PIB write's or the network layer's), so a
   suite can assert the one that names the stage it cares about. */
ZbStatus Test_BandABuild(Test_BandA *rig, const Test_BandAConfig *cfg);

/* The neighbor table as a case seeds it: an entry put in by hand, for the one thing a received frame cannot
   supply. Band A observes an address and, if the frame carried one, an IEEE address; a device type and a
   receiver duty come from association, which is ZDO work that is deferred, so a case that wants a rule
   reading a device type seeds one. No assertion: a table with no room leaves the entry unwritten, and the
   suite that cares asks the table. */
void Test_BandASeedNeighbor(Nwk_Nwk *nwk, uint16_t addr, uint32_t deviceType, int rxOnWhenIdle,
                            uint32_t relationship);

/* The layer above a device's network layer, played by the case. Take copies what the receive holds into the
   device's own 32-frame queue, NSDU included, and is done with each; Step is Nwk_Step then Take; Poll takes,
   then hands out the oldest, up to `max`; Forget empties the queue, which building the device does. */
void Test_NwkTake(Nwk_Nwk *nwk);
ZbStatus Test_NwkStep(Nwk_Nwk *nwk, uint32_t nowMs);
uint32_t Test_NwkPoll(Nwk_Nwk *nwk, Nwk_DataIndicationParameters *out, uint32_t max);
void Test_NwkForget(const Nwk_Nwk *nwk);

#endif /* RIG_BAND_A_H */
