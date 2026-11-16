/* The `nwk` suite's configuration case: the one rule about the number a
   config supplies. The crossing's attach and detach is the security part's, and lives in `cases_security.c`
   with the fixture it needs. */

#include "nwk.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * 8. The sequence number is the seed the config carries, and it wraps where an unseeded one wraps.
 *
 * 3.6.2.1: "The NWK layer on every device SHALL maintain a sequence number that is initialized with a random
 * value", and Table 3-66 prints nwkSequenceNumber as 0x00-0xff with the default "Random value from within the
 * range". The supplying of that value is the config's, and the increment and the wrap are here:
 * `Nwk_Config.seqStart` is the number the module starts with, the first frame this device composes carries it
 * in the octet 3.3.1.5 makes half of the frame's identity, and from there the counter moves by 1 per composed
 * frame and wraps inside the printed octet, the same arithmetic case 1 asserts, entered at a different number.
 * A seed outside that octet is refused at the door, because reducing it here would be this module deciding what
 * the number the application named meant.
 */
void caseSequenceNumberStartsFromTheConfig(void)
{
    Test_BandA dev;
    Nwk_Config cfg;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0x5a, 0);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast from a device whose sequence number was seeded");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame reached the backend");
    Test_Expect(npduOf(&air[0])[NPDU_SEQ_OCTET] == 0x5a,
                "and the Sequence Number octet of the NPDU is the octet the application supplied: read off the air the way case 1 reads the unseeded 0 (3.3.1.5)");
    Test_Expect(dev.nwk.seq == 0x5b,
                "and the number the next frame will take is one more: an increment, not a fresh draw (3.6.2.1, 'SHALL be incremented by 1, each time the NWK layer supplies a new sequence number value')");

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 101), ZB_OK, "the next request");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2 && npduOf(&air[1])[NPDU_SEQ_OCTET] == 0x5b, "carries the number after the seed");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "the two answers collected");
    harvestAir(&dev.model, air, &airCount);
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 2 && confirms[0].seq == 0x5a && confirms[1].seq == 0x5b,
                "and each confirmation names the number its own frame carried, oldest first: the pair 3.3.1.5 makes the frame's identity");

    /* Seeded at the top of the printed octet: the wrap is the attribute's range, and seeding a counter is not
       the same act as moving its bound. */
    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0xff, 0);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    airCount = 0;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 110), ZB_OK, "a device seeded at 0xff");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && npduOf(&air[0])[NPDU_SEQ_OCTET] == 0xff, "its first frame carries 0xff");

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 111), ZB_OK, "and the second");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2 && npduOf(&air[1])[NPDU_SEQ_OCTET] == 0x00,
                "wraps to 0 exactly where an unseeded device does, inside NWK_SEQ_WRAP (3.3.1.5 with Table 3-66's range)");
    Test_Expect(dev.nwk.seq == 0x01, "and the counter runs on from there");

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.deviceType = NWK_DEVICE_ROUTER;
    cfg.seqStart = 0x100;
    Test_ExpectStatus(Nwk_Init(&dev.nwk, &dev.mac, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "a seed outside the range Table 3-66 prints for the attribute is refused at the door rather than reduced into it");
    Test_Expect(dev.nwk.seq == 0x01 && dev.nwk.cfg.seqStart == 0xff,
                "and the refusal changed nothing: the module that failed to be re-initialised is still the module it was, which is the same consequence case 2 states for a refused device type");
}
