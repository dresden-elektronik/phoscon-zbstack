/* The `nwk` suite's association permit: 3.2.2.7's three arms of PermitDuration, the countdown 3.2.2.7.3 arms for a
   duration, and 3.2.2.7.3's answer for a device that cannot state one. */

#include <stdint.h>

#include "nwk_beacon.h"
#include "nwk_helpers.h"
#include "nwk_permit.h"
#include "test_harness.h"
#include "zb_utils.h"

#define PERMIT_SHORT 0xdead
#define PERMIT_PAN 0xbeef

static void permitBeaconInfo(Nwk_BeaconInfo *info)
{
    Zb_memset(info, 0, (uint32_t)sizeof *info);

    info->stackProfile = 2;
    info->protocolVersion = 2;
    info->routerCapacity = 1;
    info->endDeviceCapacity = 1;
    info->extendedPanId = 0x0123456789abcdef;
    info->txOffset = 0xffffff;
}

void casePermitJoining(void)
{
    Test_BandA dev;
    Nwk_BeaconInfo info;

    permitBeaconInfo(&info);
    rig(&dev, PERMIT_SHORT, PERMIT_PAN);

    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 1), ZB_OK, "the application states the beacon");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, NWK_PERMIT_OFF, 100), NWK_PERMIT_SUCCESS,
                     "3.2.2.7.3: a duration of 0x00 is answered SUCCESS");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 0, "and the permit stands false");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, NWK_PERMIT_UNLIMITED, 200), NWK_PERMIT_SUCCESS,
                     "3.2.2.7.3: 0xff is answered SUCCESS too");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "and the permit stands true");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1000000), ZB_OK, "the device is stepped long after");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "and 0xff's permit is not a countdown");
    Test_ExpectCount(Nwk_PermitJoiningExpiries(&dev.nwk), 0, "which the expiry count says plainly");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 30, 1000), NWK_PERMIT_SUCCESS, "3.2.2.7.3: a duration is accepted");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "the permit stands while it runs");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 30000), ZB_OK, "stepped before the seconds are up");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "and still standing");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 32000), ZB_OK, "stepped after them");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 0, "and the permit is set false as 3.2.2.7.3 puts it");
    Test_ExpectCount(Nwk_PermitJoiningExpiries(&dev.nwk), 1, "once, counted");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 10, 33000), NWK_PERMIT_SUCCESS, "a later request is accepted");
    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 200, 34000), NWK_PERMIT_SUCCESS,
                     "and 3.2.2.7.3's rule that every request supersedes the one before it: the first countdown is "
                     "gone");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 40000), ZB_OK, "stepped past the 10 s one's expiry");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "the permit still stands on the second one's clock");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 0x100, 41000), NWK_PERMIT_INV_REQUESTTYPE,
                     "a duration outside Table 3-15's range is refused and changes nothing");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "as the permit shows");

    Test_ExpectCount(Nwk_PermitJoiningRequests(&dev.nwk), 5, "five requests were carried out");
}

/* 3.2.2.7.3's other arm: an end device cannot permit joining, and it says so without touching anything. */
void casePermitJoiningRefusedForAnEndDevice(void)
{
    Test_BandA dev;
    Nwk_BeaconInfo info;

    permitBeaconInfo(&info);
    rigAt(&dev, PERMIT_SHORT, PERMIT_PAN, NWK_DEVICE_END_DEVICE, 0);

    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 1), ZB_OK, "an end device can be handed a beacon record");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "and it stands as it was given");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 30, 100), NWK_PERMIT_INV_REQUESTTYPE,
                     "3.2.2.7.3: the confirm for an end device is INV_REQUESTTYPE");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 1, "and nothing about the device changed");
    Test_ExpectCount(Nwk_PermitJoiningRequests(&dev.nwk), 0, "with no request counted");

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 30, 200), NWK_PERMIT_INV_REQUESTTYPE, "again, the same answer");
}

/* The permit leg re-states the beacon, so a device that was never given beacon info cannot permit anything. */
void casePermitJoiningWithoutBeaconInfo(void)
{
    Test_BandA dev;

    rig(&dev, PERMIT_SHORT, PERMIT_PAN);

    Test_ExpectCount(Nwk_PermitJoining(&dev.nwk, 30, 100), NWK_PERMIT_INV_REQUESTTYPE,
                     "no beacon to re-state, no permit");
    Test_ExpectCount(Nwk_PermitJoiningActive(&dev.nwk), 0, "and the join door is left as it was");
}
