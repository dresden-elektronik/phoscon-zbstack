/* The `nwk_routedisc` suite's entry point: a suite is a name and a ledger, not a file, so this file names the
   run and drives its cases in the one order
   `test/suite_ledger.json` records. What each of them proves lives in the two topic case files beside it
   (`cases_rreq.c` for the Route Request of Figure 3-9 and Annex K/I's TLV tail, `cases_discovery.c` for
   Table 3-79's table) and the machinery both share in `nwk_routedisc_helpers.c`. Nothing here asserts
   anything: the cases do. */

#include "nwk_routedisc_cases.h"
#include "test_harness.h"

int main(void)
{
    Test_Begin("nwk_routedisc");

    caseRreqComposeWithDestinationIeee();
    caseRreqComposeWithoutDestinationIeee();
    caseRreqComposeManyToOneWithConcentrator();
    caseRreqParseRoundTripsThoseThree();
    caseRreqRefusesAShortPayload();
    caseRreqRefusesManyToOneReserved();
    caseRreqReadsThroughReservedOptionBits();
    caseRreqRefusesTheDeprecatedBit();
    caseRreqRefusesIeeeBitWithoutOctets();
    caseRreqRefusesADuplicatedTlv();
    caseRreqRefusesADuplicatedGlobalTlv();
    caseRreqRefusesAnOddSolicitationList();
    caseRreqRefusesATruncatedTlv();
    caseExtendedRouteInformationAbsentFallsBack();
    caseExtendedRouteInformationLongerIsRead();
    caseRreqRefusesATwoOctetExtendedRouteInformation();
    caseRreqComposeForwardCarriesTheTail();
    caseUnknownLocalTagIsIgnored();
    caseMalformedTlvTerminatesWhatPrecededIt();
    caseTlvLongerThanItsFieldsIsSteppedOver();
    caseRreqTagOneIsMalformedAtItsMinimum();
    caseNetworkStatusTagTwoIsIgnored();
    caseGlobalTagRulesHoldForEveryCommand();
    caseExtendedRouteInformationWriter();

    caseDiscoveryClaimFindAndCount();
    caseDiscoverySameKeyAnswersOneSlot();
    caseDiscoveryExpiresAtThePrintedTime();
    caseDiscoveryReclaimsAnExpiredSlot();
    caseDiscoveryFullPoolRefusesTheNinth();
    caseDiscoveryRemoveDeletesByKey();
    caseDiscoveryRunningAnswersForAnInitiatorAndADestination();

    return Test_Report();
}
