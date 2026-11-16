/* The `nwk_routedisc` suite's case list: every case `nwk_routedisc_main.c` drives, in the one order
   `test/suite_ledger.json` records, so the run order is readable in one place. What each proves lives in the
   two case files beside this header (`cases_rreq.c` for the Route Request of Figure 3-9 and Annex K/I's TLV
   tail, `cases_discovery.c` for Table 3-79's table) and the machinery both use in `nwk_routedisc_helpers.c`. */

#ifndef NWK_ROUTEDISC_CASES_H
#define NWK_ROUTEDISC_CASES_H

void caseRreqComposeWithDestinationIeee(void);
void caseRreqComposeWithoutDestinationIeee(void);
void caseRreqComposeManyToOneWithConcentrator(void);
void caseRreqParseRoundTripsThoseThree(void);
void caseRreqRefusesAShortPayload(void);
void caseRreqRefusesManyToOneReserved(void);
void caseRreqReadsThroughReservedOptionBits(void);
void caseRreqRefusesTheDeprecatedBit(void);
void caseRreqRefusesIeeeBitWithoutOctets(void);
void caseRreqRefusesADuplicatedTlv(void);
void caseRreqRefusesADuplicatedGlobalTlv(void);
void caseRreqRefusesAnOddSolicitationList(void);
void caseRreqRefusesATruncatedTlv(void);
void caseExtendedRouteInformationAbsentFallsBack(void);
void caseExtendedRouteInformationLongerIsRead(void);
void caseRreqRefusesATwoOctetExtendedRouteInformation(void);
void caseRreqComposeForwardCarriesTheTail(void);
void caseUnknownLocalTagIsIgnored(void);
void caseMalformedTlvTerminatesWhatPrecededIt(void);
void caseTlvLongerThanItsFieldsIsSteppedOver(void);
void caseRreqTagOneIsMalformedAtItsMinimum(void);
void caseNetworkStatusTagTwoIsIgnored(void);
void caseGlobalTagRulesHoldForEveryCommand(void);
void caseExtendedRouteInformationWriter(void);

void caseDiscoveryClaimFindAndCount(void);
void caseDiscoverySameKeyAnswersOneSlot(void);
void caseDiscoveryExpiresAtThePrintedTime(void);
void caseDiscoveryReclaimsAnExpiredSlot(void);
void caseDiscoveryFullPoolRefusesTheNinth(void);
void caseDiscoveryRemoveDeletesByKey(void);
void caseDiscoveryRunningAnswersForAnInitiatorAndADestination(void);

#endif /* NWK_ROUTEDISC_CASES_H */
