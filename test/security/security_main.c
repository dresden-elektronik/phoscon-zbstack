/* The `security` suite's entry point: a suite is a name and a ledger, not a
   file, so this file names the run and drives the 33
   cases in the one order `test/suite_ledger.json` records, and then evaluates the vectors' intermediates once as
   quoted, because a claim a case never evaluates is not a claim. What each case proves lives in the two topic case
   files beside it (`cases_nwk.c`, `cases_aps.c`) and the fixtures they share in `security_helpers.c`. Nothing here
   asserts anything about the module: the cases do. */

#include <stdint.h>

#include "security.h"
#include "security_cases.h"
#include "security_helpers.h"
#include "test_harness.h"

int main(void)
{
    uint8_t adata[SECURITY_FRAME_MAX];
    uint8_t nonce[SECURITY_NONCE_LEN];
    uint32_t adataLen;
    uint32_t nonceLen;

    Test_Begin("security");

    caseProtectVector();
    caseProtectSecondFrameUsesNextCounter();
    caseUnprotectAndFreshness();
    caseTamperedMic();
    caseKeyAdoption();
    caseKeyAdoptionNeedsANewerSequenceNumber();
    caseNetworkKeyInstall();
    caseNetworkKeyInstallAtJoin();
    caseNetworkKeyInstallDropsItsWindows();
    caseOutgoingCounterExhausted();
    caseIncomingCounterMaximum();
    caseUnknownKeySeqNumber();
    caseUnsupportedAuxiliaryShapes();
    caseMicOnlyLevel();
    caseSourceRouteInsideTheAuthenticatedString();
    caseLevelsAndCrossLevel();
    caseMic128Level();
    caseInitRefusals();
    caseIncomingPoolFull();
    caseResetWipesEverything();
    caseCapacityRefusals();
    caseProtectApsVector();
    caseProtectApsShortAux();
    caseUnprotectApsVectorAndReply();
    caseUnprotectApsNoAuxAddress();
    caseUnprotectApsRvfcTransparent();
    caseUnprotectApsReplay();
    caseUnprotectApsEqualCounter();
    caseUnprotectApsTampered();
    caseProtectApsCounterExhausted();
    caseUnprotectApsCounterMaximum();
    caseApsUnsupportedKeyIdentifiers();
    caseApsRvfcFollowsFrameType();
    caseUnprotectApsSourceMustMatchTheMap();
    caseUnprotectApsUnauthorizedTakesARelayedFrame();
    caseApsInitRefusals();
    caseKeyPairLookups();
    caseApsUnverifiedFrameCounter();
    caseResetWipesApsMaterial();
    caseApsCapacityRefusals();
    caseVerifyKeyPair();
    caseUnverifiedPairEncryptsNothing();

    /* The vectors' intermediates, checked once as quoted: the suite claims the nonce and the
       authenticated string above are the ones the frames were computed from, and a claim a case
       never evaluates is not a claim. */
    nonceLen = Test_ParseHex(s_nonce1Hex, nonce, SECURITY_NONCE_LEN);
    Test_Expect(nonceLen == SECURITY_NONCE_LEN, "the s1 nonce is the 13 octets Figure 4-26 prints");
    Test_Expect(nonce[0] == 0xef && nonce[7] == 0x01, "starting with this device's extended address, low octet first");
    Test_Expect(nonce[8] == 0x05 && nonce[11] == 0x00, "then the frame counter, low octet first");
    Test_Expect(nonce[12] == 0x2d, "then the security control octet with the level in it: 0x2D in the computation, 0x28 on air");

    adataLen = Test_ParseHex(s_adata1Hex, adata, SECURITY_FRAME_MAX);
    Test_Expect(adataLen == HEADER_LEN + SECURITY_AUX_LEN, "the s1 authenticated string is the 22 octets 4.3.1.1 step 3d names: NwkHeader || AuxiliaryHeader");
    Test_Expect(adata[HEADER_LEN] == 0x2d, "with the auxiliary header's control octet carrying the level, which the frame itself does not");

    /* The APS vectors' intermediates, evaluated the same way. a1's nonce is what a1's frame is not: the
       control octet with the level in it, and this device's address whether or not the frame carried one. */
    nonceLen = Test_ParseHex(s_apsNonce1Hex, nonce, SECURITY_NONCE_LEN);
    Test_Expect(nonceLen == SECURITY_NONCE_LEN, "the a1 nonce is the 13 octets Figure 4-26 prints");
    Test_Expect(nonce[0] == 0xef && nonce[7] == 0x01, "starting with this device's own extended address, low octet first (4.4.1.1 step 5c with 4.5.2.2)");
    Test_Expect(nonce[8] == 0x04 && nonce[11] == 0x00, "then the frame counter, low octet first");
    Test_Expect(nonce[12] == 0x65, "then the security control octet with the level in it: 0x65 in the computation, 0x60 on air (4.4.1.1 steps 4 and 10)");

    nonceLen = Test_ParseHex(s_apsNonce2Hex, nonce, SECURITY_NONCE_LEN);
    Test_Expect(nonceLen == SECURITY_NONCE_LEN, "and a2's nonce is 13 octets too, although its frame carries no address at all");
    Test_Expect(nonce[0] == 0xef && nonce[7] == 0x01 && nonce[8] == 0x05, "the same local address and the next counter");
    Test_Expect(nonce[12] == 0x45, "with 0x45 where the frame carries 0x40: the extended nonce decides the auxiliary header's length and nothing about the nonce's length");

    adataLen = Test_ParseHex(s_apsAdata1Hex, adata, SECURITY_FRAME_MAX);
    Test_Expect(adataLen == APS_HEADER_LEN + SECURITY_APS_AUX_MAX,
           "the a1 authenticated string is the 21 octets 4.4.1.1 step 5d names for an encrypting level: ApsHeader || AuxiliaryHeader");
    Test_Expect(adata[APS_HEADER_LEN] == 0x65, "with the auxiliary header's control octet carrying the level, which the frame itself does not");
    Test_Expect(adata[APS_HEADER_LEN + 5] == 0xef && adata[APS_HEADER_LEN + 12] == 0x01,
           "and the source address field inside it is the local one: the string that is authenticated, not the string that is transmitted");

    return Test_Report();
}
