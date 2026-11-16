/* Suite for band A's security module: the two procedures of R23.1 4.3.1.1 and 4.3.1.2 that
   src/zb/security.{c,h} implements, and the two of
   4.4.1.1 and 4.4.1.2 it implements too. Runs on no radio, no port, no clock and no device:
   the module is pure, so the suite is a table of frames.
   (docs/internals/testing.md §2).

   Provenance of the byte-exact vectors. No secured-NWK frame is published anywhere in the
   corpus: R23.1 Annexes B and C, IEEE 802.15.4-2024 Annex C and IEEE 802.15.4-2006 Annex C
   were all searched and none carries a Zigbee NWK auxiliary header. The five NWK vectors below
   were therefore computed from the printed procedure by an independent CPython implementation,
   AES-ECB and AES-CTR primitives from the `cryptography` package, assembled per R23.1 Annex
   A.2 (the flags octet, the 2-octet length prefix on the authenticated string, the counter
   blocks, the truncated CBC-MAC), which is the same shape R23.1 Annex C.3 and C.4 use to
   validate a CCM* implementation, and the same shape src/crypto was validated against. Every
   vector is a frame this module must produce octet for octet, and each one is also reproduced
   by the CCM* seam directly from the intermediates the vector names: the 13-octet nonce
   `efcdab8967452301 05000000 2d` and the authenticated string `NwkHeader || AuxiliaryHeader`
   with the pre-overwrite control octet. Those intermediates are a reading of 4.5.2.2 with
   Figure 4-26 and are recorded there as an inference pending a live capture; if a real RCP
   ever disagrees about them, it is the vectors and the suite that change, not the code that
   answers to them.

   The four APS vectors a1-a4 are computed the same way, and they are needed for the same reason: the
   corpus prints no secured-APS frame at all, Figures 4-35…4-39, the only narrative example of APS
   encryption in R23.1, are rasters with no text layer behind them, and the interop fixtures carry the APS
   security bit clear in every one of the 79 + 24 APDUs they hold (measured). So a1-a4 come from a reading
   of 4.4.1.1 computed twice over: by the CPython oracle above and by an independent second implementation
   of Annex A.2, and the octets this module puts out are then checked against them. The intermediates are
   quoted in main, where their lengths are evaluated: a1's 13-octet nonce `efcdab8967452301 04000000 65`
   and its 21-octet authenticated string `2001060004010311 6504000000efcdab8967452301`, with 0x65 in the
   nonce where the frame carries 0x60 (4.4.1.1 step 10) and, in a2, an address that travels in the nonce
   and on no air at all.

   The suite is two topic case files and this is the one header that names what they prove: every case `main`
   drives is declared here, in the order it drives them, so the run order (the two NWK procedures and the shape of
   the module, then the two APS ones and the key-pair material) is readable in one place, under the run the entry
   point keeps. The fixtures, the descriptors and the vectors two or more of them use are `security_helpers.h`
   beside it; the vectors a single half quotes are its own file's. */

/* Thirty-three cases: 1-17 the two NWK procedures and the shape of the module, in the order the
   clauses run; 18-33 the two APS procedures and the key-pair material added to it.
   1 protect the s1 vector; 2 protect again and take the next counter; 3 unprotect s1 and the
   freshness rule against s5; 4 a tampered MIC that stores nothing; 5 a received key sequence
   number adopted and the frame it protects next, 5b the same step's "newer": an older key that
   leaves the active number alone and a newer one across the octet's wrap; 6 the outgoing counter at 2^32-1; 7 an incoming
   one at the same value; 8 a key sequence number the set does not hold; 9 the two auxiliary
   shapes band A refuses; 10 the authentication-only level against s3; 11 the source route inside
   the authenticated string against s4; 12 the other levels and a frame secured at one and read at
   another; 13 the MIC-128 level 0x03 round trip, in the clear and with the tag gating it both
   ways; 14 what Security_Init refuses; 15 the incoming store at its bound with nwkAllFresh both
   ways; 16 Security_Reset; 17 the two capacity refusals.
   18 protect the a1 vector, read the key-pair bank the snapshot exports, and round-trip the pair at the
   levels Table 4-38 prints and no vector covers; 19 protect a2, the
   5-octet auxiliary; 20 unprotect a1 at the partner and protect and read back the a3 reply; 21 the
   a2 shape with no address on the air, where the hint selects the entry and the entry names the
   nonce; 22 a4 read with the Require Verified Frame Counter bit clear and reported, not judged; 23 a
   replay of a1 refused by the entry's window, which the refusal leaves unmoved; 24 the equal-counter
   acceptance 4.4.1.2 step 4 as printed; 25 a tampered a1 that stores nothing and costs the sender
   nothing; 26 an entry whose outgoing counter is 2^32-1, and the other entry of the same pool still
   working; 27 a frame carrying ReceivedFrameCount 2^32-1, refused by step 1 before any crypto; 28 the
   three key identifiers 4.4.1 prints for APS and this slice does not read; 29 what Security_Init
   refuses a key pair for; 30 the two key-pair lookups and what they refuse to match; 31 4.4.1.2 step
   8's UNVERIFIED_FRAME_COUNTER leg, reachable through configuration and cleared by nothing this module
   can do; 32 Security_Reset over the new pool; 33 the two capacity refusals and what neither
   consumes. */

#ifndef SECURITY_CASES_H
#define SECURITY_CASES_H

void caseProtectVector(void);
void caseProtectSecondFrameUsesNextCounter(void);
void caseUnprotectAndFreshness(void);
void caseTamperedMic(void);
void caseKeyAdoption(void);
void caseKeyAdoptionNeedsANewerSequenceNumber(void);
void caseNetworkKeyInstall(void);
void caseNetworkKeyInstallAtJoin(void);
void caseNetworkKeyInstallDropsItsWindows(void);
void caseOutgoingCounterExhausted(void);
void caseIncomingCounterMaximum(void);
void caseUnknownKeySeqNumber(void);
void caseUnsupportedAuxiliaryShapes(void);
void caseMicOnlyLevel(void);
void caseSourceRouteInsideTheAuthenticatedString(void);
void caseLevelsAndCrossLevel(void);
void caseMic128Level(void);
void caseInitRefusals(void);
void caseIncomingPoolFull(void);
void caseResetWipesEverything(void);
void caseCapacityRefusals(void);
void caseProtectApsVector(void);
void caseProtectApsShortAux(void);
void caseUnprotectApsVectorAndReply(void);
void caseUnprotectApsNoAuxAddress(void);
void caseUnprotectApsRvfcTransparent(void);
void caseUnprotectApsReplay(void);
void caseUnprotectApsEqualCounter(void);
void caseUnprotectApsTampered(void);
void caseProtectApsCounterExhausted(void);
void caseUnprotectApsCounterMaximum(void);
void caseApsUnsupportedKeyIdentifiers(void);
void caseApsRvfcFollowsFrameType(void);
void caseUnprotectApsSourceMustMatchTheMap(void);
void caseUnprotectApsUnauthorizedTakesARelayedFrame(void);
void caseApsInitRefusals(void);
void caseKeyPairLookups(void);
void caseApsUnverifiedFrameCounter(void);
void caseResetWipesApsMaterial(void);
void caseApsCapacityRefusals(void);
void caseVerifyKeyPair(void);
void caseUnverifiedPairEncryptsNothing(void);

#endif /* SECURITY_CASES_H */
