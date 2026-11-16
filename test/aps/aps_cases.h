/* Suite for band A's APS service: the transmit half of R23.1 2.2.4.1 and the acknowledgement machine of
 * 2.2.8.4, run over the network layer this module adopts and the hardware-free backend band A's other suites
 * run over. Nothing here touches a radio, a wall clock or a device (docs/internals/testing.md §2).
 *
 * What the suite can see, and so what it asserts. An APS transaction is only observable through the frames it
 * puts on the air and the confirmations it queues, and both are read here: the air log is this device's own
 * transmitted octets, harvested after every request and every turn because `loopbackRadio` reclaims a transmit
 * record as soon as the MAC has collected its completion (the same rig fact nwk/ in test/ states, and the reason
 * a case that read the backend after its answer would be reading whatever frame came next); the confirmation
 * ring is read through `Aps_PollConfirms`, which is the SAP's own channel. The payload of every captured frame
 * is the APDU, read at `MAC header + NWK header`: a transaction's retransmissions are therefore four
 * distinguishable NWK frames carrying one identical APDU, which is a resolution stated as an observation and not
 * as a claim.
 *
 * Where a peer is needed there is a second, and in one case a third, stack of its own: its `nwk` composes and
 * issues the frame, and the octets it put on its side of the seam are handed to the target model as a neighbor's
 * delivery. Two kinds of peer appear, and which one a case uses is decided by which side of the round trip it
 * asserts. A peer that only *answers* is modelled as its frame on the air, an acknowledgement APDU composed
 * through `ApsFrame_Compose` (nothing else writes an APDU) and carried down by the peer's network layer, because
 * to the module under test a foreign device's answer is exactly that: octets at its doorstep, with nothing of the
 * peer's sub-layer in them. That is what cases 5 and 6 need, where what is under test is the matching of an
 * answer and not the owing of one. A peer that *sends* is a full second stack, its own `aps` on top of its own
 * `nwk`, because from case 13 on the frame being decided is an APS frame a peer's APS composed, and where the
 * acknowledgement owed is itself the thing under test (case 14) it is composed and issued by the module that owes
 * it, which is the only arrangement in which the swap 2.2.5.2.3.1 states can be checked against a composition the
 * case did not make.
 *
 * Times are scripted. Every `nowMs` is a number the case chose, and the waits are read as the difference
 * between two of them, so `apscAckWaitDuration` is asserted as a fact about when a retransmission happened and
 * not as a fact about how long the suite sat.
 *
 * Part C (cases 25 to 33, the crossing) adds a third kind of fixture and one rule about it. A secured
 * case runs a stack with the application's `Security` attached to `aps` (`Aps_AttachSecurity`),
 * keyed by the pair Table 4-36 describes, at the NIB default level 0x05; the `nwk` underneath
 * stays unsecured on purpose, so the octets the suite compares are the APSDU and nothing else, and
 * a1, a2 and a3 are quoted from the `security` suite rather than recomputed here: the same link
 * key, the same extended addresses, the same counters, the same APS header, so a byte-for-byte
 * agreement means composition plus protection plus the NLDE hand-off produced a frame an independent
 * implementation of 4.4.1.1 computed, which is the hand-vector regime and nothing weaker. The frames
 * the *reception* cases refuse are built by this suite's own sender stack rather than written
 * out by hand, because a case that tampers with a frame has to know which octet it changed, and
 * an authenticated header is not a header a case may edit to suit itself. Where a case seeds the
 * module's APS counter to match a vector's counter octet, it says so at the line that does it.
 *
 * The suite is seven topic case files and this is the one header that names what they prove: every case `main`
 * drives is declared here, in the order it drives them, so the run order is readable in one place. The
 * machinery two or more of them share (the rigs and the peers, the air log and its accessors, the request and
 * APDU builders and the one turn) is `aps_helpers.h` beside it, and what the case files carry is their own
 * prose and their own scaffolding. */

#ifndef APS_CASES_H
#define APS_CASES_H

void caseDoorMatrix(void);
void caseConfirmVocabularyRefusals(void);
void caseUnicastNoAck(void);
void caseConfirmCarriesTheCallersTag(void);
void caseCounterSequence(void);
void caseAckHappyPath(void);
void caseAckMismatchSweep(void);
void caseRetransmissionShape(void);
void caseNwkPrecedence(void);
void caseBroadcastDelivery(void);
void caseGroupSend(void);
void caseRxDecided(void);
void casePoolPolicy(void);

void caseUnicastIndication(void);
void caseAckOwedEndToEnd(void);
void caseBroadcastEndpointPassedUp(void);
void caseGroupFanOut(void);
void caseGroupDeliveryUnfiltered(void);
void caseGroupServiceMatrix(void);
void caseDuplicateRejection(void);
void caseSecuredDeferred(void);
void caseCommandDeferred(void);
void caseFragmentedUnsupported(void);
void caseShapeRefused(void);
void caseMalformedApdu(void);
void caseIndicationRingPressure(void);

void caseSecuredUnicastOut(void);
void caseSecuredInVectors(void);
void caseSecuredEndToEndPair(void);
void caseSecuredRetransmissionReprotects(void);
void caseSecuredReplayRefused(void);
void caseSecuredTamperRefused(void);
void caseSecuredNoKeyPair(void);
void caseSecuredShapesDeferred(void);
void caseSecuredNoPartnerNamed(void);
void caseSecuredGlobalPairSender(void);

void caseTransportKeyComposed(void);
void caseTransportKeyReceipts(void);
void caseTransportKeyRequestRefusals(void);
void caseTransportKeyInstalled(void);
void caseTransportKeyAuthorizes(void);
void caseTransportKeyAcknowledged(void);
void caseTcLinkKeyExchange(void);
void caseTransportKeyUnderTheGlobalKeyAfterJoining(void);
void caseTcLinkKeyConfirmFailureGivesUp(void);
void caseTransportKeyTeachesTheTrustCentre(void);

/* cases_admit.c: 4.4.3's update-device and 4.4.4's remove-device services, at a trust centre and a router */
void caseUpdateDeviceAtTheTrustCentre(void);
void caseUpdateDeviceUnencryptedRefused(void);
void caseUpdateDeviceAwayFromTheTrustCentre(void);
void caseUpdateDeviceDoor(void);
void caseTransportKeyTunnelled(void);
void caseRouterReportsAJoin(void);
void caseRouterRelaysATunnel(void);
void caseCommandAcknowledgedInFormatOne(void);
void caseRemoveDeviceSent(void);
void caseRouterTakesARemoveDevice(void);
void caseAddressMapBothWays(void);
void caseBoundRequest(void);

#endif /* APS_CASES_H */
