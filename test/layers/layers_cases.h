/* Suite for band A's façade: `Zb_Layers`, the one object that owns the four modules and the order that wires
   them, and the rules its init is held to, the config it takes, the extended address one build can never
   have in two places, the refusals that leave nothing half-built, the scaffold a level-0 device is, and the
   footprint the four embedded pools cost.

   A suite is a name and a ledger, not a file: this header declares every case `main`
   drives, in the order the ledger records, so the run order is readable in one place.
   The machinery the cases share (the device with its model backend and its two configs,
   and the byte image a refusal is judged against) is `layers_helpers.h` beside it.

   Runs on the hardware-free backend, so no Spinel, HDLC, property id, wall clock or radio appears anywhere in
   it, and every case drives the façade through its public operations: nothing here reaches into a module's
   internals to arrange a state the façade could have been handed. */

#ifndef STACK_CASES_H
#define STACK_CASES_H

/* A good configuration builds: level 0x05 with one key descriptor, a coordinator, every identity field named,
   the status, the running flag, the four accessors pointing at the embedded modules, the PIB mirror carrying
   what was configured, and the level and extended address the security module runs with. */
void caseBuildNamed(void);

/* The one extended address, checked: a config that names a PIB extended address other than the `ownIeee` the
   CCM* nonce uses is refused with the struct left zero bytes, before anything is applied. */
void caseBoundToOwnIeee(void);

/* The same binding the other way round, read from the device rather than written to it: a device that reports
   the config's `ownIeee` builds, a device that reports a different non-zero address is refused with the struct
   zero bytes, and a device that reports none (all zero, the LADDR of an RCP never given one) is absence
   rather than disagreement, so the stack builds and no PIB write carried the extended address at all. */
void caseDeviceNamesOwnIeee(void);
void caseDeviceNamesOtherIeee(void);
void caseDeviceNamesNoIeee(void);

/* The refusal matrix, one case per row: a null façade, a null config, a device type outside Table 3-75, a
   level 0x04 (M = 0, never a NWK level), a level above 0x07, a level that is not 0 with no security config to
   carry it, a security config whose own level is not the one the stack config names, and a security config
   that names no key at the level it is run with. Each answers ZB_ERR_BAD_ARGUMENT and leaves the façade zero
   bytes. */
void caseRefuseNullSelf(void);
void caseRefuseNullConfig(void);
void caseRefuseDeviceType(void);
void caseRefuseLevelEncOnly(void);
void caseRefuseLevelAboveMax(void);
void caseRefuseLevelWithoutSecurity(void);
void caseRefuseLevelDisagreement(void);
void caseJoiningEmptyKeySet(void);

/* A level-0 stack is the scaffold: no security config, level 0x00, and nothing refused, the security module
   answers not-enabled, neither layer above is attached to it, and the network layer still steps. */
void caseLevelZeroScaffold(void);

/* The four embedded pools measured and pinned, so a growth is a visible decision in the log rather than a
   silent one. The numbers are this build's and `main` prints them once before the cases run. */
void caseFootprint(void);

/* A failed init can be retried: a config refused before anything was applied, and a backend that was not there
   when the first apply ran, both leave the struct a second init can build on, with the corrected config the
   same struct comes up. */
void caseRetryAfterRefusal(void);

/* One `Zb_LayersStep` is one turn of the three layers: a frame the backend is holding is delivered upward once,
   the acknowledgement it makes this device owe is composed once, and the answer to that acknowledgement's own
   transmission is still owed by the next turn. A second step delivers nothing twice. This is the case that
   reddens if the facade ever advances a layer more than once per turn. */
void caseOneStepOneTurn(void);

/* The two drains route to the service that owns the ring: the confirmation a finished transaction produced and
   the delivery the peer's frame became both answer through the facade, and a null stack, a null output or a
   maximum of zero answers nothing. */
void caseDrainsRoute(void);

/* End to end through the facade: A sends one APS-secured acknowledged unicast to B, B's indication carries the
   payload under the link key its pair names, the acknowledgement B owed is the one A's confirmation was released
   by, and A's confirmation is ZB_OK with Table 2-29's SUCCESS. Neither device is authenticated, so 3.6.2.2's gate
   is off and this case pins the APSDU's crossing alone; `caseSecuredAckBothCrossings` is the authenticated one. */
void caseEndToEndPair(void);

/* The join 3.6.1.6.1 describes, with nothing of the application's carried: a parent that permits association
   answers the child's 10.21.2 exchange, 3.6.1.8 draws the address, 10.22.3's poll extracts the answer, and the
   exchange leaves the child holding its address and its parent's entry and the parent holding a child. */
void caseJoinNetwork(void);

/* The network rejoin of the same pair, 3.6.1.6.1.2 and 3.6.1.6.1.3: the child that is still on the network asks
   the parent its neighbour table names (3.4.6), the parent's three comparisons match its entry and its answer
   (3.4.7) repeats the address the join gave it, the child comes back joined under that address, the parent's
   indication names Table 3-22's NWK rejoin without security, and the three refusals the pair answers with
   (no address of its own, no key to secure it, a network no row names) are each named. */
void caseCommissioningJoinNetwork(void);
void caseCommissioningJoinSleepyChild(void);
void caseRejoinNetwork(void);
void caseJoinChannelChange(void);
void caseJoinOrphaning(void);
void caseTimeoutRequestAfterJoin(void);
void caseTimeoutRequestAfterRejoin(void);
void caseChildAgesOutAtTheDefault(void);
void caseChildPollIsAKeepalive(void);
void caseUnknownPollerIsAskedToLeave(void);

/* Both crossings on, at the two devices a real network has: A and B at level 0x05, joined and authenticated,
   holding the same network key. A sends one acknowledged unicast asking for the link key and the network key;
   B's indication carries the payload, B's acknowledgement is NWK-secured because the crossing is the device's
   state, and `Nwk_DroppedUnsecured` is 0 at both ends, which is what 3.6.2.2 would otherwise cost every
   acknowledgement an authenticated peer owes. */
void caseSecuredAckBothCrossings(void);
void caseTransportKeyIsNotNwkSecured(void);

/* The step's own door: a null stack and a stack that was never built are each refused with ZB_ERR_BAD_ARGUMENT. */
void caseRefusedStep(void);

/* The façade's own identity writes, seen from the far side of a lost event: the device comes back holding its reset
   defaults, the one re-application names the mask the config carried (every field asked for and no read-only field
   the device merely reported) and the identity is back on the device, the factory address still there to read. */
void caseLostReappliesWhatWasApplied(void);

/* A built stack captured and restored through the façade: the object carries the identity, the flags, the key
   and the three counters, the restore writes them back (banking the outgoing counter, stepping the three octet
   counters), the façade still reports itself running and a step still answers ZB_OK. */
void caseCaptureRestore(void);

/* Both calls' guard matrix: a null stack, one that was never built, and a null object on either side are each
   refused, the caller's state object is left byte-identical, and the stack a refusal was aimed at is still one. */
void caseCaptureRestoreGuards(void);

/* The send edge, and its door: a request aimed at no façade, at a stack whose init has not landed, and at one
   whose init was refused is answered by the façade's own refusal, with every layer counter unmoved, no pool
   holding anything the call took, and the model's air provably empty. */
void caseSendRefusedAtDoor(void);

/* The crossing: one accepted request puts exactly one frame at the backend and moves the sub-layer, network and
   MAC counters a request of that shape moves in their own suites (one slot at each layer, and one step of each
   layer's own numbering), so the façade is proven to add nothing and skip nothing. */
void caseSendCrossingPinsCounters(void);

/* The answer coming back: the confirmation the cascade produces is reported by `Zb_LayersPollConfirms` at the
   step that produces it and not at the step before it, the case driven through the façade alone. */
void caseSendConfirmAtItsStep(void);

/* Two refusals, each named by the layer that gave it: a DstAddressMode in Table 2-2's reserved band refused at
   the sub-layer's own door, and a request asking for network protection at a device holding no security reaching
   the caller as that layer's `ZB_ERR_UNSUPPORTED`, unchanged, with nothing on the model's air. */
void caseSendRefusalNamesItsLayer(void);

/* The whole frame is the layers' work and not the façade's: the MPDU the backend was handed is read as the MHR,
   the NWK header and the APS data header around the caller's ASDU, against a known answer written out of the
   figures, and a second call shows each layer's number moving with its own frame. */
void caseSendFrameIsTheLayersWork(void);

/* The known answer two RCPs put on channel 26: a device built with the identity, the seeds, the request and
   the material the rig transcripts print, held to the octets their tee records wrote, the whole cascade, down to
   the footer. */
void caseOnAirRigIsTheRecordedDevice(void);
void caseOnAirUnsecuredFramesAreTheRecordedOctets(void);
void caseOnAirSecuredFramesAreTheRecordedOctets(void);

/* The peer's seven delivered copies, read as a fixture first: each one is the tee record its own transcript says
   it is, at the length its line counts and FCS-valid here as it was at the receiving RCP. */
void caseOnAirCopiesAreTheRecordedFrames(void);

/* The same seven through the device that sent them, each refusal named by the clause that decided it, and through
   a device at the destination they name: one delivery, the rest of the copies duplicates, the secured three
   authenticating at the rig's key. */
void caseOnAirCopiesArriveAtTheSendingDevice(void);
void caseOnAirCopiesArriveAtTheRecordedDestination(void);

/* The diagnostics pool a config names reaches the MAC through the façade: a stack built with one discards a frame
   whose footer does not compute (6.6.2) and leaves the one record that names the claim which refused it in that
   pool, with nothing delivered to the layer above. */
void caseDiscardIsReported(void);

#endif /* STACK_CASES_H */
