/*
 * The interop gate: the captured traffic of a running test network on channel 15, replayed through
 * `mac`, `nwk`, `security` and `aps` on `loopback_radio`, with that network's key arriving as application config, and the same replay run again through
 * the deny-tx shim that makes "strictly passive" a machine-checkable number instead of a promise.
 *
 * Provenance of the fixtures: `test/fixtures/conbee2_ch15_nwksec_hex.txt` (135 PSDUs, the primary) and
 * `test/fixtures/conbee2_ch15_hex.txt` (55 PSDUs, the secondary, an earlier capture on the same PAN) are
 * received-only captures of that test network, channel 15, PAN 0xde20, the ConBee II's
 * `psduIncludesFcs` dialect, so every captured PSDU still carries the two FCS octets the carrier put on the
 * air and `mac`'s own footer check judges them as captured (docs/internals/protocol.md §9.3). The indented raw-PSDU
 * lines are the fixture; the annotation lines are a decoder's output at capture time and this loader ignores
 * them, exactly as harness/check_samples.py reads them (docs/internals/testing.md §4). Nothing was transmitted to make
 * them and nothing here transmits: no RCP is opened by this suite, and Phase D proves the passivity of the
 * wiring that would be.
 *
 * Every ledger number below is the prediction the capture inventory makes for this configuration, counter by
 * counter. Where a number diverges the diagnosis runs in this order: the drive first (the cadence stated at
 * `MS_PER_FRAME` and `RADIO_FRAME_BATCH_MAX`, the rings drained every step), then the stack, and never a
 * parser, the recorded inventory deviations (broadcast APDUs whose APS destination endpoint is 0x00) stay
 * refused as damage, and `aps rxMalformed 4` is that refusal counted.
 *
 * The security crossing adds one duty to this file. The APS security crossing landed on top of the receive sequence
 * this ledger pins, and no APDU in either fixture carries the APS security bit (measured, 79 of 79 and 24 of 24, the
 * same measurement recorded here), so the pinned numbers are now a regression gate on the crossing as well as on `mac`,
 * `nwk` and `security`: a number that moves here moved because 4.4.1.1 or 4.4.1.2 changed what a fixture frame was, and
 * the diagnosis order is unchanged (the drive first, then the stack, never a parser). The APS columns named
 * `Aps_TxNoKeyPair`, `Aps_TxSecuredFailures`, `Aps_RxSecuredFailuresAuth` and `Aps_RxSecuredFailuresCounters` are
 * pinned at zero for the same reason: they are the crossing's own counters, and a replay of traffic it never touches is
 * exactly the run in which they must not move.

   The suite is four phases and this is the one header that names what they prove: every case `main` drives is
   declared here, in the order it drives them, so the run order (the fixtures read, then the primary replay,
   then the secondary, then the three composed failure legs, then the same replay through the shim) is
   readable in one place. The pinned numbers travel with the phase that pins them, and the machinery two of
   them share is `interop_helpers.h` beside it. */

#ifndef INTEROP_CASES_H
#define INTEROP_CASES_H

void phaseA(void);
void phaseB(void);
void phaseC(void);
void phaseD(void);

#endif /* INTEROP_CASES_H */
