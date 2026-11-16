/* Suite for band A's persistence boundary: the plain C state object
   `zb_state` captures over the four layers and reads back, the six rules that entry makes binding (the
   counts are authoritative, an entry is identified by content and not by index, key material is opt-in per
   entry, a restore validates the whole set before it writes anything, a restored counter only moves forward
   by the named bank, and every tail past a count is zero) and the small module operation the security side
   needed to be restorable at all.

   A suite is a name and a ledger, not a file: this header declares every case `main` drives, in the order the
   ledger records, so the run order is readable in one place. The machinery the cases share (the device with
   its four layers, the three entry builders and the byte image a refusal is judged against) is
   `state_helpers.h` beside it.

   Runs on the band-A rig over the hardware-free backend, so no Spinel, HDLC, property id, wall clock or radio
   appears anywhere in it, and every case drives the modules directly: the persistence boundary needs no air,
   so three of the four layers are configured, one frame is sent where a counter has to move by traffic, and
   the rest of the suite is the object itself. */

#ifndef STATE_CASES_H
#define STATE_CASES_H

/* The object a capture fills, over a freshly initialised stack: the schema, the flags, the three counted
   sets, the three sequence numbers, and key material absent by default and present on request. */
void caseCaptureFresh(void);

/* What a count is *for*: fewer entries than the pool, so every tail is zero even when the caller's object
   arrived full of something else. */
void caseCaptureCounts(void);

/* A 0 in any of the five pointers, on either operation, writes nothing and answers a bad argument. */
void caseArgumentRefusals(void);

/* Capture, disturb by traffic, restore: the module answers the captured values again, the wipe leaves no
   window of the disturbed boot behind, and the key the object did not carry is still there. */
void caseRoundTrip(void);

/* The counts are authoritative: a count above the compile-time bound is refused rather than truncated, with
   the module byte-identical afterwards. */
void caseCountsAuthoritative(void);

/* An entry is identified by content: the application may permute the descriptor and window lists. */
void caseIdentityNotIndex(void);

/* A schema number this build does not know is refused, with nothing touched. */
void caseVersionRefused(void);

/* One name twice (two keys with one sequence number, two windows with one sender, two pairs with one
   device) is refused before any write. */
void caseDuplicatesRefused(void);

/* A window with no sender or a pair with no device address is malformed, not an entry at address 0. */
void caseZeroNamesRefused(void);

/* Restored counters only move forward: by ZB_STATE_COUNTER_BANK, every time the same state is restored. */
void caseCountersMoveForward(void);

/* Key material is opt-in: a state that carried no key restores the counters and leaves the key this boot was
   configured with, proved by protecting the `security` suite's vector frame. */
void caseKeysOptIn(void);

/* The two halves of the same rule: an entry with no key of its own and no key this boot holds is refused
   with ZB_ERR_AUTH, and a state whose active sequence number names no descriptor it carries is refused. */
void caseKeyWithoutDescriptorRefused(void);

/* A stored counter within the bank of 2^32-1: refused rather than wrapped, and the boundary that lands
   exactly 2^32-1 restores and then refuses to transmit (4.3.1.1 step 1). */
void caseCounterBankOverflow(void);

/* What the object does not hold is not wiped: the neighbour table and the group table survive a restore,
   while the three counters it does hold are written. */
void caseTablesNotWiped(void);

/* A restored end device child is given its full Device Timeout from the first turn after the restore (3.6.10.8). */
void caseChildRestoredWithAFullPeriod(void);

/* Security_Restore's own refusals at the module level: its bounds, its duplicates, its key-pair gate, and
   that each of them leaves the module byte-identical. */
void caseSecurityRestoreRefusals(void);

/* NIB 0xBE's routing sequence number is the object's: Table 3-66 marks it as persisting, so a capture carries
   it and a restore writes it. */
void caseRoutingSequenceRoundTrip(void);

/* And it only moves forward: a captured number below the one this boot reached does not lower it, and the one
   step reduces by the 0x10000 wrap the module's own increment takes. */
void caseRoutingSequenceForwardOnly(void);

/* A number at or above its wrap is refused with ZB_ERR_BAD_ARGUMENT before the first write, leaving both the
   module and that number as they were. */
void caseRoutingSequenceRefused(void);

/* A trust centre's own capture, the global key's entry naming no device among its pairs, is restored (4.4.12.1). */
void caseGlobalPairRoundTrip(void);

/* A restored trust centre is one still: its address comes back with the state, and its transport-key policy and
   link-key seed are this boot's configuration, which a wipe would otherwise take. */
void caseTrustCentreConfigurationKept(void);

/* apsTrustCenterAddress is the state's (4.4.12.1): captured, and restored over the boot's. */
void caseTrustCentreAddressPersisted(void);

/* The extended PAN goes in and out in the order the join holds it: least significant octet first. */
void caseExtendedPanOctetOrder(void);

/* The state names its role, and a boot of another role, or an end device's state naming no parent, is refused. */
void caseRoleMustMatch(void);

/* An end device restored on a boot with no address is joined again, its parent back in the neighbour table. */
void caseEndDeviceComesBackJoined(void);

/* A restore maps the pairs the state names: the trust centre at 0x0000 in a centralized network, the parent, the
   children, so a bound 64-bit destination resolves before any frame has taught the map (2.2.4.1.1.3). */
void caseAddressMapSeededFromTheState(void);

#endif /* STATE_CASES_H */
