/* The `aps` suite's door: what a request is refused for before anything is
   composed (2.2.4.1.1.3's argument errors against Table 2-2's printed ranges) the refusals the standard answers
   through APSDE-DATA.confirm with a Table 2-29 code, and the pool policy seen from the side of the arithmetic. */

#include "aps.h"
#include "aps_helpers.h"
#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * 1. The door matrix (2.2.4.1.1.3's argument errors, Table 2-2's printed ranges).
 *
 * Every one of these is a parameter that contradicts the table, and 2.2.4.1.1.3 answers a contradiction by
 * refusing the primitive rather than by reporting a Status: nothing is queued, nothing is composed, no frame
 * goes on the air, no confirmation is produced, and the refusal is visible only in `refusedRequests` and in the
 * status the call returns. The last one is the door's *count* (the pool policy of docs/internals/coding-rules.md §4.3
 * seen from the side of the arithmetic) and the tail of the case is the option this module cannot honour: Table
 * 2-2's 0x02 asks the network for a protection the network has no key for, and the answer is a composed frame,
 * not a refusal (4.2.2).
 */
void caseDoorMatrix(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    uint16_t nwkFcf;
    uint32_t airCount = 0;
    uint32_t refused;
    uint32_t i;
    static const uint8_t asdu[ASDU_LEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    static const uint8_t mode[] = { 0x04, 0xff };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);

    Test_ExpectStatus(Aps_Init(&rig.aps, 0), ZB_ERR_BAD_ARGUMENT,
                  "a service with no layer to adopt is refused at Init: `aps` adopts `nwk` by pointer and has no other way to reach a radio");
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, 0, 100), ZB_ERR_BAD_ARGUMENT, "and a request that names no parameters at all is refused at the door");

    refused = Aps_RefusedRequests(&rig.aps);
    Test_Expect(refused == 0, "and a refusal the module never reached is not counted: the counter counts requests this module declined");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, 0, 4, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "a length with no octets behind it is the same contradiction `nwk` and `mac` refuse at their own doors (Table 2-2 prints a pointer and a length together, and 0x00 is a length that needs neither)");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 1, "counted once");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, APS_ASDU_LENGTH_MAX + 1, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "an ASDULength above Table 2-2's printed range \"0x00 – 256 * (NsduLength - apscMinHeaderOverhead)\", which is 24576 with apscMinHeaderOverhead 12 (Table 2-23) and NsduLength 108 (Table 3-2 with Table 3-65)");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTIONS_MAX + 1);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "a TxOptions above the bitmap Table 2-2 prints as \"0000 0000 – 0001 1111\"");

    for (i = 0; i < 2; i++)
    {
        req = sapReq(mode[i], ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                     "a DstAddrMode in Table 2-2's reserved band \"0x04 – 0xff\", which is an argument error and not a Status");
    }

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.srcEndpoint = 0xff;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "a SrcEndpoint of the broadcast endpoint: Table 2-2 prints \"0x00 – 0xfe\" for it and 2.2.5.1.6 makes 0xff a destination value alone");

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_RESERVED, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "a destination in Table 3-80's Reserved band (0xfffe), which names neither a device nor a destination group, and the layer below refuses the same address at its own door");

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_RESERVED_LOW, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT, "and the low end of that band, 0xfff8");

    req = sapReq(APS_ADDR_MODE_GROUP, GROUP_ID, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.nwkBroadcastAddress = APS_BROADCAST_ADDRESS_MIN - 1;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "the last nwkBroadcastAddress below the \"0xFFFC - 0xFFFF\" Table 2-2 prints for it: the band's lower edge is the test, and its upper edge is the field's own width");

    req = sapReq(APS_ADDR_MODE_GROUP, GROUP_ID, 0, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "an acknowledged group send: 2.2.5.1.1.5, \"This sub-field SHALL be set to 0 for all frames that are broadcast or multicast\". It is a rule about what a sender may put in a frame, so it is an argument error here and not a status reported after trying (case 9 leans on this refusal)");

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT, "and an acknowledged broadcast, for the same clause");

    req = sapReq(APS_ADDR_MODE_GROUP, GROUP_ID, 0, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_SECURITY);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "a secured group send: 4.4.1 prints no key-selection rule for a group address at all, 4.4.1.1 step 1a-i selects "
                  "\"the security material associated with the destination address of the outgoing frame\" out of `apsDeviceKeyPairSet`, whose entries are keyed by a 64-bit DeviceAddress and, band A's filler, a 16-bit alias, and a group id is neither. It is refused as the contradiction of the request it is: no key looked up, no frame composed, nothing on the air, and (the part that separates it from every other secured refusal) no confirmation");

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_SECURITY);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_BAD_ARGUMENT,
                  "and a secured send to a Table 3-80 broadcast class, for the same reason: the destination is a class of devices and not an entity a key pair is shared with, so 4.4.1 has nothing to select and this module does not invent a selection. Case 26 is the other half of this pair, the group *reception* that is kept deferred");

    Test_Expect(Aps_RefusedRequests(&rig.aps) == 13, "thirteen declines, each counted once and none of them a delivery");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 0,
           "with nothing taken back and nothing answered: 2.2.4.1.1.3 answers an argument error by refusing the primitive, not by reporting a Status");
    Test_Expect(rig.aps.apsCounter == APS_COUNTER_START, "and no APS counter spent: a number is taken for a transmission, and none of these transmitted anything (2.2.5.1.7)");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 0, "with nothing on the air");

    /* The pool's arithmetic, which is where a full pool becomes a refusal a caller can be told about
       (docs/internals/coding-rules.md §4.3): a transaction is either in a slot or answered in the ring and never both, so
       the door counts both. The request below is well-formed in every parameter and refused for capacity alone,
       which is what case 12 reaches from the other side. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);

    for (i = 0; i < APS_TX_MAX; i++)
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "a well-formed request, taken back");

    Test_Expect(Aps_TransmitQueue(&rig.aps) == APS_TX_MAX, "the transaction pool is full at its named bound");

    for (i = 0; i < APS_TX_MAX; i++)
    {
        Test_Expect(rig.aps.tx[i].state == APS_TX_AWAITING_NLDE,
               "and every slot is in the state that says a transmission is owed its NLDE answer (Aps_TxState, docs/internals/coding-rules.md §3)");
    }

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_NO_SPACE,
                  "and the request past it is refused for space, not answered through the ring: the answer it would owe would not fit the confirmation ring the pool is sized to");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 14 && Aps_TransmitQueue(&rig.aps) == APS_TX_MAX,
           "counted, with the pool untouched");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == APS_TX_MAX, "and eight frames went out: the refused request added nothing");

    stepAt(&rig, air, &airCount, 101);
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == APS_CONFIRM_MAX,
           "the eight answers land in the ring and release the eight slots: a transaction is in a slot or answered in the ring and never both, which is the arithmetic the door counts");
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, APS_CONFIRM_MAX) == APS_CONFIRM_MAX,
           "drained, so what follows is judged on its own parameters and not on a full pool");

    /* The option that is not this module's to honour: Table 2-2's 0x02 asks for the network key as the carrier's
       protection, and 4.2.2 hands that decision to the network, which decides from its own state. A device with no
       `Security` attached has no protection to run, so the frame goes out unsecured and the option changes nothing
       about it. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_NWK_KEY);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 101), ZB_OK,
                  "TxOptions 0x02 at a device with no Security attached: the option asks the network and does not supply it (4.2.2), and the network's own state answers it by taking the request back");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 1 && Aps_ConfirmQueue(&rig.aps) == 0,
           "the transaction is held like any other, so its answer comes through the ring rather than back through the door");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 14, "counted as before, because nothing refused");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == APS_TX_MAX + 1, "and one frame went out: the option asked for protection the network has no key for, and an unprotected frame is what the network composes");
    nwkFcf = (uint16_t)(npduOf(&air[APS_TX_MAX])[0] | (npduOf(&air[APS_TX_MAX])[1] << 8));
    Test_Expect(((nwkFcf >> NWK_FRAME_FCF_SECURITY_SHIFT) & NWK_FRAME_FCF_SECURITY_MASK) == 0,
           "with the NWK security sub-field clear, read off the header rather than assumed (4.3.2)");

    stepAt(&rig, air, &airCount, 102);
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 1,
           "the slot is released by its answer, and every counter that moved moved for the reason this case named");
}

/*
 * 2. The refusals the standard answers through APSDE-DATA.confirm (2.2.4.1.1.3, Table 2-29).
 *
 * Each of these is a request this module took back (the call answers ZB_OK, "an answer is coming") and
 * answered there and then with a Table 2-29 code, with no frame on the air and no transaction in a slot. They
 * are the family the door does not belong to: a binding table this device does not have, an address map that
 * does not exist, an alias facility this stack refuses outright, a secured transmission at a device with no
 * provider attached, an ASDU larger than the one frame this slice will write.
 */
void caseConfirmVocabularyRefusals(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    static const uint8_t tooLong[APS_ASDU_MAX + 1] = { 0 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);

    /* DstAddrMode 0x00: the binding-table mode. */
    req = sapReq(APS_ADDR_MODE_NONE, 0, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "a request whose destination is supposed to come from the binding table is taken back: 2.2.4.1.1.3 answers it through the confirm and not through a return code");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].apsStatus == APS_STATUS_NOT_SUPPORTED,
           "answered NOT_SUPPORTED 0xaa, the code Table 2-29 prints for \"a binding table not being supported on the device\", and not NO_BOUND_DEVICE 0xa8, which is the answer of a table that exists and holds no match");
    Test_Expect(confirms[0].attempts == 0 && confirms[0].dstAddrMode == APS_ADDR_MODE_NONE,
           "with no attempt made, because no NLDE transaction was ever issued");

    /* DstAddrMode 0x03: the extended-address mode, mapped through an address map this stack has none of. */
    req = sapReq(APS_ADDR_MODE_EXTENDED, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.dstExtendedAddress = 0x0123456789abcdef;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 101), ZB_OK, "a request addressed by 64-bit extended address");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].apsStatus == APS_STATUS_NO_SHORT_ADDRESS,
           "answered NO_SHORT_ADDRESS 0xa9: 2.2.4.1.1.3 requires the mode be \"mapped to a corresponding 16-bit NWK address by using the nwkAddressMap attribute of the NIB\" and Table 2-29 prints this code for \"no corresponding short address found in the address map table\", Table 3-66 prints nwkAddressMap as \"Null Set\" and no service in this tree reads it");
    Test_Expect(confirms[0].dstExtendedAddress == 0x0123456789abcdef,
           "and the address the caller named travels back in the confirm, so the answer names the request that was made and not a truncated one");

    /* UseAlias: Green Power, refused as the facility `nwk_frame` already refuses. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.useAlias = 1;
    req.aliasSrcAddr = 0x1234;
    req.aliasSeqNumb = 7;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 102), ZB_OK, "a request that asks for an alias");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].apsStatus == APS_STATUS_NOT_SUPPORTED,
           "answered NOT_SUPPORTED. 2.2.4.1.1.3 prints that pairing for the acknowledged combination (\"If the UseAlias parameter has the value of TRUE, and the Acknowledged transmission field of the TxOptions parameter is set to 0b1\") and band A extends it to every alias use, labeled as the extension it is, consistent with `nwk_frame`'s refusal of nwkcProtocolVersion 0x03");

    /* TxOptions 0x01 at a device with no `Security` attached: the crossing is present in the
       module and absent in the application, and 2.2.4.1.1.3 says what that is answered with. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_SECURITY);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 103), ZB_OK, "a request that asks for a secured transmission");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].apsStatus == APS_STATUS_SECURITY_FAIL,
           "answered SECURITY_FAIL 0xad: 2.2.4.1.1.3's own word for a request \"that specifies that secured transmission is required\" whose \"security processing\" fails, and the provider 2.2.5.1.1.4 names is the one thing this device was not given. The same answer a stack that ran no APS security at all gives, and the same answer is the point: the door's group and broadcast refusals are argument errors, this one is the standard's status, reached now because there is no processing to fail rather than because none exists to run");
    Test_Expect(confirms[0].attempts == 0 && confirms[0].dstAddrMode == APS_ADDR_MODE_SHORT
           && confirms[0].dstAddress == ADDR_PEER,
           "answered with no attempt and for the destination the request named, which is the shape every confirm-answered refusal of this SAP has");
    Test_Expect(Aps_TxSecuredFailures(&rig.aps) == 1 && Aps_TxNoKeyPair(&rig.aps) == 0,
           "counted as a security failure and not as a missing pair: the key-pair question was never reached, because there is no module to ask, and the two counters are kept apart precisely so a reader can tell those two refusals from each other (case 25 is the missing-pair leg)");

    /* An ASDU that does not fit one frame. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, tooLong, APS_ASDU_MAX + 1, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 104), ZB_OK, "a request carrying 97 octets of ASDU, inside Table 2-2's printed range and outside what one frame carries");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].apsStatus == APS_STATUS_ASDU_TOO_LONG,
           "answered ASDU_TOO_LONG 0xa0: \"A transmit request failed since the ASDU is too large and fragmentation is not supported\" (Table 2-29), which is the honest terminal answer of a slice that defers fragmentation (2.2.8.4.5) while accepting and ignoring TxOptions 0x08");

    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0, "each answer was taken once and no more was owed");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "and no transaction outlived its answer: a refusal released the slot it never filled");
    Test_Expect(rig.aps.apsCounter == APS_COUNTER_START, "and no APS counter was spent by any of them: the five refusals transmitted nothing (2.2.5.1.7)");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 0, "and none of them is a door refusal: these are counted where the standard counts them, in the confirmation the caller is told to read");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 0, "with nothing on the air for any of the five");
}

/*
 * 12. The pool policy: full is refusal and count (docs/internals/coding-rules.md §4.3).
 *
 * The transaction pool and the confirmation ring are the same number, and a transaction is in one or the other
 * and never both; that arithmetic is what lets this module promise every answer it owes is deliverable. Both
 * halves are shown: eight transactions filling the pool, and eight answers filling the ring.
 */
void casePoolPolicy(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[APS_CONFIRM_MAX + 1];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t i;
    static const uint8_t asdu[ASDU_LEN] = { 0x70, 0x6f, 0x6f, 0x6c, 0x21, 0x00 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    /* Deliberately one request reused eight times and then a ninth time: the only thing that changes about the
       ninth is how many of its kind are already in hand. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);

    for (i = 0; i < APS_TX_MAX; i++)
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "eight well-formed requests, each taken back");

    Test_Expect(Aps_TransmitQueue(&rig.aps) == APS_TX_MAX && Aps_ConfirmQueue(&rig.aps) == 0,
           "the transaction pool full at its named bound, APS_TX_MAX 8: a house size, since 2.2.7 prints no transaction pool at all (Table 2-23's constants are a retry count and a table minimum)");

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_ERR_NO_SPACE,
                  "the ninth is refused for space at the door, where a caller can be told (docs/internals/coding-rules.md §4.3)");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 1 && Aps_TransmitQueue(&rig.aps) == APS_TX_MAX,
           "counted, with the pool untouched and no transaction disturbed to make room for it");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == APS_TX_MAX, "eight frames on the air and not nine");

    stepAt(&rig, air, &airCount, 101);
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == APS_CONFIRM_MAX,
           "the eight answers land in the ring, which is sized to the pool for exactly this arithmetic: a transaction is in a slot or answered in the ring and never both");

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 102), ZB_ERR_NO_SPACE,
                  "and a request made while the *ring* is full is refused too, for the same reason seen from the other side: its answer would not fit");
    Test_Expect(Aps_RefusedRequests(&rig.aps) == 2, "counted again");

    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, APS_CONFIRM_MAX + 1) == APS_CONFIRM_MAX,
           "the ring drains oldest first, and every confirmation the module owed is deliverable: losing one to a full ring is not a policy this module applies");

    for (i = 0; i < APS_CONFIRM_MAX; i++)
    {
        Test_Expect(confirms[i].apsStatus == APS_STATUS_SUCCESS && confirms[i].attempts == 1
               && confirms[i].apsCounter == (uint8_t)i,
               "eight answers for eight transactions, each with the counter it transmitted with: the ring is not a second source of numbers, it reports the numbers the frames carried (2.2.5.1.7)");
    }

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 103), ZB_OK, "and now a ninth request is taken");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == APS_TX_MAX + 1, "one more frame on the air");
    Test_Expect(rig.aps.apsCounter == APS_TX_MAX + 1, "with the ninth counter spent: a refusal spent nothing, so the counters run 0 … 8 across the nine frames this case transmitted");

    stepAt(&rig, air, &airCount, 104);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1 && confirms[0].apsCounter == APS_TX_MAX,
           "answered with that counter");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 0 && Aps_RefusedRequests(&rig.aps) == 2,
           "the module is empty again, holding only the two refusals it counted");
}

/* 2.2.4.1.1.3's binding mode: a request with no destination address is answered by the table, one entry at a time,
   and a device with no table answers NOT_SUPPORTED through the confirm. */
void caseBoundRequest(void)
{
    Rig rig;
    Aps_Binding bindings[APS_BIND_MAX];
    Aps_Indication indication;
    Aps_ApsdeReq req;
    Aps_Confirm confirm;
    Aps_Binding entry;
    uint8_t asdu[4];

    Zb_memset(bindings, 0, (uint32_t)sizeof bindings);
    Zb_memset(asdu, 0x11, (uint32_t)sizeof asdu);

    rigBuild(&rig, OWN_SHORT);

    req = sapReq(APS_ADDR_MODE_NONE, 0, 0, CLUSTER_ID, asdu, (uint32_t)sizeof asdu, 0);

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                      "a mode-0x00 request is answered through the confirm, not a return code");
    Test_ExpectCount(Aps_PollConfirms(&rig.aps, &confirm, 1), 1, "and the confirm is there");
    Test_ExpectCount(confirm.apsStatus, APS_STATUS_NOT_SUPPORTED,
                     "with Table 2-29's NOT_SUPPORTED, this device keeping no binding table");

    Aps_SetBindings(&rig.aps, bindings);

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 200), ZB_OK, "with a table that holds nothing, the search runs");
    Test_ExpectCount(Aps_PollConfirms(&rig.aps, &confirm, 1), 1, "and the confirm is there");
    Test_ExpectCount(confirm.apsStatus, APS_STATUS_NO_BOUND_DEVICE,
                     "with 2.2.4.1.1.3's NO_BOUND_DEVICE");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = CLUSTER_ID;
    entry.dstAddrMode = 0x02;
    entry.dstAddress = ADDR_PEER;
    entry.dstEndpoint = 1;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ILLEGAL,
                     "the destination mode Table 2-6 reserves is ILLEGAL_REQUEST, and never reaches the table");
    Test_ExpectCount(Aps_BindCount(bindings), 0, "so the search still finds nothing");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = 0x00212effff05a888;
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = CLUSTER_ID;
    entry.dstAddrMode = 0x01;
    entry.dstAddress = 0x0011;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ADDED, "an entry sourced by another device");
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 250), ZB_OK,
                      "Table 2-24's mapping keys a device's own frames by the source an entry carries, so this "
                      "device's search still finds nothing");
    Test_ExpectCount(Aps_PollConfirms(&rig.aps, &confirm, 1), 1, "and the confirm is there");
    Test_ExpectCount(confirm.apsStatus, APS_STATUS_NO_BOUND_DEVICE, "with NO_BOUND_DEVICE");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = OWN_IEEE;
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = 0xffff;
    entry.dstAddrMode = 0x01;
    entry.dstAddress = 0x0012;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ADDED,
                     "and an entry for cluster 0xffff, which Table 2-6 prints as an ordinary cluster");
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 260), ZB_OK,
                      "which answers a request for another cluster with nothing, no clause giving a binding table a "
                      "wildcard");
    Test_ExpectCount(Aps_PollConfirms(&rig.aps, &confirm, 1), 1, "and the confirm is there");
    Test_ExpectCount(confirm.apsStatus, APS_STATUS_NO_BOUND_DEVICE, "with NO_BOUND_DEVICE again");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = OWN_IEEE;
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = CLUSTER_ID;
    entry.dstAddrMode = 0x01;
    entry.dstAddress = 0x0011;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ADDED,
                     "a group entry, which Table 2-6 prints without a destination endpoint");

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 300), ZB_OK,
                      "the request is then answered by the entry's own destination");
    Test_ExpectCount(Aps_TransmitQueue(&rig.aps), 1, "as one transaction aimed at the group the entry names");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = OWN_IEEE;
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = CLUSTER_ID;
    entry.dstAddrMode = 0x03;
    entry.dstExtendedAddress = 0x00212effff05a888;
    entry.dstEndpoint = 1;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ADDED,
                      "and an extended entry, which Table 2-6 prints with one");
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 400), ZB_OK, "two entries now answer the same request");
    Test_ExpectCount(Aps_PollConfirms(&rig.aps, &confirm, 1), 1,
                     "2.2.4.1.1.3's mode-0x03 mapping answers for the entry the map does not hold");
    Test_ExpectCount(confirm.apsStatus, APS_STATUS_NO_SHORT_ADDRESS, "with NO_SHORT_ADDRESS");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = OWN_IEEE;
    entry.srcEndpoint = req.srcEndpoint;
    entry.clusterId = CLUSTER_ID;
    entry.dstAddrMode = 0x03;
    entry.dstExtendedAddress = OWN_IEEE;
    entry.dstEndpoint = 4;

    Test_ExpectCount(Aps_BindRequest(&rig.aps, &entry, 1), APS_BIND_ADDED,
                     "and an entry that names this device itself");
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 500), ZB_OK,
                      "2.2.4.1.1.3 issues such an entry as an indication and not as a frame");
    Test_ExpectCount(Aps_TransmitQueue(&rig.aps), 3,
                     "the transactions the three group entries asked for, and no fourth one for the self-entry");
    Test_ExpectCount(Aps_PollIndications(&rig.aps, &indication, 1), 1, "the self-entry is delivered upward");
    Test_ExpectCount(indication.dstEndpoint, 4, "at the endpoint the entry names");
    Test_ExpectCount(indication.clusterId, CLUSTER_ID, "with the cluster the request carried");
}
