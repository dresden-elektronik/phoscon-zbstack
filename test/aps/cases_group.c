/* The `aps` suite's group sends: the mode that changes the header and the
   address the frame is aimed at, the fan-out every member is handed, and the group services of 2.2.4.5. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * 10. A group send: the mode that changes the header and the address the frame is aimed at
 * (2.2.4.1.1.3, 2.2.5.1.3, 2.2.8.4.1, Table 2-2).
 *
 * "This address will be placed in the group address field of the APS header … The nwkBroadcastAddress passed to
 * the APSDE-DATA.request primitive SHALL be passed to the NLDE-DATA.request primitive", and where the request
 * states none 2.2.8.4.1 prints the one to employ: "employing a broadcast address of 0xfffd". The group id never
 * rides the NWK header, and the confirm echoes the group id and not the class the frame was aimed at.
 */
void caseGroupSend(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    Aps_Frame frame;
    uint8_t wanted[APS_FRAME_MAX];
    uint32_t wantedLen;
    uint32_t wantedOffset;
    uint32_t airCount = 0;
    uint32_t i;
    static const uint8_t asdu[ASDU_LEN] = { 0x67, 0x72, 0x6f, 0x75, 0x70, 0x21 };

    rigBuild(&rig, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_GROUP, GROUP_ID, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.dstEndpoint = DST_EP;     /* present in the struct and ignored by the module, which is 2.2.4.1.1.3's own word: "the DstEndpoint parameter will be ignored, and the destination endpoint field will be omitted from the APS header" */

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "a request addressed to a group");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame");
    Test_Expect(airDestOf(&air[0]) == NWK_ADDR_ALL_DEVICES,
           "with the MAC's broadcast address 0xffff in the destination field, which is what R23.1 3.2.1.1.3 step 6 a.3 makes of any of Table 3-80's classes");
    Test_Expect(npduOf(air)[2] == (uint8_t)(APS_NWK_BROADCAST_GROUP_DEFAULT & 0xff)
           && npduOf(air)[3] == (uint8_t)(APS_NWK_BROADCAST_GROUP_DEFAULT >> 8),
           "and the address 2.2.8.4.1 prints for a group transmission when the request states none (0xfffd, Table 3-80's macRxOnWhenIdle class, band A's named default and not a value this module invented) in the NWK header's destination field, low octet first as 3.3 orders a multi-octet field: the group id rides the APS header and never the NWK header");

    dataHeader(&frame, APS_DELIVERY_GROUP, 0, 0, DST_EP, CLUSTER_ID);
    Test_ExpectStatus(ApsFrame_Compose(&frame, asdu, ASDU_LEN, wanted, (uint32_t)sizeof wanted, &wantedLen, &wantedOffset), ZB_OK,
                  "the case composes the group form through the codec");
    Test_Expect(wantedLen == APS_HEADER_GROUP_FORM + ASDU_LEN && ApsFrame_HeaderLen(&frame) == APS_HEADER_GROUP_FORM,
           "nine octets of header plus the ASDU");

    Test_Expect(apduLenOf(&air[0]) == wantedLen && Zb_memcmp(apduOf(&air[0]), wanted, wantedLen) == 0,
           "and the APDU on the air is it octet for octet");
    Test_Expect(apduOf(&air[0])[0] == APS_FCF_DATA_GROUP,
           "FCF 0x0c: delivery mode 0b11, group addressing (Table 2-21)");
    Test_Expect(apduOf(&air[0])[1] == (uint8_t)(GROUP_ID & 0xff) && apduOf(&air[0])[2] == (uint8_t)(GROUP_ID >> 8),
           "the group address as the header's second field, low octet first (2.2.5.1.3: \"16 bits in length\")");
    Test_Expect(apduOf(&air[0])[APS_COUNTER_OCTET_GROUP] == 0,
           "and the counter one octet further than a unicast's, because the group form has no destination endpoint: 2.2.8.4.1, group transmissions \"SHALL contain a source endpoint field and group address field, but no destination endpoint field\" (2.2.5.1.3 states the same from the field side)");

    stepAt(&rig, air, &airCount, 101);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1 && confirms[0].apsStatus == APS_STATUS_SUCCESS,
           "SUCCESS on the NLDE confirmation, with no acknowledgement owed for a group frame (2.2.8.4.3)");
    Test_Expect(confirms[0].dstAddrMode == APS_ADDR_MODE_GROUP && confirms[0].dstAddress == GROUP_ID,
           "and the confirm echoes the group id Table 2-2 says DstAddress *is* for that mode, not the class the frame was aimed at: conflating them would describe a frame this stack did not send");

    req = sapReq(APS_ADDR_MODE_GROUP, GROUP_ID, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.nwkBroadcastAddress = NWK_ADDR_ALL_DEVICES;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 102), ZB_OK,
                  "the same group with an explicit nwkBroadcastAddress, which Table 2-2 permits in \"0xFFFC - 0xFFFF\" and 2.2.4.1.1.3 requires be passed to the NLDE");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 2, "one frame");
    Test_Expect(airDestOf(&air[1]) == NWK_ADDR_ALL_DEVICES && npduOf(&air[1])[2] == 0xff && npduOf(&air[1])[3] == 0xff,
           "aimed at 0xffff now, in the MAC destination and in the NWK header both: the parameter wins over the default where the request states one");
    Test_Expect(apduLenOf(&air[1]) == wantedLen && apduOf(&air[1])[0] == APS_FCF_DATA_GROUP
           && Zb_memcmp(apduOf(&air[1]) + 1, wanted + 1, APS_COUNTER_OCTET_GROUP - 1) == 0,
           "while every other octet of the APDU is the same group frame, the NWK destination an APS header names nothing about (2.2.5.1.3: the group address is the only address an APS header carries)");
    Test_Expect(apduOf(&air[1])[APS_COUNTER_OCTET_GROUP] == 1 && wanted[APS_COUNTER_OCTET_GROUP] == 0,
           "and the one octet that differs is the counter: the second transaction, the second counter (2.2.5.1.7)");

    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1 && confirms[0].dstAddress == GROUP_ID, "answered, for the group it was addressed to");

    for (i = 0; i < 2; i++)
    {
        Test_Expect(rig.aps.tx[i].state == APS_TX_FREE, "and both slots released");
    }
}

/*
 * 16. Group fan-out: the group table decides acceptance, and every member gets its own primitive
 * (2.2.8.3, 2.2.8.4.2, Table 2-25).
 *
 * The device under test holds two endpoints in one group and nothing in another. The frame for the first becomes
 * two indications that differ in exactly one field, because 2.2.8.4.2 ends its fan-out with the rule that makes a
 * fan-out reportable at all: "All other parameters of the NLDE-DATA.indication primitive SHALL remain the same for
 * all instances of the primitive issued." The frame for the second group becomes nothing at all, and the counter
 * it lands in is the group table saying this device is not a member; 2.2.8.3's "delivered selectively to those
 * endpoints that are associated in the table with a particular group" read as the acceptance rule it is.
 */
void caseGroupFanOut(void)
{
    Rig rig;
    Rig a;
    Air air[AIR_LOG_MAX];
    Air airA[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Indication inds[4];
    uint32_t airCount = 0;
    uint32_t airCountA = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x66, 0x61, 0x6e, 0x6f, 0x75, 0x74 };
    static const uint16_t held = 0x0002;
    static const uint16_t unheld = 0x0003;

    rigBuild(&rig, OWN_SHORT);
    rigBuild(&a, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&a.stack.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);

    Test_Expect(Aps_AddGroup(&rig.aps, held, 0x03) == APS_STATUS_SUCCESS, "this device puts endpoint 3 in group 0x0002 (2.2.4.5.1)");
    Test_Expect(Aps_AddGroup(&rig.aps, held, 0x07) == APS_STATUS_SUCCESS, "and endpoint 7 in the same group");
    Test_Expect(Aps_GroupQueue(&rig.aps) == 2, "two pairs in the table, which is Table 2-25's group with a two-endpoint list");

    req = sapReq(APS_ADDR_MODE_GROUP, held, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK, "A addresses the group");

    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 2,
           "and this device issues one indication for every endpoint the table associates with that group id: \"it SHALL deliver the frame to each endpoint on the device that is associated in the group table with the 16-bit group address found in the group address field of the APS header\"");

    got = Aps_PollIndications(&rig.aps, inds, 4);
    Test_Expect(got == 2, "both of them, oldest first, and nothing further");
    Test_Expect(inds[0].dstEndpoint == 0x03 && inds[1].dstEndpoint == 0x07,
          "DstEndpoint is the member endpoint in each instance: 0x03 then 0x07, in the order the pool holds them, which is 2.2.8.3.1's license (\"free to implement the group table in any manner that is convenient and efficient\") paid for with an order this suite can name");

    /* Every other parameter of the two instances, compared against each other rather than against the case's own
       constants: the clause's rule is that the instances agree, and the only way to assert agreement is to read
       both of them. */
    Test_Expect(inds[0].dstAddrMode == APS_ADDR_MODE_GROUP && inds[1].dstAddrMode == APS_ADDR_MODE_GROUP,
          "DstAddrMode 0x01 for both: Table 2-2's words for the mode are \"16-bit group address for DstAddress; DstEndpoint not present\", and Table 2-4 prints the same code for the indication");
    Test_Expect(inds[0].dstAddress == held && inds[1].dstAddress == held,
          "DstAddress is the group id out of the APS header for both (2.2.8.4.2), and not the 0xfffd class the frame was broadcast with: the group id never rides the NWK header, so this is the only place it can be reported from");
    Test_Expect(inds[0].srcAddrMode == inds[1].srcAddrMode
           && inds[0].srcAddress == inds[1].srcAddress && inds[0].srcEndpoint == inds[1].srcEndpoint,
          "\"All other parameters … SHALL remain the same\": the source triple, identical");
    Test_Expect(inds[0].srcAddrMode == APS_ADDR_MODE_SHORT && inds[0].srcAddress == ADDR_PEER
           && inds[0].srcEndpoint == SRC_EP,
          "and stated once for both, since they agree: SrcAddrMode 0x02 with the NWK source of the indication and the source endpoint the frame carried, which a group transmission always carries (2.2.8.4.1: group transmissions \"SHALL contain a source endpoint field and group address field, but no destination endpoint field\")");
    Test_Expect(inds[0].profileId == inds[1].profileId && inds[0].clusterId == inds[1].clusterId
           && inds[0].profileId == PROFILE_ID && inds[0].clusterId == CLUSTER_ID,
          "ProfileId and ClusterId, identical");
    Test_Expect(inds[0].asduLength == inds[1].asduLength
           && Zb_memcmp(inds[0].asdu, inds[1].asdu, inds[0].asduLength) == 0
           && inds[0].asduLength == ASDU_LEN && Zb_memcmp(inds[0].asdu, asdu, ASDU_LEN) == 0,
          "the same ASDU in both, copied twice rather than one buffer shared between two indications a caller keeps");
    Test_Expect(inds[0].status == inds[1].status && inds[0].status == APS_STATUS_SUCCESS
           && inds[0].securityStatus == inds[1].securityStatus
           && inds[0].securityStatus == APS_STATUS_UNSECURED
           && inds[0].linkQuality == inds[1].linkQuality && inds[0].keyIndex == inds[1].keyIndex,
          "Status, SecurityStatus, LinkQuality and KeyIndex, identical in both instances");

    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0,
           "and no acknowledgement for a group frame, which is 2.2.5.1.1.5's prohibition on the ask carried through to the answer it would have obliged: 2.2.8.4.3 makes a broadcast or multicast frame unowed, and this device is one member of a group and not the intended recipient of a unicast");
    Test_Expect(Aps_DroppedGroupMiss(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
           "nothing was a miss and nothing was refused for room, whatever the fan-out cost");

    stepAt(&a, airA, &airCountA, 102);

    req = sapReq(APS_ADDR_MODE_GROUP, unheld, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 110), ZB_OK, "the same kind of frame, for a group id this device holds no endpoint in");
    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 111);

    Test_Expect(Aps_DroppedGroupMiss(&rig.aps) == 1,
           "the group table decides acceptance: two indications for a group with two members and none for a group with none, which is 2.2.8.3's \"delivered selectively\" and the whole reason the table exists");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0,
           "nothing was indicated for it and nothing was answered for it");
    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 0 && Aps_RxMalformed(&rig.aps) == 0
           && Aps_RxShapeRefused(&rig.aps) == 0,
           "and it is not counted as a duplicate, as damage or as a refused shape either: it was a well-formed group frame for a group this device is not in, and the counter that says so is the group table's own");
}

/*
 * 17. The group services, and the statuses Tables 2-14 … 2-19 print (2.2.4.5).
 *
 * No frames here: the three APSME requests are answered in place, and the return value *is* the Status parameter
 * of the confirm each of them prints. What the case pins down is the difference between the answers (a parameter
 * outside the printed range, a pool with no room, a pair the table does not hold, and a repeated add that changes
 * nothing): four outcomes the tables name with four different codes, one of which is not a failure at all.
 */
void caseGroupServiceMatrix(void)
{
    Rig rig;
    uint32_t i;
    static const uint16_t base = 0x0100;

    rigBuild(&rig, OWN_SHORT);

    Test_Expect(Aps_GroupQueue(&rig.aps) == 0, "a fresh module holds the table Table 2-24 prints as its default: \"Null set\"");

    Test_Expect(Aps_AddGroup(&rig.aps, 0x0001, 0x00) == APS_STATUS_INVALID_PARAMETER,
           "endpoint 0x00 is refused: Table 2-14 prints Endpoint as \"0x01 – 0xfe\", and 0x00 is the ZDO, which is a device's object and not a member of a group");
    Test_Expect(Aps_AddGroup(&rig.aps, 0x0001, 0xff) == APS_STATUS_INVALID_PARAMETER,
           "and so is 0xff: the broadcast endpoint names every endpoint at once, which is not a thing one group table entry can be");
    Test_Expect(Aps_RemoveAllGroups(&rig.aps, 0x00) == APS_STATUS_INVALID_PARAMETER,
           "APSME-REMOVE-ALL-GROUPS judges the same parameter against the same range (Table 2-18, which 2.2.4.5.5.3's first sentence answers with INVALID_PARAMETER)");
    Test_Expect(Aps_RemoveAllGroups(&rig.aps, 0xff) == APS_STATUS_INVALID_PARAMETER, "and the same at the top of the range");
    Test_Expect(Aps_GroupRefusals(&rig.aps) == 4 && Aps_GroupQueue(&rig.aps) == 0,
           "four refusals counted, none of them a delivery, and the table untouched by all four");

    for (i = 0; i < APS_GROUP_MAX; i++)
        Test_Expect(Aps_AddGroup(&rig.aps, (uint16_t)(base + i), 0x03) == APS_STATUS_SUCCESS,
               "sixteen distinct pairs, each accepted");

    Test_Expect(Aps_GroupQueue(&rig.aps) == APS_GROUP_MAX, "the group table full at its named bound");

    Test_Expect(Aps_AddGroup(&rig.aps, 0x0200, 0x04) == APS_STATUS_TABLE_FULL,
           "and the seventeenth answered TABLE_FULL 0xae, Table 2-29: \"An APSME-BIND.request or APSME.ADD-GROUP.request issued when the binding or group tables, respectively, were full\", which 2.2.4.5.1.3 words as \"no room in the group table for another entry\"");
    Test_Expect(Aps_GroupQueue(&rig.aps) == APS_GROUP_MAX,
           "with the pool untouched: nothing was evicted to make room, because the entries are the members 2.2.8.4.2 delivers to and dropping one of this device's own memberships in order to take on another is a decision no clause of 2.2.4.5 or 2.2.8.3 prints (docs/internals/coding-rules.md §4.3, stated at `Aps_AddGroup`)");

    Test_Expect(Aps_AddGroup(&rig.aps, base, 0x03) == APS_STATUS_SUCCESS,
           "a duplicate add is SUCCESS, 2.2.4.5.1.3: \"If there is an entry for the given GroupAddress and Endpoint parameters in the group table then the APSME does not alter the group table … The APSME then issues the APSME-ADD-GROUP.confirm primitive to the next higher layer with a status value of SUCCESS\"");
    Test_Expect(Aps_GroupQueue(&rig.aps) == APS_GROUP_MAX,
           "and the queue did not move, which is the half of that sentence a caller can observe: the add is idempotent and not a second entry");

    Test_Expect(Aps_RemoveGroup(&rig.aps, 0x0300, 0x03) == APS_STATUS_INVALID_GROUP,
           "removing a pair the table does not hold answers INVALID_GROUP 0xa5, Table 2-29 in its own words: \"An APSME-REMOVE-GROUP.request has been issued with a group identifier that does not appear in the group table\", and not INVALID_PARAMETER, which 2.2.4.5.3.3 reserves for the parameters it checks before it looks at the table at all");
    Test_Expect(Aps_RemoveGroup(&rig.aps, base, 0x04) == APS_STATUS_INVALID_GROUP,
           "nor the right group with the wrong endpoint: the pair is the entry, and Table 2-16's primitive names both halves of it");

    Test_Expect(Aps_RemoveAllGroups(&rig.aps, 0x03) == APS_STATUS_SUCCESS,
           "APSME-REMOVE-ALL-GROUPS on the endpoint all sixteen pairs share");
    Test_Expect(Aps_GroupQueue(&rig.aps) == 0, "and every pair carrying it is gone, which is 2.2.4.5.5.3's \"remove all entries related to this endpoint from the group table\"");

    Test_Expect(Aps_AddGroup(&rig.aps, 0x0002, 0x03) == APS_STATUS_SUCCESS
           && Aps_AddGroup(&rig.aps, 0x0002, 0x07) == APS_STATUS_SUCCESS
           && Aps_AddGroup(&rig.aps, 0x0003, 0x03) == APS_STATUS_SUCCESS
           && Aps_AddGroup(&rig.aps, 0x0004, 0x09) == APS_STATUS_SUCCESS,
           "a mixed table to judge the removal against: one group with two endpoints, one endpoint in two groups, and one endpoint on its own");

    Test_Expect(Aps_RemoveAllGroups(&rig.aps, 0x03) == APS_STATUS_SUCCESS && Aps_GroupQueue(&rig.aps) == 2,
           "removing endpoint 3 takes it out of both groups and leaves the other two pairs where they were");
    Test_Expect(Aps_RemoveGroup(&rig.aps, 0x0002, 0x03) == APS_STATUS_INVALID_GROUP
           && Aps_RemoveGroup(&rig.aps, 0x0003, 0x03) == APS_STATUS_INVALID_GROUP,
           "exactly the pairs with that endpoint are gone: asserted by the table's own answer to a removal attempt, which is the observable form of \"all entries related to this endpoint\"");
    Test_Expect(Aps_RemoveGroup(&rig.aps, 0x0002, 0x07) == APS_STATUS_SUCCESS
           && Aps_RemoveGroup(&rig.aps, 0x0004, 0x09) == APS_STATUS_SUCCESS,
           "and exactly the pairs without it are still there, each removed successfully and each therefore present");
    Test_Expect(Aps_GroupQueue(&rig.aps) == 0 && Aps_GroupRefusals(&rig.aps) == 5,
           "the table ends empty, and the fifth refusal counted is the one TABLE_FULL the full pool answered: INVALID_GROUP is not a refusal of the pool and is not counted as one (see `groupRefusals`)");
}

/*
 * 18. A group frame for a group this device holds no endpoint in: dropped, or delivered once for the application to
 * filter (2.2.8.3, 2.2.8.4.2).
 *
 * The clause delivers "to each endpoint on the device that is associated in the group table" and prints no other
 * arm, so the drop is the clause and the delivery is this stack's own: one indication, at the broadcast endpoint,
 * with the group id where the application can read it. What the case pins is that the two arms are exclusive and
 * that a member's frame is never doubled.
 */
void caseGroupDeliveryUnfiltered(void)
{
    Rig rig;
    Rig a;
    Air air[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Indication inds[4];
    uint32_t airCount = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x66, 0x61, 0x6e, 0x6f, 0x75, 0x74 };
    static const uint16_t stranger = 0x0004;
    static const uint16_t held = 0x0005;

    rigBuild(&rig, OWN_SHORT);
    rigBuild(&a, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&a.stack.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);

    Test_ExpectCount(Aps_GroupDelivery(&rig.aps), APS_GROUP_DELIVERY_MEMBERS,
                     "a service that was not asked delivers to the table's members and to nothing else");

    req = sapReq(APS_ADDR_MODE_GROUP, stranger, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK, "A addresses a group this device holds nothing in");
    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 101);

    Test_ExpectCount(Aps_DroppedGroupMiss(&rig.aps), 1, "the member arm drops it and counts the miss");
    Test_ExpectCount(Aps_IndicationQueue(&rig.aps), 0, "with nothing indicated");

    Aps_SetGroupDelivery(&rig.aps, APS_GROUP_DELIVERY_UNFILTERED);

    Test_ExpectCount(Aps_GroupDelivery(&rig.aps), APS_GROUP_DELIVERY_UNFILTERED,
                     "an application that filters its own group traffic asks for the other arm");
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 110), ZB_OK, "and the same frame comes again");
    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 111);

    Test_ExpectCount(Aps_GroupDeliveredUnfiltered(&rig.aps), 1, "delivered once");
    Test_ExpectCount(Aps_DroppedGroupMiss(&rig.aps), 1, "and no longer a miss");
    Test_ExpectCount(Aps_IndicationQueue(&rig.aps), 1, "one indication and not one per endpoint the device has");

    got = Aps_PollIndications(&rig.aps, inds, 4);

    Test_ExpectCount(got, 1, "taken once");
    Test_ExpectCount(inds[0].dstAddrMode, APS_ADDR_MODE_GROUP, "with the group mode the frame was addressed by");
    Test_ExpectCount(inds[0].dstAddress, stranger, "the group id, which is what the application filters on");
    Test_ExpectCount(inds[0].dstEndpoint, APS_ENDPOINT_BROADCAST,
                     "and the broadcast endpoint where a member's frame would name the member");

    Test_Expect(Aps_AddGroup(&rig.aps, held, 0x03) == APS_STATUS_SUCCESS, "the device joins a group with one endpoint");
    req = sapReq(APS_ADDR_MODE_GROUP, held, 0, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 120), ZB_OK, "A addresses it");
    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 121);

    Test_ExpectCount(Aps_IndicationQueue(&rig.aps), 1, "a member's frame is delivered once, not twice");
    got = Aps_PollIndications(&rig.aps, inds, 4);
    Test_ExpectCount(got, 1, "the one indication");
    Test_ExpectCount(inds[0].dstEndpoint, 0x03, "and it names the member endpoint, as the clause prints it");
    Test_ExpectCount(Aps_GroupDeliveredUnfiltered(&rig.aps), 1, "with the stranger arm left where it was");

    Aps_SetGroupDelivery(&rig.aps, 0x7f);

    Test_ExpectCount(Aps_GroupDelivery(&rig.aps), APS_GROUP_DELIVERY_MEMBERS,
                     "a value outside the two is the clause's arm, not a third behaviour");
}
