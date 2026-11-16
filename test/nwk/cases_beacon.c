/* The `nwk` suite's beacon half: R23.1 3.6.8's beacon payload (Table 3-83's fields in Figure 3-53's bit order)
   and the one rule that decides which device answers a Beacon Request at all (D.11.1.5: coordinators and
   routers, and nobody else). */

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* Short addresses this suite rigs devices with, from `nwk_helpers.h`'s own set. */
#define BEACON_COORDINATOR_SHORT 0x0000
#define BEACON_ROUTER_SHORT 0x1234

/* 7.5.2's Beacon Request, ten octets with its footer: command type, short destination, no source address, AR
   clear, the broadcast PAN and the broadcast short address. */
static uint32_t composeBeaconRequest(uint8_t *out, uint8_t seq)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_BEACON_REQUEST };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_NONE;
    frame.destPan = MAC_FRAME_PAN_BROADCAST;
    frame.destShort = MAC_FRAME_ADDR_BROADCAST;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "a Beacon Request composes (7.5.2)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its own footer");

    return len;
}

static void injectRaw(Loopback_Radio *model, const uint8_t *bytes, uint32_t len, uint64_t stamp)
{
    Loopback_FrameSpec spec;

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -94;
    spec.lqi = 200;
    spec.stampTicks = stamp;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(model, &spec, 1), ZB_OK, "the request is put in front of the device");
}

static void beaconInfoOf(Nwk_BeaconInfo *info)
{
    Zb_memset(info, 0, (uint32_t)sizeof *info);

    info->stackProfile = NWK_BEACON_STACK_PROFILE;
    info->protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info->routerCapacity = 1;
    info->deviceDepth = 0;
    info->endDeviceCapacity = 1;
    info->extendedPanId = ((uint64_t)0x11223344 << 32) | 0x55667788;
    info->txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info->updateId = 0;
}

/* Table 3-83's fifteen octets, octet by octet, against the values R23.1's own worked beacon prints for the
   fields it shares with it. */
/* 7.3.1.4's Superframe Specification, whose bit 15 is the Association Permit of the beacon on the air. */
static int beaconPermitBitOf(const Loopback_Sent *sent)
{
    Mac_Frame frame;
    MacFrame_Beacon beacon;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen;

    Test_Expect(MacFrame_Parse(sent->bytes, sent->len, 1, &frame, &payloadOut, &payloadOutLen, 0) == ZB_OK,
                "the beacon parses");
    Test_Expect(MacFrame_ParseBeaconPayload(payloadOut, payloadOutLen, &beacon, &payloadOut, &payloadOutLen) == ZB_OK,
                "and its body reads");

    return beacon.associationPermit;
}

void caseBeaconInfoOctets(void)
{
    Nwk_BeaconInfo info;
    Nwk_BeaconInfo readBack;
    uint8_t bytes[NWK_BEACON_INFO_LEN];
    uint8_t small[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    uint32_t len = 0;

    beaconInfoOf(&info);

    Test_ExpectStatus(Nwk_ComposeBeaconInfo(&info, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "the beacon payload composes");
    Test_Expect(len == NWK_BEACON_INFO_LEN, "at fifteen octets (Figure 3-53's 120 bits)");
    Test_Expect(bytes[0] == 0x00, "protocol identifier zero, which Table 3-83 pins for Zigbee");
    Test_Expect(bytes[1] == 0x22, "stack profile 0x2 beside protocol version 0x2, as R23.1's worked beacon prints");
    Test_Expect(bytes[2] == 0x84,
                "router capacity at bit 18 and end-device capacity at bit 23 with a zero depth: 0x84, which is the "
                "value Figure 3-53's own bit positions give and not the 0x88 the worked example's line prints");
    Test_Expect(bytes[3] == 0x88 && bytes[4] == 0x77 && bytes[5] == 0x66 && bytes[6] == 0x55,
                "the extended PAN identifier least significant octet first");
    Test_Expect(bytes[11] == 0xff && bytes[12] == 0xff && bytes[13] == 0xff,
                "TxOffset 0xFFFFFF, the value Table 3-83 names for beaconless networks");
    Test_Expect(bytes[14] == 0x00, "and the update id last");

    Test_ExpectStatus(Nwk_ParseBeaconInfo(bytes, len, &readBack), ZB_OK, "and it reads back");
    Test_Expect(readBack.stackProfile == 2 && readBack.protocolVersion == 2 && readBack.routerCapacity == 1
                && readBack.deviceDepth == 0 && readBack.endDeviceCapacity == 1,
                "field for field");
    Test_Expect(readBack.extendedPanId == info.extendedPanId && readBack.txOffset == NWK_BEACON_TX_OFFSET_NONE
                && readBack.updateId == 0,
                "the extended PAN identifier, the TxOffset and the update id intact");

    Test_ExpectStatus(Nwk_ComposeBeaconInfo(&info, small, (uint32_t)sizeof small, &len), ZB_ERR_NO_SPACE,
                      "a buffer that cannot hold fifteen octets is no space");
    Zb_memset(&readBack, 0xff, (uint32_t)sizeof readBack);

    Test_ExpectStatus(Nwk_ParseBeaconInfo(bytes, 14, &readBack), ZB_OK,
                      "and a span one octet short is a beacon without the appendix, which 3.6.8.1 makes a Revision 23 device accept");
    Test_Expect(readBack.stackProfile == 0 && readBack.protocolVersion == 0 && readBack.routerCapacity == 0
                && readBack.deviceDepth == 0 && readBack.endDeviceCapacity == 0 && readBack.extendedPanId == 0,
                "with every field of the appendix at its zero, which is what an absent one says");
}

/* Which device answers. R23.1 D.11.1.5 obliges coordinators and routers; an end device that is nobody's parent
   has no answer to give, and the MAC it was given says so by holding no payload. */
void caseOnlyAParentAnswersABeaconRequest(void)
{
    Test_BandA dev;
    Nwk_BeaconInfo info;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    uint8_t request[RADIO_MPDU_MAX];
    uint32_t len;
    Mac_Counters counters;

    beaconInfoOf(&info);

    rig(&dev, BEACON_COORDINATOR_SHORT, PAN_ID);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 1), ZB_OK, "a coordinator takes the beacon payload");

    len = composeBeaconRequest(request, 0x31);
    injectRaw(&dev.model, request, len, 5000);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "and a request that arrives is stepped");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconReplies == 1, "and answered");

    /* A router answers too (D.11.1.5 names both kinds) and states that it is not the PAN coordinator. */
    rig(&dev, BEACON_ROUTER_SHORT, PAN_ID);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 1), ZB_OK, "a router takes the beacon payload");

    len = composeBeaconRequest(request, 0x32);
    injectRaw(&dev.model, request, len, 5100);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "a request that arrives at a router is stepped");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconReplies == 1, "and answered by it as well");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1, "one beacon");

    /* 7.3.1.4: the Association Permit bit states macAssociationPermit, which is this network's policy and not the
       parent role: a router that takes no children says so in the beacon and still answers a request 0x02. */
    rig(&dev, BEACON_ROUTER_SHORT, PAN_ID);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 0), ZB_OK,
                      "a router whose policy refuses new children takes the beacon payload");
    len = composeBeaconRequest(request, 0x34);
    injectRaw(&dev.model, request, len, 5300);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 400), ZB_OK, "a request that arrives at it is stepped");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconReplies == 1, "and answered, because 3.6.1.6.1.3 answers PAN_ACCESS_DENIED");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1, "one beacon goes out");
    Test_Expect(beaconPermitBitOf(&sent[0]) == 0,
                "with the Association Permit bit clear, which is what 7.3.1.4 says the attribute means");

    /* An end device answers nothing: it is nobody's parent, and D.11.1.5 has it out of the duty. */
    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1, 0x11, 0);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 0), ZB_OK,
                      "an end device takes the call and enables nothing");

    len = composeBeaconRequest(request, 0x33);
    injectRaw(&dev.model, request, len, 5200);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 300), ZB_OK, "a request that arrives at an end device is stepped");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconRequestsHeard == 1, "it is heard");
    Test_Expect(counters.beaconReplies == 0 && counters.beaconIgnored == 1,
                "and ignored, because an end device is not the device D.11.1.5 obliges");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "nothing went on the air");
}

/*
 * 3.6.8.1's appendix: "The nwkDeviceBeaconPayloadTLVs SHALL contain at a minimum the Router Information Global TLV",
 * which Annex I.4.7 prints as a two-octet bitmap behind Annex I.4.1's tag and length.
 */
void caseBeaconPayloadCarriesTheRouterInformation(void)
{
    Nwk_BeaconInfo info;
    Nwk_BeaconInfo readBack;
    uint8_t bytes[NWK_BEACON_PAYLOAD_LEN];
    uint8_t small[NWK_BEACON_PAYLOAD_LEN - 1];
    uint32_t len = 0;

    Zb_memset(&info, 0, (uint32_t)sizeof info);

    info.stackProfile = 2;
    info.protocolVersion = 2;
    info.routerCapacity = 1;
    info.deviceDepth = 0;
    info.endDeviceCapacity = 1;
    info.extendedPanId = 0x000000000000beef;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = 0;

    Test_ExpectStatus(Nwk_ComposeBeaconPayload(&info, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                  "the payload composes");
    Test_ExpectCount(len, NWK_BEACON_PAYLOAD_LEN,
                     "as Table 3-83's fifteen octets and the four of Annex I.4.1's tag and length with Annex I.4.7's two-octet bitmap behind them");

    Test_Expect(bytes[15] == 70,
           "the TLV's tag is 70, which Annex I.4.7 prints as the Router Information Global TLV");
    Test_Expect(bytes[16] == 1,
           "its length field is 1, which Annex I.4.1's bias makes a two-octet value");
    Test_Expect(bytes[17] == 0x00 && bytes[18] == 0x00,
           "and every bit of Table I-6's bitmap is zero: no hub, no battery backup, no enhanced-beacon support, no uptime clock, no preferred parent");

    Test_ExpectStatus(Nwk_ParseBeaconInfo(bytes, len, &readBack), ZB_OK,
                  "and the info field reads back out of the longer payload, the appendix being no part of it");
    Test_Expect(readBack.stackProfile == 2 && readBack.extendedPanId == info.extendedPanId,
                "field for field");

    Test_ExpectStatus(Nwk_ComposeBeaconPayload(&info, small, (uint32_t)sizeof small, &len), ZB_ERR_NO_SPACE,
                      "a buffer one octet short of the appendix is no space");

    Test_Expect(Nwk_BeaconHasAppendix(bytes, NWK_BEACON_PAYLOAD_LEN) == 1,
                "the composed payload carries the R23 appendix 3.6.1.6.1.1 chooses commissioning by");
    Test_Expect(Nwk_BeaconHasAppendix(bytes, NWK_BEACON_INFO_LEN) == 0, "the fifteen octets alone carry none");
    Test_Expect(Nwk_BeaconHasAppendix(bytes, NWK_BEACON_PAYLOAD_LEN - 1) == 0, "nor does a TLV cut short");
    bytes[15] = 71;
    Test_Expect(Nwk_BeaconHasAppendix(bytes, NWK_BEACON_PAYLOAD_LEN) == 0,
                "and whole TLVs without the Router Information one are not 3.6.8.1's appendix");
}

/* The appendix walk steps over a record it does not name, and takes the bitmap from the first two octets of a Router
   Information longer than Table I-6 prints. */
void caseBeaconAppendixStepsOverOtherRecords(void)
{
    uint8_t bytes[NWK_BEACON_INFO_LEN + 8];
    uint16_t bitmap = 0;

    Zb_memset(bytes, 0, (uint32_t)sizeof bytes);
    bytes[NWK_BEACON_INFO_LEN] = 0x10;
    bytes[NWK_BEACON_INFO_LEN + 1] = 0x00;
    bytes[NWK_BEACON_INFO_LEN + 2] = 0xff;
    bytes[NWK_BEACON_INFO_LEN + 3] = NWK_BEACON_TLV_ROUTER_INFORMATION;
    bytes[NWK_BEACON_INFO_LEN + 4] = 0x02;
    bytes[NWK_BEACON_INFO_LEN + 5] = 0x34;
    bytes[NWK_BEACON_INFO_LEN + 6] = 0x12;
    bytes[NWK_BEACON_INFO_LEN + 7] = 0x99;

    Test_Expect(Nwk_BeaconRouterInformation(bytes, (uint32_t)sizeof bytes, &bitmap) == 1,
                "a Router Information behind another record is found");
    Test_ExpectCount(bitmap, 0x1234, "its bitmap low octet first, the third value octet left unread");
    Test_Expect(Nwk_BeaconRouterInformation(bytes, (uint32_t)sizeof bytes - 1, &bitmap) == 0,
                "and one cut short is no appendix at all");
}
