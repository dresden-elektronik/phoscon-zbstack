/* The `mac` suite's shared machinery: the bodies. See `mac_helpers.h` for what this file is and why it is
   here. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

const uint8_t payload[PAYLOAD_LEN] = { 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b };

/* A band-A device built by the shared rig (test/support/rig_band_a.h): the model, the MAC on its seam and
   the PIB band A is told about itself, on the channel every band-A rig arms. The DSN seed is the one thing the
   seam cannot supply (6.6.1, Table 8-36 print macDsn's default as a random value), so it is the one thing the
   rig may be told: `rig` below names no config, which is dsnStart 0, the number every case in this suite
   already matches its confirmations against.

   What this suite keeps of its own is the PIB variant a plain arm does not have: a write the backend refuses,
   whose status has to come back as the backend named it. `Test_BandABuild` reports the first status that was
   not ZB_OK, so the first assertion below is the whole build (model, seam, MAC init and PIB write) and the
   three after it are the capability the MAC kept, the address and PAN the backend took, and that refusal. */
void rigConfig(Test_BandA *rig, const Radio_Caps *caps, uint16_t shortAddress, uint16_t panId,
               const Mac_Config *config)
{
    Test_BandAConfig cfg;
    Radio_Pib pib;
    ZbStatus status;

    Test_BandADefaults(&cfg);
    cfg.caps = *caps;
    cfg.ownAddress = shortAddress;
    cfg.panId = panId;
    cfg.dsnStart = config ? (uint32_t)config->dsnStart : 0;
    cfg.log = config ? config->log : 0;   /* the pool an application names, through the module's own door */

    status = Test_BandABuild(rig, &cfg);

    Test_ExpectStatus(status, ZB_OK, "band A adopts the backend it is given");
    Test_Expect(Mac_Caps(&rig->mac)->handlesAckTimeout == caps->handlesAckTimeout,
           "and keeps the capability it read, because that is what its own decisions branch on");
    Test_Expect(rig->model.pib.shortAddress == shortAddress && rig->model.pib.panId == panId,
           "its own address and PAN are set through the seam");

    if (shortAddress != 0)
    {
        Zb_memset(&pib, 0, (uint32_t)sizeof pib);
        pib.present = RADIO_PIB_CHANNEL;
        pib.channel = 99;
        Test_ExpectStatus(Mac_SetPib(&rig->mac, &pib), ZB_ERR_BAD_ARGUMENT,
                     "and what the backend refused is reported as the backend named it, not as a device fault band A invented");
    }
}

/* The device every case that names no config builds: the 0x10d radio both RCPs report (docs/internals/hardware.md
   §4), addressed as the rig addressed its RCPs. */
void rig(Test_BandA *rig, uint16_t shortAddress, uint16_t panId)
{
    Radio_Caps caps;

    Test_BandACapsAcks(&caps);
    rigConfig(rig, &caps, shortAddress, panId, 0);
}

Mac_DataRequestParameters dataReq(uint32_t frameType, uint32_t destMode, uint16_t destPan, uint16_t destShort,
                    uint32_t srcMode, int ackRequest)
{
    Mac_DataRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.msduHandle = 1;
    req.frameType = frameType;
    req.destAddrMode = (Mac_AddrMode)destMode;
    req.srcAddrMode = (Mac_AddrMode)srcMode;
    req.destPan = destPan;
    req.destShort = destShort;
    req.ackRequest = ackRequest;
    req.payload = payload;
    req.payloadLen = (uint32_t)sizeof payload;

    return req;
}

/* A request meant to be queued rather than sent. Its payload is a parameter because a queued transaction
   is a copy of what the request carried and not a pointer into the caller's buffer (10.22.2),
   and the ask is the one an extraction always carries: 10.22.2, "In order to be successfully extracted, an
   acknowledgment shall be received if one was requested". */
Mac_DataRequestParameters indirectReq(uint32_t frameType, uint32_t destMode, uint16_t destPan, uint16_t destShort,
                        const uint8_t *what, uint32_t len)
{
    Mac_DataRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.msduHandle = 1;              /* a caller's handle, so the confirmation can be tied to it */
    req.frameType = frameType;
    req.destAddrMode = (Mac_AddrMode)destMode;
    req.srcAddrMode = MAC_ADDR_SHORT;
    req.destPan = destPan;
    req.destShort = destShort;
    req.ackRequest = 1;
    req.payload = what;
    req.payloadLen = len;

    return req;
}

/* The child side of the poll, composed by the suite because the suite is what puts a poll in front of a
   coordinator: 10.22.4.1's twelve octets, Command ID 0x04 with a zero-length Content field, the
   Destination PAN ID this device's own with the Source PAN ID omitted, short addressing at both ends, AR
   one and Frame Pending zero. */
uint32_t composePollTo(uint8_t *out, uint8_t dsn, uint16_t src, uint16_t dest)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = dest;
    frame.srcShort = src;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                 ZB_OK, "the poll a child sends is a frame this stack can compose (10.22.4.1)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                 "closed by the footer those octets compute (7.2.11)");

    return len;
}

uint32_t composePoll(uint8_t *out, uint8_t dsn, uint16_t src)
{
    return composePollTo(out, dsn, src, COORDINATOR_SHORT);
}

/* 10.22.5.2: a poll directed to the PAN coordinator may omit the destination fields. 6.6.2 d)4 then judges it
   by its source PAN, and only the PAN coordinator is its destination. */
uint32_t composePollToPan(uint8_t *out, uint8_t dsn, uint64_t src)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = PAN_ID;
    frame.srcExtended = src;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the destination-less poll composes (10.22.5.2)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    return len;
}

/* 10.21.5.1: Command ID 0x01 and the one capability octet, the source extended, the source PAN the broadcast
   one (which is why the frame does not compress), the destination the coordinator's short address, AR one. */
uint32_t composeAssociationRequest(uint8_t *out, uint8_t dsn, uint64_t child, uint8_t capability)
{
    Mac_Frame frame;
    uint8_t content[2];
    uint32_t len;

    content[0] = MAC_CMD_ASSOCIATION_REQUEST;
    content[1] = capability;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    frame.srcExtended = child;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the Association Request a child sends is a frame this stack can compose (10.21.5.1)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    return len;
}

/* R23.1 Annex D.4's destination-less form: the destination is the PAN coordinator, so its PAN and address
   fields are omitted, the source PAN is still the broadcast one and the source address is extended. */
uint32_t composeAssociationRequestToPan(uint8_t *out, uint8_t dsn, uint64_t child, uint8_t capability)
{
    Mac_Frame frame;
    uint8_t content[2];
    uint32_t len;

    content[0] = MAC_CMD_ASSOCIATION_REQUEST;
    content[1] = capability;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    frame.srcExtended = child;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the destination-less Association Request composes (R23.1 Annex D.4)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    return len;
}

/* The poll of a child that has no short address yet: 10.22.4.1's source mode follows macShortAddress, which is
   0xffff before association, so the source is the extended address and the PAN compresses into one field. */
uint32_t composePollExtended(uint8_t *out, uint8_t dsn, uint64_t src)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcExtended = src;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the poll a child without a short address sends is a frame this stack can compose");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    return len;
}

/* 10.21.5.2: extended addressing at both ends, one PAN field because the destination PAN is this device's own
   (7.2.2.6), AR one, Frame Pending zero, and Figure 10-158's three content octets: the short address least
   significant octet first, then Table 10-102's status. The source is the parent the child addressed, which is
   what makes 10.21.2's answer the parent's own. */
uint32_t composeAssociationResponse(uint8_t *out, uint8_t dsn, uint64_t child, uint64_t parent,
                                    uint16_t shortAddress, uint8_t status)
{
    Mac_Frame frame;
    uint8_t content[4];
    uint32_t len;

    content[0] = MAC_CMD_ASSOCIATION_RESPONSE;
    content[1] = (uint8_t)(shortAddress & 0xff);
    content[2] = (uint8_t)((shortAddress >> 8) & 0xff);
    content[3] = status;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_EXTENDED;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destExtended = child;
    frame.srcExtended = parent;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the Association Response a parent sends is a frame this stack can compose (10.21.5.2)");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    return len;
}

void injectFrame(Loopback_Radio *model, const uint8_t *bytes, uint32_t len, uint64_t stamp)
{
    Loopback_FrameSpec spec;

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = stamp;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(model, &spec, 1), ZB_OK, "a frame is put in front of band A");
}

void injectPoll(Loopback_Radio *model, uint8_t dsn, uint16_t src, uint64_t stamp)
{
    uint8_t frame[RADIO_MPDU_MAX];
    uint32_t len;

    len = composePoll(frame, dsn, src);

    injectFrame(model, frame, len, stamp);
}

/* The Frame Control of a frame the backend recorded, read the way this PAN writes it: the low octet first,
   which is the order docs/internals/protocol.md §9.1 records for every frame in test/fixtures/ and the order
   `mac_frame` composes in (802.15.4-2006 6.3, "all multiple octet fields shall be transmitted or received least
   significant octet first"). */
uint16_t fcfOf(const Loopback_Sent *sent)
{
    return (uint16_t)(sent->bytes[0] | (sent->bytes[1] << 8));
}

/* Which record the backend is showing for that destination at that DSN: searched for by the octets on the
   wire rather than by the slot a transmit happened to take, which is how `caseTrackPool` already reads the
   same backend. A frame whose destination is not a short address, or which carries no DSN octet at all, is
   not what this looks for, so it answers `count`: an expect then reads as "found", not as a magic number. */
uint32_t sentIndexFor(const Loopback_Sent *sent, uint32_t count, uint16_t destShort, uint8_t dsn)
{
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if (sent[i].len < 7)
            continue;

        if (sent[i].bytes[2] == dsn && (uint16_t)(sent[i].bytes[5] | (sent[i].bytes[6] << 8)) == destShort)
            return i;
    }

    return count;
}

void harvestAir(Loopback_Radio *model, Air *log, uint32_t *count)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t got;
    uint32_t i;
    uint32_t j;

    got = LoopbackRadio_Sent(model, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        for (j = 0; j < *count; j++)
        {
            if (log[j].len == sent[i].len && log[j].ackRequest == sent[i].ackRequest
                && Zb_memcmp(log[j].bytes, sent[i].bytes, sent[i].len) == 0)
                break;
        }

        if (j < *count)
            continue;

        Test_Expect(*count < AIR_LOG_MAX, "the suite's own air log has room for what this case puts on the air");

        if (*count >= AIR_LOG_MAX)
            return;

        log[*count].len = sent[i].len;
        log[*count].ackRequest = sent[i].ackRequest;
        Zb_memcpy(log[*count].bytes, sent[i].bytes, sent[i].len);
        (*count)++;
    }
}

/* The logged frame with that destination and that DSN, answered by the index or by `count` when the ledger
   holds no such frame. Searched for by the octets on the wire, which is what a ledger entry is. */
uint32_t airIndexOf(const Air *log, uint32_t count, uint16_t destShort, uint8_t dsn)
{
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if (log[i].len < 7)
            continue;

        if (log[i].bytes[2] == dsn && (uint16_t)(log[i].bytes[5] | (log[i].bytes[6] << 8)) == destShort)
            return i;
    }

    return count;
}
