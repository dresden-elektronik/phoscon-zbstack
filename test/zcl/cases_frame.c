/* ZCL R8's foundation over one cluster: Figure 2-2's frame, Table 3-7's Basic attributes, and 2.5.1's read path
   answered record by record. */

#include "af_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "zcl.h"

typedef struct Zcl_Rig
{
    Af_Rig af;
    Zcl_Zcl zcl;
    Zcl_Cluster cluster;
} Zcl_Rig;

static void zclRigBuild(Zcl_Rig *rig)
{
    afRigBuild(&rig->af, AF_OWN_SHORT);

    Zcl_BasicDefaults(&rig->cluster, 0x01, "phoscon", "zbstack");

    Test_ExpectStatus(Zcl_Init(&rig->zcl, &rig->af.af, 1, 0x0104, &rig->cluster), ZB_OK,
                      "the Basic cluster is installed on endpoint 1");
}

void caseZclFrameCodec(void)
{
    Zcl_Header header;
    Zcl_Header back;
    uint8_t frame[16];
    uint8_t payload[2];
    uint8_t widest[ZCL_PAYLOAD_MAX];
    uint8_t asdu[AF_ASDU_MAX];
    uint32_t offset = 0;
    uint32_t len = 0;

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    payload[0] = 0x11;
    payload[1] = 0x22;

    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = 0x2a;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES;

    Test_ExpectStatus(Zcl_FrameCompose(&header, payload, 2, frame, (uint32_t)sizeof frame, &len), ZB_OK,
                      "Figure 2-2's frame without a manufacturer code");
    Test_ExpectCount(len, 5, "the three header octets and the two payload octets");
    Test_ExpectCount(frame[0], ZCL_FRAME_TYPE_GLOBAL, "the frame control first");

    Test_ExpectStatus(Zcl_FrameParse(frame, len, &back, &offset), ZB_OK, "and it reads back");
    Test_ExpectCount(back.transactionSequenceNumber, 0x2a, "the transaction sequence number");
    Test_ExpectCount(back.commandIdentifier, ZCL_CMD_READ_ATTRIBUTES, "the command identifier");
    Test_ExpectCount(offset, 3, "and the payload starts after the three header octets");

    header.frameControl = (uint8_t)(ZCL_FRAME_TYPE_GLOBAL | ZCL_FC_MANUFACTURER);
    header.manufacturerCode = 0x1037;

    Test_ExpectStatus(Zcl_FrameCompose(&header, payload, 2, frame, (uint32_t)sizeof frame, &len), ZB_OK,
                      "2.4.1.2: with the manufacturer bit set the code is in the frame");
    Test_ExpectCount(len, 7, "which is two octets wider");

    Test_ExpectStatus(Zcl_FrameParse(frame, len, &back, &offset), ZB_OK, "and it reads back");
    Test_ExpectCount(back.manufacturerCode, 0x1037, "the manufacturer code");
    Test_ExpectCount(offset, 5, "with the payload after five header octets");

    Zb_memset(widest, 0x5a, (uint32_t)sizeof widest);
    Test_ExpectStatus(Zcl_FrameCompose(&header, widest, ZCL_PAYLOAD_MAX, asdu, AF_ASDU_MAX, &len), ZB_OK,
                      "Figure 2-2: the payload bound leaves room for the header at its widest, the manufacturer code included");
    Test_ExpectCount(len, AF_ASDU_MAX, "and that frame fills the ASDU exactly");

    Test_ExpectStatus(Zcl_FrameParse(frame, 4, &back, &offset), ZB_ERR_BAD_ARGUMENT,
                      "a frame that stops inside its header is refused");

    Test_ExpectStatus(Zcl_FrameCompose(&header, frame, 2, frame, (uint32_t)sizeof frame, &len), ZB_OK,
                      "and a payload in the destination's own buffer composes: the frame is built beside it");
}

void caseZclBasicAttributes(void)
{
    Zcl_Rig rig;
    const Zcl_Attribute *attribute;

    zclRigBuild(&rig);

    Test_ExpectCount(rig.cluster.attributeCount, 4, "Table 3-7's two mandatory attributes and the two the case named");

    attribute = Zcl_AttributeOf(&rig.cluster, 0x0000);
    Test_Expect(attribute != 0, "3.2.2.2.1: ZCLVersion is there");
    Test_ExpectCount(attribute->type, ZCL_TYPE_UINT8, "as Table 2-18's unsigned 8-bit integer");
    Test_ExpectCount(attribute->value[0], ZCL_BASIC_ZCL_VERSION, "and its value is this revision's number, 8");

    attribute = Zcl_AttributeOf(&rig.cluster, 0x0007);
    Test_Expect(attribute != 0 && attribute->type == ZCL_TYPE_ENUM8, "PowerSource is an enum8");
    Test_ExpectCount(attribute->value[0], 0x01, "with the power source the caller named");

    attribute = Zcl_AttributeOf(&rig.cluster, 0x0004);
    Test_Expect(attribute != 0 && attribute->type == ZCL_TYPE_STRING, "ManufacturerName is a character string");
    Test_ExpectCount(attribute->value[0], 7, "whose length octet comes first");
    Test_ExpectCount(attribute->value[1], 'p', "and whose characters follow it");

    Test_Expect(Zcl_AttributeOf(&rig.cluster, 0x00ff) == 0, "an attribute the cluster does not hold is not found");
}

void caseZclReadAttributes(void)
{
    Zcl_Rig rig;
    Af_Indication indication;
    uint8_t asdu[8];
    uint32_t len = 0;
    Zcl_Header header;

    zclRigBuild(&rig);

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = 0x5a;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES;

    asdu[0] = 0x00;
    asdu[1] = 0x00;     /* ZCLVersion */
    asdu[2] = 0xff;
    asdu[3] = 0x00;     /* an attribute nobody holds */

    Test_ExpectStatus(Zcl_FrameCompose(&header, asdu, 4, asdu, (uint32_t)sizeof asdu, &len), ZB_OK,
                      "2.5.1's Read Attributes command naming two identifiers");

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);
    indication.dstEndpoint = 1;
    indication.srcEndpoint = 1;
    indication.srcAddress = AF_PEER_SHORT;
    indication.clusterId = ZCL_CLUSTER_BASIC;
    indication.asduLength = len;
    Zb_memcpy(indication.asdu, asdu, len);

    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 100), ZB_OK, "the server answers the command");
    Test_ExpectCount(Zcl_ResponsesSent(&rig.zcl), 1, "with one Read Attributes Response");
    Test_ExpectCount(Zcl_AttributesRead(&rig.zcl), 1, "one attribute read");
    Test_ExpectCount(Zcl_AttributesUnsupported(&rig.zcl), 1, "and one the cluster does not hold");

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = 0x5b;
    header.commandIdentifier = 0x0c;    /* Discover Attributes, which this stack does not implement */

    Test_ExpectStatus(Zcl_FrameCompose(&header, 0, 0, asdu, (uint32_t)sizeof asdu, &len), ZB_OK,
                      "a global command this stack does not implement");

    indication.asduLength = len;
    Zb_memcpy(indication.asdu, asdu, len);

    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 200), ZB_OK,
                      "draws 2.5.12's Default Response rather than silence");
    Test_ExpectCount(Zcl_CommandsUnsupported(&rig.zcl), 1, "and the command is counted");
    Test_ExpectCount(Zcl_ResponsesSent(&rig.zcl), 2, "as a second answer");
}

void caseZclClientRead(void)
{
    Zcl_Rig rig;
    Zcl_ReadRecord record;
    uint16_t ids[2];
    Af_Indication indication;
    uint8_t answer[16];
    uint8_t frame[16];
    uint32_t len = 0;
    Zcl_Header header;

    zclRigBuild(&rig);

    ids[0] = 0x0000;
    ids[1] = 0x0007;

    Test_ExpectStatus(Zcl_ReadAttributes(&rig.zcl, AF_PEER_SHORT, 1, ids, 2, 100), ZB_OK,
                      "2.5.1: a Read Attributes command naming two identifiers is sent");
    Test_ExpectCount(Zcl_ReadsSent(&rig.zcl), 1, "and counted");
    Test_ExpectCount(Zcl_TransactionSequenceNumber(&rig.zcl), 1, "with 2.4.1.3's counter moved by one");

    /* The answer as the peer would send it: 2.5.2's frame, the direction bit set, one record SUCCESS and one
       UNSUPPORTED_ATTRIBUTE. */
    answer[0] = 0x00;
    answer[1] = 0x00;       /* attribute 0x0000 */
    answer[2] = ZCL_STATUS_SUCCESS;
    answer[3] = ZCL_TYPE_UINT8;
    answer[4] = ZCL_BASIC_ZCL_VERSION;
    answer[5] = 0xff;       /* attribute 0x00ff */
    answer[6] = 0x00;
    answer[7] = ZCL_STATUS_UNSUPPORTED_ATTRIBUTE;

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    header.frameControl = (uint8_t)(ZCL_FRAME_TYPE_GLOBAL | ZCL_FC_DIRECTION | ZCL_FC_DISABLE_DEFAULT_RESPONSE);
    header.transactionSequenceNumber = 0;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES_RESPONSE;

    Test_ExpectStatus(Zcl_FrameCompose(&header, answer, 8, frame, (uint32_t)sizeof frame, &len), ZB_OK,
                      "the answer is a ZCL frame of its own");

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);
    indication.dstEndpoint = 1;
    indication.srcEndpoint = 1;
    indication.srcAddress = AF_PEER_SHORT;
    indication.clusterId = ZCL_CLUSTER_BASIC;
    indication.asduLength = len;
    Zb_memcpy(indication.asdu, frame, len);

    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 200), ZB_OK, "the answer is read, not answered");
    Test_ExpectCount(Zcl_ResponsesSent(&rig.zcl), 0, "so this device composes nothing back");

    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 1), 1, "the first record is there");
    Test_ExpectCount(record.attributeId, 0x0000, "keyed by the identifier that was read");
    Test_ExpectCount(record.status, ZCL_STATUS_SUCCESS, "with a success");
    Test_ExpectCount(record.value[0], ZCL_BASIC_ZCL_VERSION, "and the value the peer holds");

    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 1), 1, "and the second");
    Test_ExpectCount(record.attributeId, 0x00ff, "an attribute the peer does not hold");
    Test_ExpectCount(record.status, ZCL_STATUS_UNSUPPORTED_ATTRIBUTE, "answered with Table 2-15's status");
    Test_ExpectCount(record.valueLength, 0, "and no value at all");

    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 1), 0, "the ring is empty once both were taken");
}

/* Where the read path stops: an answer that runs out of room ends on INSUFFICIENT_SPACE after the records that fitted,
   and a response record cut short, or a string running past the frame, is not taken. */
void caseZclReadBounds(void)
{
    static const uint8_t cutAfterType[] = { 0x04, 0x00, ZCL_STATUS_SUCCESS, ZCL_TYPE_STRING };
    static const uint8_t stringPastFrame[] = { 0x04, 0x00, ZCL_STATUS_SUCCESS, ZCL_TYPE_STRING, 0x05, 0x61, 0x62 };
    static const uint8_t trailingOctets[] = { 0x00, 0x00, ZCL_STATUS_SUCCESS, ZCL_TYPE_UINT8, ZCL_BASIC_ZCL_VERSION,
                                              0x01, 0x00 };
    Zcl_Rig rig;
    Zcl_ReadRecord record;
    Af_Indication indication;
    Zcl_Header header;
    uint8_t ids[16];
    uint32_t len = 0;
    uint32_t i;

    zclRigBuild(&rig);

    /* Each ManufacturerName record is the identifier, the status, the type and "phoscon" behind its length: twelve
       octets, so six fit ZCL_PAYLOAD_MAX and the seventh is answered INSUFFICIENT_SPACE. */
    for (i = 0; i < 8; i++)
    {
        ids[i * 2] = 0x04;
        ids[i * 2 + 1] = 0x00;
    }

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = 0x5c;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES;

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);
    indication.dstEndpoint = 1;
    indication.srcEndpoint = 1;
    indication.srcAddress = AF_PEER_SHORT;
    indication.clusterId = ZCL_CLUSTER_BASIC;

    Test_ExpectStatus(Zcl_FrameCompose(&header, ids, (uint32_t)sizeof ids, indication.asdu,
                                       (uint32_t)sizeof indication.asdu, &len), ZB_OK,
                      "a read naming ManufacturerName eight times");
    indication.asduLength = len;

    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 100), ZB_OK, "is answered");
    Test_ExpectCount(Zcl_AttributesRead(&rig.zcl), 6, "with the six records that fit");
    Test_ExpectCount(Zcl_ResponsesSent(&rig.zcl), 1, "in one response");

    header.frameControl = (uint8_t)(ZCL_FRAME_TYPE_GLOBAL | ZCL_FC_DIRECTION | ZCL_FC_DISABLE_DEFAULT_RESPONSE);
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES_RESPONSE;

    Test_ExpectStatus(Zcl_FrameCompose(&header, cutAfterType, (uint32_t)sizeof cutAfterType, indication.asdu,
                                       (uint32_t)sizeof indication.asdu, &len), ZB_OK, "a record cut after its type");
    indication.asduLength = len;
    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 200), ZB_OK, "is read");
    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 1), 0, "and not taken");

    Test_ExpectStatus(Zcl_FrameCompose(&header, stringPastFrame, (uint32_t)sizeof stringPastFrame, indication.asdu,
                                       (uint32_t)sizeof indication.asdu, &len), ZB_OK,
                      "a string whose length runs past the frame");
    indication.asduLength = len;
    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 300), ZB_OK, "is read");
    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 1), 0, "and not taken");

    Test_ExpectStatus(Zcl_FrameCompose(&header, trailingOctets, (uint32_t)sizeof trailingOctets, indication.asdu,
                                       (uint32_t)sizeof indication.asdu, &len), ZB_OK,
                      "a whole record and two octets behind it");
    indication.asduLength = len;
    Test_ExpectStatus(Zcl_HandleIndication(&rig.zcl, &indication, 400), ZB_OK, "is read");
    Test_ExpectCount(Zcl_PollReadRecords(&rig.zcl, &record, 2), 1, "as the one record");
    Test_ExpectCount(record.value[0], ZCL_BASIC_ZCL_VERSION, "with its value");
}

/* The three payload codecs an application uses over Zb_Stack's own requests and events, with no endpoint installed:
   the read it writes, the answer a cluster gives it, and that answer read back. */
void caseZclPayloadCodecs(void)
{
    static const uint16_t ids[] = { 0x0004, 0x0005, 0x4000 };
    Zcl_Cluster cluster;
    Zcl_ReadRecord records[4];
    uint8_t request[8];
    uint8_t answer[ZCL_PAYLOAD_MAX];
    uint32_t requestLen;
    uint32_t answerLen;
    uint32_t read = 0;
    uint32_t unsupported = 0;

    Zcl_BasicDefaults(&cluster, 0x01, "phoscon", "zbstack");

    requestLen = Zcl_ReadAttributesCompose(ids, 3, request, (uint32_t)sizeof request);
    Test_ExpectCount(requestLen, 6, "2.5.1: two octets per identifier");
    Test_ExpectCount(request[0], 0x04, "low octet first");
    Test_ExpectCount(Zcl_ReadAttributesCompose(ids, 3, request, 5), 0, "and nothing when they do not fit");

    answerLen = Zcl_ReadAttributesAnswer(&cluster, request, requestLen, answer, (uint32_t)sizeof answer, &read,
                                         &unsupported);
    Test_ExpectCount(answerLen, 12 + 12 + 3, "two string records and one with no value");
    Test_ExpectCount(read, 2, "ManufacturerName and ModelIdentifier are read");
    Test_ExpectCount(unsupported, 1, "and the identifier Basic does not hold is UNSUPPORTED_ATTRIBUTE");

    Test_ExpectCount(Zcl_ReadResponseParse(answer, answerLen, records, 4), 3, "the answer reads back as three records");
    Test_ExpectCount(records[0].attributeId, 0x0004, "ManufacturerName first");
    Test_ExpectCount(records[0].type, ZCL_TYPE_STRING, "as a character string");
    Test_ExpectCount(records[0].valueLength, 8, "its length octet and seven characters");
    Test_ExpectCount(records[1].value[1], 'z', "ModelIdentifier's first character");
    Test_ExpectCount(records[2].status, ZCL_STATUS_UNSUPPORTED_ATTRIBUTE, "and the third's status");
    Test_ExpectCount(Zcl_ReadResponseParse(answer, answerLen, records, 1), 1, "no more records than asked for");
}
