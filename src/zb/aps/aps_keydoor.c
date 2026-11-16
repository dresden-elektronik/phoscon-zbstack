#include "aps_keydoor.h"

#include "zb_utils.h"

/* R23.1 4.4.1.3 4.4.1.5 4.4.2.1.3 4.4.2.3 4.4.11 4.4.11.1 4.9.2 ok; Figure 4-8's body is `aps_transportkey.c`'s and
   the indication ring is the façade's. docs/internals/conformance.md pages 428, 433, 436-437, 461, 530. */

/* The command identifier opens the payload, Figure 2-8's "APS payload" column, so the header length handed back
   is where security's auxiliary header goes: in front of the identifier, which is encrypted with the body. */
ZbStatus Aps_TransportKeyComposeFrame(const Aps_TransportKeyReq *req, uint64_t ownIeee, uint8_t apsCounter,
                                      int apsSecurity, uint8_t *out, uint32_t outMax, uint32_t *outLen,
                                      uint32_t *headerLen)
{
    Aps_TransportKey body;
    Aps_Frame frame;
    uint8_t payload[APS_FRAME_COMMAND_ID_OCTETS + APS_TK_NETWORK_BODY_OCTETS];
    uint32_t bodyLen;
    ZbStatus status;

    if (req == 0 || out == 0 || outLen == 0 || headerLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(&body, 0, (uint32_t)sizeof body);

    body.standardKeyType = req->standardKeyType;
    Zb_memcpy(body.key, req->key, APS_TK_KEY_OCTETS);
    body.keySeqNumber = req->keySeqNumber;
    body.destinationIeee = req->destinationIeee;
    body.sourceIeee = req->sourceIeee != 0 ? req->sourceIeee : ownIeee;
    body.partnerIeee = req->partnerIeee;
    body.initiator = req->initiator ? 1 : 0;

    payload[0] = (uint8_t)APS_TK_COMMAND_ID;

    status = Aps_TransportKeyCompose(&body, payload + APS_FRAME_COMMAND_ID_OCTETS,
                                     (uint32_t)sizeof payload - APS_FRAME_COMMAND_ID_OCTETS, &bodyLen);

    if (status != ZB_OK)
        return status;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.ackRequest = req->tunnel ? 0 : 1;
    frame.securityEnabled = apsSecurity;
    frame.apsCounter = apsCounter;

    return ApsFrame_Compose(&frame, payload, APS_FRAME_COMMAND_ID_OCTETS + bodyLen, out, outMax, outLen, headerLen);
}

uint32_t Aps_TransportKeyIdentifier(uint32_t standardKeyType)
{
    if (standardKeyType == APS_TK_TYPE_NETWORK_KEY)
        return SECURITY_KEY_ID_KEY_TRANSPORT;

    if (standardKeyType == APS_TK_TYPE_APPLICATION_LINK_KEY || standardKeyType == APS_TK_TYPE_TC_LINK_KEY)
        return SECURITY_KEY_ID_KEY_LOAD;

    return SECURITY_KEY_ID_DATA;
}

ZbStatus Aps_KeyVerdictFor(const Aps_KeyReceipt *receipt, Aps_KeyVerdict *out)
{
    const Aps_TransportKey *body;
    const Aps_KeyPolicy *policy;
    int broadcastNetworkKey;
    int fromTrustCenter;
    int hasSourceField;
    int securedWithLinkKey;

    if (receipt == 0 || receipt->body == 0 || receipt->policy == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    body = receipt->body;
    policy = receipt->policy;

    hasSourceField = body->standardKeyType == APS_TK_TYPE_NETWORK_KEY
                     || body->standardKeyType == APS_TK_TYPE_TC_LINK_KEY;

    securedWithLinkKey = receipt->secured && receipt->keyPairKnown;

    broadcastNetworkKey = body->standardKeyType == APS_TK_TYPE_NETWORK_KEY
                          && body->destinationIeee == 0
                          && policy->joinedAndAuthorized;

    if (policy->trustCenterIeee == APS_KEY_IEEE_ALL_F || policy->trustCenterIeee == APS_KEY_IEEE_UNSET)
        fromTrustCenter = 1;
    else if (receipt->secured)
        fromTrustCenter = receipt->keyPairKnown && receipt->keyPairIeee == policy->trustCenterIeee;
    else if (hasSourceField)
        fromTrustCenter = body->sourceIeee == policy->trustCenterIeee;
    else
        fromTrustCenter = receipt->nwkSrc == APS_KEY_NWK_TRUST_CENTER;

    if (!fromTrustCenter)
    {
        *out = APS_KEY_DROP_NOT_TRUST_CENTER;

        return ZB_OK;
    }

    if (!receipt->secured && !broadcastNetworkKey && (policy->requireLinkKeyEncryption || policy->hasPreconfiguredLinkKey))
    {
        *out = APS_KEY_DROP_POLICY;

        return ZB_OK;
    }

    if (body->standardKeyType == APS_TK_TYPE_NETWORK_KEY && body->sourceIeee == APS_KEY_IEEE_ALL_F
        && policy->trustCenterIeee != APS_KEY_IEEE_ALL_F)
    {
        *out = APS_KEY_DROP_DISTRIBUTED;

        return ZB_OK;
    }

    if (!securedWithLinkKey && !broadcastNetworkKey && policy->trustCenterIeee != APS_KEY_IEEE_ALL_F
        && body->standardKeyType != APS_TK_TYPE_NETWORK_KEY)
    {
        *out = APS_KEY_DROP_UNSECURED_KEY;

        return ZB_OK;
    }

    if (hasSourceField && body->destinationIeee != 0 && body->destinationIeee != receipt->localIeee)
    {
        *out = APS_KEY_FORWARD;

        return ZB_OK;
    }

    *out = APS_KEY_ACCEPT;

    return ZB_OK;
}
