#include "mac.h"

#include "mac_assoc.h"

#include "zb_time.h"
#include "zb_utils.h"

/* M2024: 6.2, 6.6.2, 8.2.2, 10.21.2, 10.21.5.1, 10.21.5.2, 10.21.6.1.5, 10.22.2, 10.22.3, 10.22.4.1 ok; 7.3.1.4
   deferred (the permit is the answer's status, not whether the request is indicated, docs/internals/decisions.md); 7.1.17,
   10.21.4 unbuilt; R23.1 3.6.1.6.1 ok. docs/internals/conformance.md pages. */

enum
{
    MAC_STATUS_CHANNEL_ACCESS_FAILURE = 0xe1,
    MAC_STATUS_NO_ACK = 0xe9,
    MAC_STATUS_NO_DATA = 0xeb,
    MAC_STATUS_TRANSACTION_OVERFLOW = 0xee,

    MAC_SHORT_ADDRESS_UNASSOCIATED = 0xffff
};

/* `self` is the façade, taken by the four entries that walk one of its doors: Mac_SetPib on 10.21.2's three PIB
   writes and Mac_DataRequest on the request and its extraction. Every field this module reads arrives beside it,
   the caller's pools as pointers. */

/* What an attempt ends as: Table 10-107's Status and AssociationStatus, the state they name, and the flag that says
   the layer above has not taken it. A successful exchange carrying a parent's refusal is still no association. */
static void macAssocConclude(Mac_Assoc *assoc, Mac_Mac *self, uint8_t status, uint8_t associationStatus)
{
    Radio_Pib pib;

    assoc->assocConfirm.status = status;
    assoc->assocConfirm.associationStatus = associationStatus;
    assoc->assocConfirmReady = 1;

    if (status == MAC_ASSOC_STATUS_SUCCESS && associationStatus == MAC_ASSOC_STATUS_SUCCESS)
    {
        assoc->assocState = MAC_ASSOC_DONE;
        return;
    }

    assoc->assocState = MAC_ASSOC_FAILED;

    assoc->assocConfirm.shortAddress = MAC_FRAME_ADDR_BROADCAST;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS;
    pib.panId = MAC_FRAME_PAN_BROADCAST;
    pib.shortAddress = MAC_FRAME_ADDR_BROADCAST;
    (void)Mac_SetPib(self, &pib);
}

/* The extraction's own confirmation, released once it is collected: the child's poll is this module's evidence and
   never a report upward, and a slot left in the pool would be one Mac_PollConfirms handed to the layer above. */
static void macReleasePollTrack(Mac_Assoc *assoc, Mac_Tx *tx)
{
    Mac_Track *slot = MacTx_TrackNamed(tx, assoc->assocPollHandle, assoc->assocPollHandleValid);

    if (MacTx_TrackAnswered(slot))
    {
        MacTx_TrackRelease(slot);
        assoc->assocPollHandleValid = 0;
    }
}

/* The request from what MacAssoc_Request stored, so a held request goes out as it was first composed. */
static ZbStatus macAssocSendRequest(Mac_Assoc *assoc, Mac_Mac *self, uint32_t nowMs)
{
    Mac_DataRequestParameters data;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    ZbStatus status;

    Zb_memset(&data, 0, (uint32_t)sizeof data);
    data.frameType = MAC_FRAME_TYPE_COMMAND;
    data.destAddrMode = assoc->assocParentShortKnown ? MAC_ADDR_SHORT : MAC_ADDR_EXTENDED;
    data.srcAddrMode = MAC_ADDR_EXTENDED;
    data.destPan = assoc->assocDestPan;
    data.destShort = assoc->assocParentShortKnown ? assoc->assocParentShort : 0;
    data.destExtended = assoc->assocParentShortKnown ? 0 : assoc->assocParentExtended;
    data.ackRequest = 1;
    data.framePending = 0;
    data.payload = assoc->assocPayload;
    data.payloadLen = assoc->assocPayloadLen;

    status = Mac_DataRequest(self, &data, nowMs, &handle);

    if (status != ZB_OK)
        return status;

    assoc->assocHandle = handle;
    assoc->assocHandleValid = 1;
    assoc->assocState = MAC_ASSOC_REQUESTING;

    return ZB_OK;
}

/* The write before the request: the channel when one is named (0 leaves the radio's own), the parent's PAN, and
   macShortAddress at the unassociated 0xffff. */
static void macAssocPibOf(const Mac_Assoc *assoc, Radio_Pib *pib)
{
    Zb_memset(pib, 0, (uint32_t)sizeof *pib);

    if (assoc->assocChannel != 0)
    {
        pib->present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE;
        pib->channel = assoc->assocChannel;
        pib->page = 0;
    }

    pib->present |= RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS;
    pib->panId = assoc->assocDestPan;
    pib->shortAddress = MAC_SHORT_ADDRESS_UNASSOCIATED;
}

/* The request's way out: the PIB write first while band B had no room for it, then the frame, each refusal for want
   of room answered the same so the caller holds the request either way. */
static ZbStatus macAssocIssue(Mac_Assoc *assoc, Mac_Mac *self, uint32_t nowMs)
{
    Radio_Pib pib;
    ZbStatus status;

    if (assoc->assocPibOwed)
    {
        macAssocPibOf(assoc, &pib);
        status = Mac_SetPib(self, &pib);

        if (status != ZB_OK)
            return status;

        assoc->assocPibOwed = 0;
    }

    return macAssocSendRequest(assoc, self, nowMs);
}

/* 10.21.2's failure path for a request the door refused after the PAN write: macPanId and macShortAddress go back
   to Table 8-36's 0xffff, the exchange is failed and 10.21.6.1.5's confirm carries 8.2.2's TRANSACTION_OVERFLOW,
   "there is no capacity to store another transaction". The caller keeps the door's own status. */
static void macAssocAbandonRequest(Mac_Assoc *assoc, Mac_Mac *self)
{
    Zb_memset(&assoc->assocConfirm, 0, (uint32_t)sizeof assoc->assocConfirm);

    assoc->assocParentShortKnown = 0;
    assoc->assocParentShort = 0;
    assoc->assocParentExtended = 0;

    macAssocConclude(assoc, self, MAC_STATUS_TRANSACTION_OVERFLOW, 0);
}

/* The confirm's status for a request that was not acknowledged: CHANNEL_ACCESS_FAILURE where CSMA-CA found the
   channel busy and nothing was sent, NO_ACK for every other way the acknowledgment failed to arrive. */
static uint8_t macAssocSendFailure(ZbStatus status)
{
    return status == ZB_ERR_CHANNEL_ACCESS_FAILURE ? MAC_STATUS_CHANNEL_ACCESS_FAILURE : MAC_STATUS_NO_ACK;
}

/* 10.21.2: the first extraction is owed at macResponseWaitTime after the acknowledgment, and the window that
   attempt opens for the answer is as wide as that same wait, so the deadline is two of them. */
static int macAssocWindowOpen(const Mac_Assoc *assoc, uint32_t nowMs)
{
    return Zb_timeWithin(nowMs, assoc->assocWaitMs + MAC_RESPONSE_WAIT_MS, MAC_RESPONSE_WAIT_MS);
}

/* Whether the first extraction is owed yet: "it shall attempt to extract the Association Response command from the
   coordinator after macResponseWaitTime". */
static int macAssocPollOwed(const Mac_Assoc *assoc, uint32_t nowMs)
{
    return Zb_timeReached(nowMs, assoc->assocWaitMs + MAC_RESPONSE_WAIT_MS);
}

/* 10.22.3, the Data Request that extracts a decision the coordinator holds, sourced as 10.22.4.1 pins it: the
   extended address while macShortAddress is 0xffff. The transaction is the parent's and outlives a poll, and a
   poll still on the air keeps its slot rather than being replaced by the next one. */
static ZbStatus macAssocPoll(Mac_Assoc *assoc, Mac_Mac *self, Mac_Tx *tx, const Radio_Pib *pib,
                             uint32_t nowMs)
{
    Mac_DataRequestParameters poll;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint8_t content[1];
    ZbStatus status;

    content[0] = MAC_CMD_POLL;

    Zb_memset(&poll, 0, (uint32_t)sizeof poll);
    poll.frameType = MAC_FRAME_TYPE_COMMAND;
    poll.destAddrMode = assoc->assocParentShortKnown ? MAC_ADDR_SHORT : MAC_ADDR_EXTENDED;
    poll.srcAddrMode = MAC_ADDR_EXTENDED;
    poll.destPan = pib->panId;
    poll.destShort = assoc->assocParentShort;
    poll.destExtended = assoc->assocParentExtended;
    poll.ackRequest = 1;
    poll.framePending = 0;
    poll.payload = content;
    poll.payloadLen = 1;

    if (assoc->assocPollHandleValid && !MacTx_TrackAnswered(MacTx_TrackNamed(tx, assoc->assocPollHandle, 1)))
        return ZB_ERR_BUSY;

    status = Mac_DataRequest(self, &poll, nowMs, &handle);

    if (status != ZB_OK)
        return status;

    assoc->assocPollHandle = handle;
    assoc->assocPollHandleValid = 1;
    assoc->assocPollMs = nowMs;

    return ZB_OK;
}

/* 10.21.2, the child's sequence, advanced once per step from the same nowMs: the acknowledgment, the wait, and the
   extractions that ask for the decision (10.22.3). The window is not concluded here: MacAssoc_Expire runs after
   the step's frames so an answer delivered on the deadline's own turn still ends the exchange. */
void MacAssoc_Progress(Mac_Assoc *assoc, Mac_Mac *self, Mac_Tx *tx, const Radio_Pib *pib, uint32_t nowMs)
{
    Mac_Track *slot;
    ZbStatus status;
    int acknowledged;
    int pollDue;

    switch (assoc->assocState)
    {
        case MAC_ASSOC_SENDING:
            status = macAssocIssue(assoc, self, nowMs);

            if ((status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
                && Zb_timeWithin(nowMs, assoc->assocSendMs, MAC_ASSOC_SEND_WAIT_MS))
                return;

            if (status != ZB_OK)
                macAssocAbandonRequest(assoc, self);

            return;

        case MAC_ASSOC_REQUESTING:
            slot = MacTx_TrackNamed(tx, assoc->assocHandle, assoc->assocHandleValid);

            if (slot == 0)
            {
                assoc->assocHandleValid = 0;
                macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, 0);
                return;
            }

            if (!MacTx_TrackAnswered(slot))
                return;

            acknowledged = slot->state == MAC_TX_ANSWERED && slot->status == ZB_OK && slot->acked;
            status = slot->state == MAC_TX_ANSWERED ? slot->status : ZB_ERR_TIMEOUT;

            MacTx_TrackRelease(slot);
            assoc->assocHandleValid = 0;

            if (!acknowledged)
            {
                macAssocConclude(assoc, self, macAssocSendFailure(status), 0);
                return;
            }

            assoc->assocWaitMs = nowMs;
            assoc->assocState = MAC_ASSOC_WAITING;
            return;

        case MAC_ASSOC_WAITING:
            pollDue = macAssocPollOwed(assoc, nowMs) && macAssocWindowOpen(assoc, nowMs)
                      && !Zb_timeWithin(nowMs, assoc->assocPollMs, MAC_ASSOC_POLL_DELAY_MS);

            if (!pollDue)
                return;

            status = macAssocPoll(assoc, self, tx, pib, nowMs);

            if (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
                return;

            if (status != ZB_OK)
            {
                macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, 0);
                return;
            }

            assoc->assocState = MAC_ASSOC_POLLING;
            return;

        case MAC_ASSOC_POLLING:
            macReleasePollTrack(assoc, tx);

            if (!macAssocWindowOpen(assoc, nowMs))
                return;

            if (Zb_timeWithin(nowMs, assoc->assocPollMs, MAC_ASSOC_POLL_DELAY_MS))
                return;

            status = macAssocPoll(assoc, self, tx, pib, nowMs);

            if (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
                return;

            if (status != ZB_OK)
            {
                macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, 0);
                return;
            }

            return;

        case MAC_ASSOC_DONE:
        case MAC_ASSOC_FAILED:
            macReleasePollTrack(assoc, tx);
            assoc->assocConfirmReady = 1;
            return;

        default:
            return;
    }
}

/* 10.21.2, the deadline: a device with no answer inside macResponseWaitTime is told NO_DATA, Table 78's 0xeb. Read
   after the step's frames, so an answer delivered on that turn has already ended the exchange. */
void MacAssoc_Expire(Mac_Assoc *assoc, Mac_Mac *self, uint32_t nowMs)
{
    if (assoc->assocState != MAC_ASSOC_WAITING && assoc->assocState != MAC_ASSOC_POLLING)
        return;

    if (!Zb_timeReached(nowMs, assoc->assocWaitMs + (2 * MAC_RESPONSE_WAIT_MS)))
        return;

    macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, 0);
}

/* Table 10-104, MLME-ASSOCIATE.request written where 10.21.2 puts it, then 10.21.5.1's request. A refusal before
   that write leaves nothing; no room at the door after it holds the request for Progress to re-ask, the PIB still
   written; any other refusal leaves what macAssocAbandonRequest restores. */
ZbStatus MacAssoc_Request(Mac_Assoc *assoc, Mac_Mac *self, const Mac_AssociateRequestParameters *req,
                          int ownExtendedKnown, uint32_t *refusedRequests, uint32_t nowMs)
{
    Radio_Pib pib;
    uint32_t bodyLen = 0;
    ZbStatus status;

    if (assoc == 0 || self == 0 || req == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (assoc->assocState != MAC_ASSOC_IDLE && assoc->assocState != MAC_ASSOC_DONE
        && assoc->assocState != MAC_ASSOC_FAILED)
    {
        (*refusedRequests)++;
        return ZB_ERR_BUSY;
    }

    assoc->assocState = MAC_ASSOC_IDLE;

    Zb_memset(&assoc->assocConfirm, 0, (uint32_t)sizeof assoc->assocConfirm);
    assoc->assocConfirmReady = 0;

    if (!ownExtendedKnown)
    {
        (*refusedRequests)++;
        return ZB_ERR_NOT_READY;
    }

    if (req->capability.associationType || req->capability.suspendableCsmaCa
        || req->capability.securityCapability)
    {
        (*refusedRequests)++;
        return ZB_ERR_UNSUPPORTED;    /* the capability's fast, suspendable-CSMA and security bits: forms not built, docs/internals/conformance.md §1 */
    }

    if (req->destPan == MAC_FRAME_PAN_BROADCAST)
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (req->parentShortKnown)
    {
        if (req->parentShort >= MAC_SHORT_ADDRESS_LAST_USABLE)
        {
            (*refusedRequests)++;
            return ZB_ERR_BAD_ARGUMENT;
        }
    }
    else if (req->parentExtended == 0 || MacTx_IsBroadcastExtendedAddress(req->parentExtended))
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    assoc->assocChannel = req->channel;
    assoc->assocDestPan = req->destPan;
    macAssocPibOf(assoc, &pib);

    status = Mac_SetPib(self, &pib);

    if (status != ZB_OK && status != ZB_ERR_BUSY && status != ZB_ERR_NO_SPACE)
        return status;                

    assoc->assocPibOwed = status != ZB_OK;
    assoc->assocPayload[0] = MAC_CMD_ASSOCIATION_REQUEST;

    status = MacFrame_ComposeAssociationRequest(&req->capability, assoc->assocPayload + 1,
                                               (uint32_t)sizeof assoc->assocPayload - 1, &bodyLen);

    if (status != ZB_OK)
    {
        (*refusedRequests)++;
        macAssocAbandonRequest(assoc, self);
        return status;
    }

    Zb_memset(&assoc->assocConfirm, 0, (uint32_t)sizeof assoc->assocConfirm);
    assoc->assocConfirmReady = 0;
    assoc->assocWaitMs = 0;
    assoc->assocPollMs = 0;
    assoc->assocHandleValid = 0;
    assoc->assocPollHandle = RADIO_HANDLE_NONE;
    assoc->assocPollHandleValid = 0;
    assoc->assocParentShortKnown = req->parentShortKnown;
    assoc->assocParentShort = req->parentShortKnown ? req->parentShort : 0;
    assoc->assocParentExtended = req->parentExtended;
    assoc->assocPayloadLen = bodyLen + 1;
    assoc->assocSendMs = nowMs;

    status = macAssocIssue(assoc, self, nowMs);

    if (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
    {
        assoc->assocState = MAC_ASSOC_SENDING;
        return ZB_OK;
    }

    if (status != ZB_OK)
    {
        macAssocAbandonRequest(assoc, self);
        return status;
    }

    return ZB_OK;
}

uint32_t MacAssoc_PollConfirm(Mac_Assoc *assoc, Mac_AssociateConfirmParameters *out)
{
    if (assoc == 0 || out == 0)
        return 0;

    if (!assoc->assocConfirmReady)
        return 0;

    *out = assoc->assocConfirm;

    Zb_memset(&assoc->assocConfirm, 0, (uint32_t)sizeof assoc->assocConfirm);

    assoc->assocConfirmReady = 0;

    if (assoc->assocState == MAC_ASSOC_DONE || assoc->assocState == MAC_ASSOC_FAILED)
        assoc->assocState = MAC_ASSOC_IDLE;

    return 1;
}

Mac_AssocState MacAssoc_StateOf(const Mac_Assoc *assoc)
{
    if (assoc == 0)
        return MAC_ASSOC_IDLE;

    return assoc->assocState;
}

/* Table 10-102's statuses this stack can produce: 0x00, 0x01 and 0x02, for an answer received as well as sent,
   so a reserved or unreachable octet in a response is no Association Status at all. */
static int macAssociationStatusValid(uint8_t status)
{
    return status == MAC_ASSOC_STATUS_SUCCESS
        || status == MAC_ASSOC_STATUS_PAN_AT_CAPACITY
        || status == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED;
}

/* 10.21.5.2's answer, queued as the indirect transaction the child's Data Request extracts (10.21.2: the
   response "shall be sent to the device requesting association using indirect transmission"). The destination
   PAN is macPanId and both addressing modes are extended, which is the clause's own shape. */
ZbStatus MacAssoc_Response(Mac_Indirect *indirect, const Mac_AssociationResponse *response, int beaconAnswers,
                           const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio,
                           uint32_t *dsn, uint32_t *refusedRequests, uint32_t nowMs)
{
    Mac_DataRequestParameters req;
    MacFrame_AssociationResponse body;
    uint8_t payload[4];
    uint32_t bodyLen = 0;
    ZbStatus status;

    if (indirect == 0 || response == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!beaconAnswers)
        return ZB_ERR_NOT_READY;

    if (response->request.extendedAddress == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!macAssociationStatusValid(response->status))
        return ZB_ERR_BAD_ARGUMENT;

    if (response->status == MAC_ASSOC_STATUS_SUCCESS)
    {
        if (response->request.capability.allocateAddress)
        {
            if (response->shortAddress > MAC_SHORT_ADDRESS_LAST_USABLE - 1)
                return ZB_ERR_BAD_ARGUMENT;
        }
        else if (response->shortAddress != MAC_SHORT_ADDRESS_LAST_USABLE)
        {
            return ZB_ERR_BAD_ARGUMENT;
        }
    }
    else if (response->shortAddress != MAC_FRAME_ADDR_BROADCAST)
    {
        return ZB_ERR_BAD_ARGUMENT;
    }

    body.shortAddress = response->shortAddress;
    body.status = response->status;
    payload[0] = MAC_CMD_ASSOCIATION_RESPONSE;

    status = MacFrame_ComposeAssociationResponse(&body, payload + 1, (uint32_t)sizeof payload - 1, &bodyLen);

    if (status != ZB_OK)
        return status;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.frameType = MAC_FRAME_TYPE_COMMAND;
    req.destAddrMode = MAC_ADDR_EXTENDED;
    req.srcAddrMode = MAC_ADDR_EXTENDED;
    req.destPan = pib->panId;
    req.destExtended = response->request.extendedAddress;
    req.ackRequest = 1;
    req.framePending = 0;
    req.payload = payload;
    req.payloadLen = bodyLen + 1;

    status = MacIndirect_Queue(indirect, 1, &req, pib, ownExtendedKnown, ownExtended, radio, dsn, refusedRequests,
                               nowMs);

    if (status == ZB_OK && response->status == MAC_ASSOC_STATUS_SUCCESS
            && response->request.capability.allocateAddress)
        (void)MacIndirect_LearnPair(indirect, response->shortAddress, response->request.extendedAddress);

    return status;
}

/* Table 7-11's 0x01 Association Request: a command whose Content is the one Capability Information octet
   (10.21.5.1). It is the parent's event, not a data indication. */
int MacAssoc_RequestCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (payloadLen == 0 || payload == 0)
        return 0;

    return payload[0] == MAC_CMD_ASSOCIATION_REQUEST;
}

/* 10.21.5.1 addresses the request to the coordinator from the beacon, so it is this device's only where the
   destination is this device's own address and not the broadcast one, which the caller has judged. R23.1 Annex
   D.4 is the source PAN's own rule, and a request for somebody else is a command this module heard and consumed. */
int MacAssoc_RequestForThisDevice(const Mac_Frame *header, int beaconPanCoordinator, int destIsThisDevice)
{
    if (header->destAddrMode == MAC_ADDR_NONE)
        return beaconPanCoordinator && destIsThisDevice;

    return destIsThisDevice;
}

/* One request the parent could not take, counted under the clause that refused it. */
void MacAssoc_CountRefusedRequest(Mac_Assoc *assoc, MacAssoc_RequestRefusal reason)
{
    if (reason == MAC_ASSOC_REQUEST_SOURCE)
        assoc->requestsDroppedSource++;
    else if (reason == MAC_ASSOC_REQUEST_CONTENT)
        assoc->requestsDroppedContent++;
    else if (reason == MAC_ASSOC_REQUEST_NOT_OURS)
        assoc->requestsDroppedNotOurs++;
    else if (reason == MAC_ASSOC_REQUEST_FAST)
        assoc->requestsDroppedFast++;
    else
        assoc->requestsDroppedUnparsable++;
}

/* The parent's association event, in arrival order. Full is a refusal and a count: the newest arrival is the
   one dropped, the older requests being ones the layer above has still to decide. */
void MacAssoc_QueueRequest(Mac_Assoc *assoc, const Mac_Frame *header, const MacFrame_Capability *capability,
                           uint64_t stampTicks)
{
    Mac_AssociationIndication *slot;

    if (assoc->associationCount >= MAC_ASSOCIATION_MAX)
    {
        assoc->associationsDropped++;
        return;
    }

    slot = &assoc->associations[(assoc->associationHead + assoc->associationCount) % MAC_ASSOCIATION_MAX];
    Zb_memset(slot, 0, (uint32_t)sizeof *slot);
    slot->extendedAddress = header->srcExtended;
    slot->destPan = header->destPan;
    slot->capability = *capability;
    slot->stampTicks = stampTicks;
    assoc->associationCount++;
}

uint32_t MacAssoc_PollRequests(Mac_Assoc *assoc, Mac_AssociationIndication *out, uint32_t max)
{
    uint32_t count;
    uint32_t i;

    if (assoc == 0 || out == 0 || max == 0)
        return 0;

    count = assoc->associationCount < max ? assoc->associationCount : max;

    for (i = 0; i < count; i++)
        out[i] = assoc->associations[(assoc->associationHead + i) % MAC_ASSOCIATION_MAX];

    assoc->associationHead = (assoc->associationHead + count) % MAC_ASSOCIATION_MAX;
    assoc->associationCount -= count;

    return count;
}

/* Table 7-11's 0x02 Association Response: 10.21.5.2's answer to an associating device, whose Content is Figure
   10-158's three octets. It is the child's own exchange, so it is consumed here and never delivered upward. */
int MacAssoc_ResponseCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (payloadLen != 4 || payload == 0)
        return 0;

    return payload[0] == MAC_CMD_ASSOCIATION_RESPONSE;
}

/* Whether a delivered 0x02 is this device's answer, and what it says when it is: 10.21.2's exchange is the only
   reader, the parent the request addressed is the only answerer, and a successful answer's short address is
   written where 10.21.2 stores it. A declined answer is counted here and consumed as a heard command. */
int MacAssoc_TakeResponse(Mac_Assoc *assoc, Mac_Mac *self, Mac_Tx *tx, const Mac_Frame *header,
                          const uint8_t *payload, int destIsThisDevice)
{
    MacFrame_AssociationResponse body;
    Radio_Pib pib;
    ZbStatus status;

    if (assoc->assocState != MAC_ASSOC_WAITING && assoc->assocState != MAC_ASSOC_POLLING)
    {
        assoc->assocsDroppedNotAsked++;
        return 0;
    }

    if (!destIsThisDevice)
    {
        assoc->assocsDroppedNotOurs++;
        return 0;
    }

    if (header->srcAddrMode != MAC_ADDR_EXTENDED)
    {
        assoc->assocsDroppedSource++;
        return 0;
    }

    if (assoc->assocParentExtended != 0 && header->srcExtended != assoc->assocParentExtended)
    {
        assoc->assocsDroppedParent++;
        return 0;
    }

    if (MacFrame_ParseAssociationResponse(payload + 1, 3, &body) != ZB_OK)
    {
        assoc->assocsDroppedMalformed++;
        return 0;
    }

    macReleasePollTrack(assoc, tx);

    Zb_memset(&assoc->assocConfirm, 0, (uint32_t)sizeof assoc->assocConfirm);
    assoc->assocConfirm.parentExtended = header->srcExtended;

    assoc->assocConfirm.parentShortKnown = assoc->assocParentShortKnown;
    assoc->assocConfirm.parentShort = assoc->assocParentShort;

    if (!macAssociationStatusValid(body.status))
    {
        assoc->assocsDroppedMalformed++;
        return 0;
    }

    if (body.status != MAC_ASSOC_STATUS_SUCCESS)
    {
        macAssocConclude(assoc, self, MAC_ASSOC_STATUS_SUCCESS, body.status);
        return 1;
    }

    if (body.shortAddress == MAC_FRAME_ADDR_BROADCAST)
    {
        macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, body.status);
        return 1;
    }

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = body.shortAddress;

    status = Mac_SetPib(self, &pib);

    if (status != ZB_OK)
    {
        assoc->assocsDroppedAddress++;
        macAssocConclude(assoc, self, MAC_STATUS_NO_DATA, body.status);
        return 1;
    }

    assoc->assocConfirm.shortAddress = body.shortAddress;
    macAssocConclude(assoc, self, MAC_ASSOC_STATUS_SUCCESS, body.status);

    return 1;
}
