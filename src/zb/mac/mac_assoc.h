#ifndef MAC_ASSOC_H
#define MAC_ASSOC_H

/*
 * 10.21.2's child sequence and 10.21.5's parent door; docs/internals/conformance.md §1 owns its contract.
 */

#include <stdint.h>

#include "mac_indirect.h"
#include "radio.h"
#include "zb_status.h"

/* The association subject's own state: 10.21.5.1's requests waiting for the layer above, and the child's exchange
   (10.21.2's state, the confirm 10.21.6.1.5 hands over, the handles of the two frames it issues, the parent it
   addressed, the wait it is inside), with the numbers each half is read by. */
typedef struct Mac_Assoc
{
    Mac_AssocState assocState;
    Mac_AssociateConfirmParameters assocConfirm;
    int assocConfirmReady;
    uint32_t assocWaitMs;
    uint32_t assocPollMs;
    uint32_t assocHandle;
    int assocHandleValid;
    uint32_t assocPollHandle;
    int assocPollHandleValid;
    uint16_t assocParentShort;
    uint64_t assocParentExtended;
    int assocParentShortKnown;
    uint16_t assocDestPan;
    uint8_t assocPayload[2];
    uint32_t assocPayloadLen;
    uint32_t assocSendMs;
    uint32_t assocChannel;
    int assocPibOwed;
    uint32_t assocsDroppedNotAsked;
    uint32_t assocsDroppedNotOurs;
    uint32_t assocsDroppedSource;
    uint32_t assocsDroppedParent;
    uint32_t assocsDroppedMalformed;
    uint32_t assocsDroppedAddress;
    uint32_t requestsDroppedSource;
    uint32_t requestsDroppedContent;
    uint32_t requestsDroppedNotOurs;
    uint32_t requestsDroppedFast;
    uint32_t requestsDroppedUnparsable;

    Mac_AssociationIndication associations[MAC_ASSOCIATION_MAX];
    uint32_t associationHead;
    uint32_t associationCount;
    uint32_t associationsDropped;
} Mac_Assoc;

/* 10.21.2's child sequence, advanced once per step from the same nowMs: the acknowledgment and macResponseWaitTime's
   window. `tx` and `pib` are the caller's pools, and `self` the façade whose Mac_SetPib and Mac_DataRequest this
   sequence walks. */
void MacAssoc_Progress(Mac_Assoc *assoc, Mac_Mac *self, Mac_Tx *tx, const Radio_Pib *pib, uint32_t nowMs);

/* 10.21.2's deadline, read after the step's frames so an answer delivered on that turn has already ended the
   exchange. */
void MacAssoc_Expire(Mac_Assoc *assoc, Mac_Mac *self, uint32_t nowMs);

/* Table 10-104, MLME-ASSOCIATE.request written where 10.21.2 puts it, then 10.21.5.1's request: `ownExtendedKnown`
   is whether this device was given an address at all, and every refusal is counted in the caller's ledger. */
ZbStatus MacAssoc_Request(Mac_Assoc *assoc, Mac_Mac *self, const Mac_AssociateRequestParameters *req,
                          int ownExtendedKnown, uint32_t *refusedRequests, uint32_t nowMs);

/* 10.21.6.1.5's confirm, handed over once: 1 when there was one and 0 otherwise. */
uint32_t MacAssoc_PollConfirm(Mac_Assoc *assoc, Mac_AssociateConfirmParameters *out);

/* What the exchange is doing, for an owner that reads the state and not only the confirm. */
Mac_AssocState MacAssoc_StateOf(const Mac_Assoc *assoc);

/* Table 7-11's 0x01 and its 0x02, read off a delivered frame's header and Content: the two questions 3.6.2.2 draws
   on the way in, and whether the request is this device's (`beaconPanCoordinator` being 7.3.1.4's bit and
   `destIsThisDevice` 6.6.2's test of the same frame). */
int MacAssoc_RequestCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen);
int MacAssoc_RequestForThisDevice(const Mac_Frame *header, int beaconPanCoordinator, int destIsThisDevice);

/* 10.21.5.1's request refused at the door, each reason counted apart: an extended source is the clause's, the
   content is one capability octet, the destination is this device's, 10.21.4's fast form is not built, and the
   octet is a capability of 10.21.5.1's shape. */
typedef enum MacAssoc_RequestRefusal
{
    MAC_ASSOC_REQUEST_SOURCE = 0,
    MAC_ASSOC_REQUEST_CONTENT,
    MAC_ASSOC_REQUEST_NOT_OURS,
    MAC_ASSOC_REQUEST_FAST,
    MAC_ASSOC_REQUEST_UNPARSABLE
} MacAssoc_RequestRefusal;
void MacAssoc_CountRefusedRequest(Mac_Assoc *assoc, MacAssoc_RequestRefusal reason);
int MacAssoc_ResponseCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen);

/* 10.21.5.1's request is an event for the layer above: queued in arrival order, full is a refusal and a count. */
void MacAssoc_QueueRequest(Mac_Assoc *assoc, const Mac_Frame *header, const MacFrame_Capability *capability,
                           uint64_t stampTicks);

/* The requests this device has heard, oldest first, taken the way the confirmations are taken. */
uint32_t MacAssoc_PollRequests(Mac_Assoc *assoc, Mac_AssociationIndication *out, uint32_t max);

/* Whether a delivered 0x02 is this device's answer, and what it says when it is: the extraction's only reader, and a
   declined answer is counted and consumed as a heard command. */
int MacAssoc_TakeResponse(Mac_Assoc *assoc, Mac_Mac *self, Mac_Tx *tx, const Mac_Frame *header,
                          const uint8_t *payload, int destIsThisDevice);

/* 10.21.5.2's answer, queued as the indirect transaction the child's Data Request extracts, at the DSN the caller
   issues at: `beaconAnswers` says whether this device is a coordinator or a router to answer at all. */
ZbStatus MacAssoc_Response(Mac_Indirect *indirect, const Mac_AssociationResponse *response, int beaconAnswers,
                           const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio,
                           uint32_t *dsn, uint32_t *refusedRequests, uint32_t nowMs);

#endif /* MAC_ASSOC_H */
