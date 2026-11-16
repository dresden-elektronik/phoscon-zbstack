#ifndef ZB_STATUS_H
#define ZB_STATUS_H

/* Append-only: a code is never reused or renumbered (docs/internals/coding-rules.md §5). */
typedef enum ZbStatus
{
    ZB_OK = 0,
    ZB_ERR_BAD_ARGUMENT = 1,
    ZB_ERR_UNSUPPORTED = 2,
    ZB_ERR_NOT_OPEN = 3,
    ZB_ERR_NO_DEVICE = 4,
    ZB_ERR_BUSY = 5,
    ZB_ERR_DEVICE_LOST = 6,
    ZB_ERR_NO_SPACE = 7,
    ZB_ERR_INTERNAL = 8,

    /* The three band B needs once it drives a device instead of a fixture. Each translates a named
       reply on the wire (docs/internals/protocol.md §7.3); none is a new failure of its own: a reply that
       never arrived, a link that is open but not brought up, and an answer this codec cannot read. */
    ZB_ERR_TIMEOUT = 9,
    ZB_ERR_NOT_READY = 10,
    ZB_ERR_BAD_FRAME = 11,

    /* The device said no for a reason this stack does not name. The code it used travels with the
       reply, so nothing is lost by folding several codes into one status. */
    ZB_ERR_DEVICE = 12,

    /* A message authentication check failed (a CCM tag, later an APS MIC). */
    ZB_ERR_AUTH = 13,

    /* The routing layer has no path to the destination (R23.1 3.6.4.3, ROUTE_ERROR). */
    ZB_ERR_NO_ROUTE = 14,

    /* A frame counter was met where it cannot be used: the outgoing counter at its maximum 2^32-1
       (R23.1 4.3.1.1 step 1), the incoming counter at the same value (4.3.1.2 step 1, the one failure
       in that procedure that names no status) or an incoming count a sender has already used
       (4.3.1.2 step 3, 'bad frame counter'). One reason word for all three, because the direction is
       known at the call site. */
    ZB_ERR_BAD_FRAME_COUNTER = 15,

    /* The two a request can meet that are neither a shape nor a device's no: nothing in this build answers
       what it names (R23.1 3.2.1.1.3's NOT_PERMITTED), and the request is not one this device may make now
       (3.6.1.6.1.1's INV_REQUESTTYPE). Each is a stated refusal of band A's own, with no radio reply behind it. */
    ZB_ERR_NOT_FOUND = 16,
    ZB_ERR_BAD_STATE = 17,

    /* 8.2.2's NO_ACK: "successfully transmits the frame required by a request primitive, but the expected
       acknowledgment is not received". A radio that runs the exchange itself reports it as a device code, and
       this is the name band A's confirmation carries for it (R23.1 Annex D.2's numeric value is 0xe9 on the air). */
    ZB_ERR_NO_ACK = 18,

    /* 8.2.2 and 6.6.6's lost-data answer: "If macTransactionPersistenceTime is reached, the transaction information
       will be discarded, and the MAC sublayer will issue a failure confirmation to the next higher layer". */
    ZB_ERR_TRANSACTION_EXPIRED = 19,

    /* 8.2.2's TRANSACTION_OVERFLOW: "there is no capacity to store another transaction". A full transaction
       pool answered NO_SPACE until this name existed, which said the same thing in a word from another table. */
    ZB_ERR_TRANSACTION_OVERFLOW = 20,

    /* 4.4.1.2 step 8 a)'s UNVERIFIED_FRAME_COUNTER: the key pair supports 4.6.3.8's frame counter synchronization
       and its counter is not verified, so the frame is dropped and the counter is not stored. 4.5.1.1.4's Require
       Verified Frame Counter bit is the sender asking for the same answer. */
    ZB_ERR_UNVERIFIED_FRAME_COUNTER = 21,

    /* 8.2.2's CHANNEL_ACCESS_FAILURE: "a transmission could not take place due to activity on the channel, i.e.,
       the CSMA-CA mechanism has failed". A radio that runs the CCA itself reports it as a device code (Spinel 18). */
    ZB_ERR_CHANNEL_ACCESS_FAILURE = 22,

    /* 8.2.2's NO_DATA: a poll whose coordinator held nothing for this device, which MLME-POLL.confirm reports when
       the Ack said Frame Pending zero or the frame after it was empty or never came (10.22.5.3). */
    ZB_ERR_NO_DATA = 23
} ZbStatus;

#endif /* ZB_STATUS_H */
