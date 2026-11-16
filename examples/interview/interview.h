#ifndef EX_INTERVIEW_H
#define EX_INTERVIEW_H

/*
 * What each device that joins is, asked one step at a time: its node descriptor, its active endpoints, each
 * endpoint's simple descriptor, then the Basic cluster's ManufacturerName and ModelIdentifier on the first endpoint
 * that serves it. One state machine per device, over the stack's requests and the events that answer them.
 */

#include <stdint.h>

#include "zb_stack.h"
#include "zdo.h"

enum
{
    INTERVIEW_DEVICE_MAX = 32,       /* the devices one run remembers, a house size */
    INTERVIEW_ENDPOINT_MAX = 8,      /* the endpoints of one device it asks about */
    INTERVIEW_TEXT_MAX = 32,         /* ZCL R8 Table 3-7: ManufacturerName and ModelIdentifier are 0 to 32 characters */
    INTERVIEW_PARALLEL = 4,          /* devices asked at once, so their requests stay inside the 8 the stack takes */
    INTERVIEW_ATTEMPTS = 3,          /* a step asked this often before the device is given up on */
    INTERVIEW_ANSWER_MS = 10000,     /* how long a step waits for its answer: a route discovery and APS retries */
    INTERVIEW_RETRY_MS = 2000,       /* and how long it waits before it asks again */
    INTERVIEW_TAG_END = INTERVIEW_DEVICE_MAX << 8   /* a request's tag is its device's place, then a sequence octet */
};

/* Where a device's interview stands: the step being asked, then the end it came to. */
typedef enum InterviewStep
{
    INTERVIEW_NODE_DESCRIPTOR,
    INTERVIEW_ACTIVE_ENDPOINTS,
    INTERVIEW_SIMPLE_DESCRIPTOR,
    INTERVIEW_BASIC,
    INTERVIEW_COMPLETE,
    INTERVIEW_FAILED
} InterviewStep;

typedef struct InterviewDevice
{
    int inUse;
    uint64_t ieee;
    uint16_t networkAddress;
    int receiverOn;

    InterviewStep step;
    uint32_t attempts;               /* of the step being asked */
    int asking;                      /* a request is out and its answer awaited */
    uint32_t askedMs;
    uint32_t nextAskMs;              /* when a step not yet asked, or asked again, may go */
    uint16_t tag;                    /* the request's tag, which its ZB_EVENT_SENT carries */
    uint16_t cluster;                /* the answer's cluster */
    uint8_t sequence;                /* and its transaction sequence number */

    Zdo_NodeDescriptor node;
    uint8_t endpoints[INTERVIEW_ENDPOINT_MAX];
    uint32_t endpointCount;
    uint32_t endpointIndex;          /* the endpoint whose simple descriptor is asked */
    Af_SimpleDescriptor simple[INTERVIEW_ENDPOINT_MAX];
    uint8_t basicEndpoint;           /* the first endpoint whose input clusters name Basic, 0 when none does */
    char manufacturer[INTERVIEW_TEXT_MAX + 1];
    char model[INTERVIEW_TEXT_MAX + 1];
} InterviewDevice;

typedef struct Interview
{
    Zb_Stack *stack;
    uint8_t ownEndpoint;             /* the coordinator's endpoint a ZCL read goes from, and its answer comes to */
    uint8_t zclSequence;             /* the ZCL transaction sequence number of this application's reads */
    uint8_t tagSequence;
    InterviewDevice devices[INTERVIEW_DEVICE_MAX];
} Interview;

void Interview_Init(Interview *self, Zb_Stack *stack, uint8_t ownEndpoint);

/* A device announced itself: it is interviewed from the start, as soon as a place among the parallel ones is free. */
void Interview_Joined(Interview *self, const Zb_StackJoined *joined, uint32_t nowMs);

/* A frame for the application: 1 when it was the answer a device's step was waiting for, 0 otherwise. */
int Interview_Data(Interview *self, const Aps_Indication *data, uint32_t nowMs);

/* A request's outcome: 1 when it was one of the interview's, 0 otherwise. A request not delivered is asked again. */
int Interview_Sent(Interview *self, ZbStatus status, const Aps_Confirm *sent, uint32_t nowMs);

/* Asks what is due and gives up on what waited too long; called on every turn of the application's loop. */
void Interview_Turn(Interview *self, uint32_t nowMs);

#endif /* EX_INTERVIEW_H */
