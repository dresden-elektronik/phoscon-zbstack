#ifndef APS_TCLINK_H
#define APS_TCLINK_H

/* The bodies of 4.4.11.4's Request-Key, 4.4.11.7's Verify-Key and 4.4.11.8's Confirm-Key commands, the three a trust
   centre exchanges with a device that updates its trust centre link key (4.7.3.8, D-218). Each body is what follows the
   command identifier, which Figure 2-8 makes the payload's first octet. */

/* The 64-bit addresses travel low octet first, which 1.2.3 states for every field of more than one octet. */

#include <stdint.h>
#include "zb_status.h"

enum
{
    /* Table 4-31's identifiers */
    APS_TCLINK_REQUEST_KEY_ID = 0x08,
    APS_TCLINK_VERIFY_KEY_ID = 0x0f,
    APS_TCLINK_CONFIRM_KEY_ID = 0x10,

    /* Table 4-19's RequestKeyType values: different numbers from Table 4-9's StandardKeyType (4.4.11.4.2) */
    APS_TCLINK_REQUEST_APPLICATION_KEY = 0x02,
    APS_TCLINK_REQUEST_TC_LINK_KEY = 0x04,

    APS_TCLINK_HASH_OCTETS = 16,

    /* Figures 4-15, 4-18 and 4-19 after the identifier */
    APS_TCLINK_REQUEST_TC_OCTETS = 1,
    APS_TCLINK_REQUEST_APP_OCTETS = 1 + 8,
    APS_TCLINK_VERIFY_OCTETS = 1 + 8 + APS_TCLINK_HASH_OCTETS,
    APS_TCLINK_CONFIRM_OCTETS = 1 + 1 + 8
};

typedef struct Aps_RequestKey
{
    uint8_t requestKeyType;          /* Table 4-19 */
    uint64_t partnerIeee;            /* 4.4.11.4.3: present for an application key only */
} Aps_RequestKey;

typedef struct Aps_VerifyKey
{
    uint8_t standardKeyType;         /* Table 4-9 */
    uint64_t sourceIeee;             /* 4.4.11.7.3 */
    uint8_t hash[APS_TCLINK_HASH_OCTETS]; /* 4.4.11.7.4's Initiator Verify-Key Hash Value */
} Aps_VerifyKey;

typedef struct Aps_ConfirmKey
{
    uint8_t status;                  /* Table 2-27 */
    uint8_t standardKeyType;         /* Table 4-9 */
    uint64_t destinationIeee;        /* 4.4.11.8.4 */
} Aps_ConfirmKey;

/* A Request-Key body: ZB_OK, or ZB_ERR_BAD_FRAME for a length its key type does not print. */
ZbStatus Aps_RequestKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_RequestKey *out);

/* A Verify-Key body: ZB_OK, or ZB_ERR_BAD_FRAME for any length but Figure 4-18's. */
ZbStatus Aps_VerifyKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_VerifyKey *out);

/* A Confirm-Key command's payload, its identifier first: 11 octets. */
ZbStatus Aps_ConfirmKeyCompose(uint8_t status, uint8_t standardKeyType, uint64_t destinationIeee, uint8_t *out,
                               uint32_t outMax, uint32_t *outLen);

/* A Request-Key command's payload for the trust centre link key, its identifier first: 2 octets. An application
   key request is not composed, so another type is ZB_ERR_BAD_ARGUMENT. */
ZbStatus Aps_RequestKeyCompose(uint8_t requestKeyType, uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* A Verify-Key command's payload, its identifier first: 26 octets. */
ZbStatus Aps_VerifyKeyCompose(const Aps_VerifyKey *verify, uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* A Confirm-Key body: ZB_OK, or ZB_ERR_BAD_FRAME for any length but Figure 4-19's. */
ZbStatus Aps_ConfirmKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_ConfirmKey *out);

#endif /* APS_TCLINK_H */
