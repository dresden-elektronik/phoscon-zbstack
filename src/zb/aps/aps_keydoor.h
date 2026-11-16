#ifndef APS_KEYDOOR_H
#define APS_KEYDOOR_H

/* 4.4.2's two APSME-TRANSPORT-KEY doors: the request that composes one (4.4.2.1.3 with 4.4.11's command frame) and
   the receipt that decides whether what arrived is kept (4.4.1.3's sender identification, 4.4.1.5's policy, and
   4.4.2.3's rules in the order it prints them). */

/* This module decides and composes; it installs nothing and rings nothing. The key that lands is 4.6.3.4.2's and the
   indication is the façade's, so a verdict here is a value a caller acts on rather than an effect. */

#include <stdint.h>

#include "aps_frame.h"
#include "aps_transportkey.h"
#include "security.h"
#include "zb_status.h"

/* Table 4-8's parameters with the two facts it leaves to the layer below: where the NLDE-DATA.request is aimed
   (4.4.2.1.3 sends to DestAddress, or to ParentAddress when UseParent is TRUE) and the radius it carries. A
   `sourceIeee` of 0 asks for the local device address, which 4.4.2.1.3 requires of the source sub-field. */
typedef struct Aps_TransportKeyReq
{
    uint64_t destIeee;         /* Table 4-8's DestAddress: the extended address of the destination device */
    uint16_t nwkDst;           /* that destination as the network layer names it */
    uint32_t standardKeyType;  /* Table 4-8's range 0x00-0x04, Table 4-9's values */
    uint8_t key[APS_TK_KEY_OCTETS];
    uint8_t keySeqNumber;      /* KeySeqNumber, which Figure 4-10 carries for a network key */
    uint64_t destinationIeee;  /* the descriptor's Destination address */
    uint64_t sourceIeee;       /* the descriptor's Source address; 0 means the local device address */
    uint64_t partnerIeee;      /* Figure 4-11's Partner address, for an application link key */
    int initiator;             /* Figure 4-11's Initiator, 1 or 0 */
    uint8_t radiusCounter;
    int tunnel;                /* Table 4-8's TunnelCommand: the secured command goes inside a Tunnel (4.4.2.1.3) */
    uint16_t tunnelNwk;        /* TunnelAddress, the parent the Tunnel is sent to, as the network layer names it */
    uint64_t tunnelIeee;       /* and its extended address */
} Aps_TransportKeyReq;

/* The AIB attributes 4.4.1.3, 4.4.1.5 and 4.4.2.3 read, gathered so a caller cannot hand over half of them. An
   all-F `trustCenterIeee` is 4.6.3.1's distributed security network, where no trust-centre test applies. */
typedef struct Aps_KeyPolicy
{
    uint64_t trustCenterIeee;      /* apsTrustCenterAddress */
    int requireLinkKeyEncryption;  /* requireLinkKeyEncryptionForApsTransportKey (4.4.2.3) */
    int joinedAndAuthorized;       /* 4.4.1.5's operating state, which decides the two MAY rows */
    int hasPreconfiguredLinkKey;   /* 4.4.1.5: this device holds a link key for the trust centre */
} Aps_KeyPolicy;

/* What became of a command that arrived. ACCEPT and FORWARD are the two outcomes 4.4.2.3 acts on; each drop names
   the rule that refused it, so a refusal can be counted and read without a second look at the frame. */
typedef enum Aps_KeyVerdict
{
    APS_KEY_ACCEPT = 0,                /* 4.4.2.3's indication is owed: the key is kept */
    APS_KEY_FORWARD = 1,               /* 4.4.2.3: a 0x01 or 0x04 key for somebody else, sent on with security disabled */
    APS_KEY_DROP_NOT_TRUST_CENTER = 2, /* 4.4.1.3: centralized, and the sender is not the trust centre */
    APS_KEY_DROP_POLICY = 3,           /* 4.4.2.3: unsecured while the policy requires APS encryption */
    APS_KEY_DROP_UNSECURED_KEY = 4,    /* 4.4.2.3: a key of type 0x01, 0x03 or 0x04 not secured with a link key */
    APS_KEY_DROP_DISTRIBUTED = 5       /* 4.4.2.3: an all-F source while apsTrustCenterAddress names a trust centre */
} Aps_KeyVerdict;

/* Figure 4-10's all-F source, which 4.4.2.3 reads as a distributed security network, and the 0x0000 that
   4.4.1.3's unsecured test compares the NWK source against. */
#define APS_KEY_IEEE_ALL_F 0xffffffffffffffff

/* 4.9.2's initial apsTrustCenterAddress, before a joining device has been sent its first key. */
#define APS_KEY_IEEE_UNSET 0x0000000000000000

enum
{
    APS_KEY_NWK_TRUST_CENTER = 0x0000
};

/* One command as it arrived, in the parts the three clauses read. `keyPairIeee` is the pair 4.4.1.2 protected the
   frame with, which is 4.4.1.3's secured test; `nwkSrc` is Table 3-4's source, its unsecured test. */
typedef struct Aps_KeyReceipt
{
    const Aps_TransportKey *body;
    int secured;
    uint64_t keyPairIeee;
    int keyPairKnown;
    uint16_t nwkSrc;
    uint64_t localIeee;
    const Aps_KeyPolicy *policy;
} Aps_KeyReceipt;

/* 4.4.2.1.3's descriptor duties and 4.4.11's command frame, from a request into the APDU a transaction stores:
   frame type 0x01, delivery unicast, an acknowledgement asked (4.4.11), the extended nonce bit where the frame is
   secured (4.4.1.1 step 4 a ii), and the command identifier Table 4-31 gives in front of Figure 4-8's body.
   ZB_ERR_BAD_ARGUMENT for a type Table 4-9 does not give or a missing buffer, ZB_ERR_NO_SPACE when outMax is short. */
ZbStatus Aps_TransportKeyComposeFrame(const Aps_TransportKeyReq *req, uint64_t ownIeee, uint8_t apsCounter,
                                      int apsSecurity, uint8_t *out, uint32_t outMax, uint32_t *outLen,
                                      uint32_t *headerLen);

/* Table 4-39's identifier a transported key is protected with: 0x02 for a network key and 0x03 for a link key, which
   is 4.4.1.1 step 1 b ii's rule and not the type octet's own value. */
uint32_t Aps_TransportKeyIdentifier(uint32_t standardKeyType);

/* 4.4.1.3 and then 4.4.2.3 over one command, in that order because 4.4.1.3 decides whether this device is the
   command's addressee at all and 4.4.2.3 what it does once it is; an unset apsTrustCenterAddress takes the key as the
   trust centre's, whose source names it (4.9.2). ZB_OK with `out` written, or ZB_ERR_BAD_ARGUMENT for a missing pointer. */
ZbStatus Aps_KeyVerdictFor(const Aps_KeyReceipt *receipt, Aps_KeyVerdict *out);

#endif /* APS_KEYDOOR_H */
