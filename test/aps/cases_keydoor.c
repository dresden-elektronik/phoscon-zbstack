/* The two APSME-TRANSPORT-KEY doors of R23.1 4.4.2 (docs/internals/conformance.md §2, docs/internals/conformance.md's `aps_keydoor.c` row).

   The sender half is asserted twice over: the octets `Aps_TransportKeyComposeFrame` writes against Figure 4-8 read
   out by hand, and what the service puts on the air when `Aps_TransportKeyRequest` takes the same request through a
   whole transaction. The receiver half is asserted as the decision it is: every rule 4.4.1.3 and 4.4.2.3 print, one
   case each, over `Aps_KeyVerdictFor` with the fields a receipt carries, and then one command taken end to end so the
   install 4.6.3.4.2 asks for is read off the module that holds the keys. */

#include "aps.h"
#include "aps_helpers.h"
#include "aes_hash.h"
#include "aps_keydoor.h"
#include "aps_transportkey.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The two devices these cases need: this one, and the trust centre it holds a link key for. */
#define OWN_SHORT 0xdead
#define ADDR_PEER 0x0011
#define ADDR_OTHER 0x0022

#define OWN_IEEE 0x00212effff048a12
#define PEER_IEEE 0x00212effff05a888
#define OTHER_IEEE 0x00212effff060000

#define ALL_F 0xffffffffffffffff

static const char *s_linkKeyHex = "0f0e0d0c0b0a09080706050403020100";
static const char *s_nwkKeyHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
static const char *s_newKeyHex = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

static Security_KeyPairEntry keyPairFor(uint64_t partner, uint16_t alias)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = partner;
    entry.shortAddress = alias;
    entry.shortKnown = 1;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = 1;
    entry.incomingFrameCounter = 0;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.verifiedFrameCounter = 1;
    Test_ParseHex(s_linkKeyHex, entry.key, SECURITY_KEY_OCTETS);

    return entry;
}

/* A receipt over one body, with everything 4.4.1.3 and 4.4.2.3 read set by the caller. */
static void receiptOf(Aps_KeyReceipt *receipt, const Aps_TransportKey *body, const Aps_KeyPolicy *policy)
{
    Zb_memset(receipt, 0, (uint32_t)sizeof *receipt);

    receipt->body = body;
    receipt->localIeee = OWN_IEEE;
    receipt->policy = policy;
}

static void bodyOf(Aps_TransportKey *body, uint32_t standardKeyType, uint64_t destination, uint64_t source)
{
    Zb_memset(body, 0, (uint32_t)sizeof *body);

    body->standardKeyType = standardKeyType;
    body->destinationIeee = destination;
    body->sourceIeee = source;
    body->keySeqNumber = 0x01;
    Test_ParseHex(s_nwkKeyHex, body->key, SECURITY_KEY_OCTETS);
}

/*
 * The sender door. 4.4.1.1 step 1 b ii's identifier, Figure 4-8's body behind Table 4-31's command identifier, and
 * the frame 4.4.11 prints around it: type 0x01, unicast, an acknowledgement asked, and 4.4.2.1.3's duty that the
 * source sub-field be the local device address when the request names none.
 */
void caseTransportKeyComposed(void)
{
    Aps_TransportKeyReq req;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t headerLen;
    uint32_t apduLen;

    Test_Expect(Aps_TransportKeyIdentifier(APS_TK_TYPE_NETWORK_KEY) == SECURITY_KEY_ID_KEY_TRANSPORT,
          "a transported network key is protected with Table 4-39's key-transport key, identifier 02 (4.4.1.1 step 1 b ii)");
    Test_Expect(Aps_TransportKeyIdentifier(APS_TK_TYPE_APPLICATION_LINK_KEY) == SECURITY_KEY_ID_KEY_LOAD
           && Aps_TransportKeyIdentifier(APS_TK_TYPE_TC_LINK_KEY) == SECURITY_KEY_ID_KEY_LOAD,
          "and a transported link key, application or trust-centre, with the key-load key, identifier 03: the two link key types share one protection");
    Test_Expect(Aps_TransportKeyIdentifier(0x00) == SECURITY_KEY_ID_DATA && Aps_TransportKeyIdentifier(0xb0) == SECURITY_KEY_ID_DATA,
          "while a type Table 4-9 does not give selects no transport key at all, which the door reads as the data identifier and refuses");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = PEER_IEEE;
    req.nwkDst = ADDR_PEER;
    req.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    req.keySeqNumber = 0x01;
    req.destinationIeee = PEER_IEEE;
    Test_ParseHex(s_newKeyHex, req.key, APS_TK_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&req, OWN_IEEE, 0x2a, 1, apdu, (uint32_t)sizeof apdu,
                                                   &apduLen, &headerLen), ZB_OK,
                  "a network-key command composes: Figure 4-8's body behind the command identifier, in Figure 2-8's payload");

    Test_Expect(headerLen == 2 && apduLen == 2 + 1 + APS_TK_NETWORK_BODY_OCTETS,
          "two octets of header (frame control, APS counter), Table 4-40's APS command header, then a payload of the identifier and Figure 4-10's 34: the header length is where 4.4.10's auxiliary header goes, in front of the identifier");

    Test_Expect(apdu[0] == 0x61,
          "the frame control is 0x61: frame type 0x01 command in bits 0-1, delivery unicast, security enabled in bit 5 and acknowledgement requested in bit 6 (4.4.11 with Figure 2-4)");
    Test_Expect(apdu[1] == 0x2a, "the APS counter is the one the caller passed, 2.2.5.1.7's octet held across the transaction");
    Test_Expect(apdu[2] == APS_TK_COMMAND_ID, "and Table 4-31's command identifier 0x05 sits where Figure 4-8 puts it");
    Test_Expect(apdu[3] == APS_TK_TYPE_NETWORK_KEY, "then Table 4-9's standard key type 0x01");
    Test_Expect(Zb_memcmp(apdu + 4, req.key, APS_TK_KEY_OCTETS) == 0, "then the key itself, 16 octets");
    Test_Expect(apdu[20] == 0x01, "then Figure 4-10's sequence number");
    Test_Expect(apdu[21] == 0x88 && apdu[28] == 0x00,
          "then the destination address low octet first, which 1.2.3 states for every field of more than one octet");

    req.sourceIeee = 0;
    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&req, OWN_IEEE, 0x2a, 1, apdu, (uint32_t)sizeof apdu,
                                                   &apduLen, &headerLen), ZB_OK,
                  "and a request that names no source address composes");
    Test_Expect(apdu[29] == 0x12 && apdu[36] == 0x00,
          "with the local device address in the source sub-field, which 4.4.2.1.3 makes the sender's duty rather than the caller's");

    req.sourceIeee = OTHER_IEEE;
    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&req, OWN_IEEE, 0x2a, 1, apdu, (uint32_t)sizeof apdu,
                                                   &apduLen, &headerLen), ZB_OK,
                  "while a request that names one is obeyed");
    Test_Expect(apdu[29] == 0x00 && apdu[30] == 0x00 && apdu[35] == 0x21,
          "so the source sub-field is that address and not this device's own");

    req.standardKeyType = 0x00;
    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&req, OWN_IEEE, 0x2a, 1, apdu, (uint32_t)sizeof apdu,
                                                   &apduLen, &headerLen), ZB_ERR_BAD_ARGUMENT,
                  "and a type Table 4-9 reserves is refused at composition rather than written as a command nobody may read");

    Test_ExpectStatus(Aps_TransportKeyComposeFrame(0, OWN_IEEE, 0x2a, 1, apdu, (uint32_t)sizeof apdu,
                                                   &apduLen, &headerLen), ZB_ERR_BAD_ARGUMENT,
                  "as is a call with no request");
}

/*
 * The receiver door, rule by rule. Each assertion names the clause it holds and one receipt's worth of fields; the
 * order they are read in is 4.4.1.3's then 4.4.2.3's, which is the order a command is decided in.
 */
void caseTransportKeyReceipts(void)
{
    Aps_TransportKey body;
    Aps_KeyPolicy policy;
    Aps_KeyReceipt receipt;
    Aps_KeyVerdict verdict;

    /* A centralized network: this device holds the trust centre's link key and no pair for anybody else. */
    Zb_memset(&policy, 0, (uint32_t)sizeof policy);
    policy.trustCenterIeee = PEER_IEEE;
    policy.joinedAndAuthorized = 1;
    policy.hasPreconfiguredLinkKey = 1;
    policy.requireLinkKeyEncryption = 1;

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, PEER_IEEE);
    receiptOf(&receipt, &body, &policy);

    receipt.secured = 1;
    receipt.keyPairIeee = PEER_IEEE;
    receipt.keyPairKnown = 1;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "a receipt is decided");
    Test_Expect(verdict == APS_KEY_ACCEPT,
          "a network key addressed to this device, secured with the trust centre's own link key, is kept: 4.4.1.3's secured test and 4.4.2.3's destination test both pass");

    receipt.keyPairIeee = OTHER_IEEE;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "and the same frame under another pair");
    Test_Expect(verdict == APS_KEY_DROP_NOT_TRUST_CENTER,
          "is discarded, because 4.4.1.3 says the key used must be the one the pair set holds for apsTrustCenterAddress: in a centralized network a command from any other device is not processed");

    receipt.keyPairIeee = PEER_IEEE;
    receipt.keyPairKnown = 0;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "a secured command with no pair this device can name");
    Test_Expect(verdict == APS_KEY_DROP_NOT_TRUST_CENTER,
          "cannot be shown to be the trust centre's, so 4.4.1.3 discards it");

    receipt.keyPairKnown = 1;
    receipt.secured = 0;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "an unsecured command in the same network");
    Test_Expect(verdict == APS_KEY_DROP_POLICY,
          "is dropped without processing: requireLinkKeyEncryptionForApsTransportKey is TRUE and 4.4.2.3 says such a message SHALL be dropped, which is also 4.4.1.5's device that holds a preconfigured link key");

    body.sourceIeee = OTHER_IEEE;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "and one whose source field names a third device");
    Test_Expect(verdict == APS_KEY_DROP_NOT_TRUST_CENTER,
          "is refused on 4.4.1.3's unsecured test first, which compares the frame's own IEEE source against apsTrustCenterAddress");

    /* The same network with the policy off: 4.4.1.5's device that has no preconfigured link key. */
    policy.requireLinkKeyEncryption = 0;
    policy.hasPreconfiguredLinkKey = 0;

    bodyOf(&body, APS_TK_TYPE_APPLICATION_LINK_KEY, 0, 0);
    body.partnerIeee = OTHER_IEEE;
    receiptOf(&receipt, &body, &policy);
    receipt.nwkSrc = ADDR_OTHER;

    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "an application link key, unsecured, from a device that is not the coordinator");
    Test_Expect(verdict == APS_KEY_DROP_NOT_TRUST_CENTER,
          "is refused: Figure 4-11 carries no source field for 4.4.1.3 to compare, so it verifies the NWK source against the coordinator's own address instead");

    receipt.nwkSrc = 0x0000;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "the same command from the coordinator");
    Test_Expect(verdict == APS_KEY_DROP_UNSECURED_KEY,
          "reaches 4.4.2.3 and is discarded there, which prints that a 0x03 or 0x04 key not secured with a link key SHALL be discarded: the second rule and not the first");

    /* A distributed network: no trust centre to compare against, and Figure 4-10's all-F source is how it says so. */
    policy.trustCenterIeee = ALL_F;
    policy.joinedAndAuthorized = 0;

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, ALL_F);
    receiptOf(&receipt, &body, &policy);
    receipt.secured = 1;
    receipt.keyPairIeee = PEER_IEEE;
    receipt.keyPairKnown = 1;

    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "a secured network key with an all-F source in a distributed network");
    Test_Expect(verdict == APS_KEY_ACCEPT,
          "is kept: 4.4.2.3 allows that source only while apsTrustCenterAddress is all-F too, and here it is");

    policy.trustCenterIeee = PEER_IEEE;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "and the same frame in a centralized network");
    Test_Expect(verdict == APS_KEY_DROP_DISTRIBUTED,
          "is dropped: 4.4.2.3's \"Otherwise, it SHALL be dropped and no further processing shall be done\"");

    /* 4.4.2.3's broadcast carve-out, which 4.4.1.5 restates as a SHALL. */
    policy.trustCenterIeee = PEER_IEEE;
    policy.joinedAndAuthorized = 1;
    policy.requireLinkKeyEncryption = 1;
    policy.hasPreconfiguredLinkKey = 1;

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, 0, PEER_IEEE);
    receiptOf(&receipt, &body, &policy);

    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "an unsecured broadcast network key");
    Test_Expect(verdict == APS_KEY_ACCEPT,
          "is accepted by a device in the joined and authorized state, which 4.4.1.5 prints as a SHALL and 4.4.2.3 as a MAY: the all-zero destination is Figure 4-10's broadcast key, and its destination field SHALL be ignored upon reception");

    policy.joinedAndAuthorized = 0;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "the same broadcast to a device that is not yet authorized");
    Test_Expect(verdict == APS_KEY_DROP_POLICY,
          "falls back to the policy, which requires APS encryption of it");

    /* 4.4.2.3's forwarding duty. */
    policy.joinedAndAuthorized = 1;

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OTHER_IEEE, PEER_IEEE);
    receiptOf(&receipt, &body, &policy);
    receipt.secured = 1;
    receipt.keyPairIeee = PEER_IEEE;
    receipt.keyPairKnown = 1;

    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "a network key addressed to somebody else");
    Test_Expect(verdict == APS_KEY_FORWARD,
          "is sent on rather than kept: 4.4.2.3 issues an NLDE-DATA.request with security disabled to the address the destination field names");

    bodyOf(&body, APS_TK_TYPE_TC_LINK_KEY, OTHER_IEEE, PEER_IEEE);
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "as is a trust-centre link key for somebody else, which 4.4.2.3 names in the same sentence");

    bodyOf(&body, APS_TK_TYPE_APPLICATION_LINK_KEY, 0, 0);
    body.partnerIeee = OTHER_IEEE;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "while an application link key has no destination field at all");
    Test_Expect(verdict == APS_KEY_ACCEPT,
          "and is kept wherever it was addressed: Figure 4-11 prints a partner address and no destination, so the forwarding rule cannot apply to it");

    Test_ExpectStatus(Aps_KeyVerdictFor(0, &verdict), ZB_ERR_BAD_ARGUMENT, "and a call with no receipt is refused");
}

/* The door's refusals, each before a transaction slot is taken: no material, a type Table 4-9 does not give, and a
   destination this device holds no pair for, which is 4.4.1.1 step 1's own precondition. */
void caseTransportKeyRequestRefusals(void)
{
    Rig rig;
    Security security;
    Security_Config cfg;
    Security_KeyDescriptor key;
    Security_KeyPairEntry pairs[1];
    Aps_TransportKeyReq req;

    pairs[0] = keyPairFor(PEER_IEEE, ADDR_PEER);

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = PEER_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;

    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK, "the trust centre's own material");

    rigBuild(&rig, OWN_SHORT);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = PEER_IEEE;
    req.nwkDst = ADDR_PEER;
    req.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    req.keySeqNumber = 0x01;
    req.destinationIeee = PEER_IEEE;
    Test_ParseHex(s_newKeyHex, req.key, APS_TK_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyRequest(0, &req, 0), ZB_ERR_BAD_ARGUMENT, "a call with no service is refused");

    Test_ExpectStatus(Aps_TransportKeyRequest(&rig.aps, &req, 0), ZB_ERR_AUTH,
                  "and one on a service with no `Security` attached is refused for want of material rather than composed unsecured");

    Aps_AttachSecurity(&rig.aps, &security);

    req.standardKeyType = 0x00;
    Test_ExpectStatus(Aps_TransportKeyRequest(&rig.aps, &req, 0), ZB_ERR_BAD_ARGUMENT,
                  "a type Table 4-9 reserves is refused, 0x00 among them");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0,
          "with no transaction taken for it");

    req.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    req.destIeee = OTHER_IEEE;
    req.destinationIeee = OTHER_IEEE;

    Test_Expect(Security_FindKeyPairByIeee(&security, OTHER_IEEE) < 0,
          "and a destination this device holds no pair for is the case 4.4.1.1 step 1 cannot answer: there is no key to protect the command with");
    Test_ExpectStatus(Aps_TransportKeyRequest(&rig.aps, &req, 0), ZB_ERR_NOT_FOUND,
                  "which the door refuses by name");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_RefusedRequests(&rig.aps) == 3,
          "leaving the pool empty and every one of the three refusals counted");

    req.destIeee = PEER_IEEE;
    req.destinationIeee = PEER_IEEE;

    Test_ExpectStatus(Aps_TransportKeyRequest(&rig.aps, &req, 0), ZB_OK,
                  "while the pair it does hold takes the request");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 1,
          "as one transaction, aimed at the destination the request named");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0,
          "and 4.4.2 prints no confirm for it, so no answer is owed through the confirmation ring");
}

/*
 * One transport key taken end to end: an unsecured network key in a distributed security network, which is 4.4.2.3's
 * own permitted case, arriving at a device that holds no preconfigured link key. What the door does with it is read
 * off the module that holds the keys, and off the indication ring 4.4.2.2 owes.
 */
void caseTransportKeyInstalled(void)
{
    Rig rig;
    Security security;
    Security_Config cfg;
    Security_KeyDescriptor key;
    Security_KeyState state;
    Test_BandA peer;
    Aps_TransportKey body;
    Aps_KeyIndication inds[2];
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t *out;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t i;

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = ALL_F;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;

    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "a device in a distributed security network: apsTrustCenterAddress all-F (4.6.3.1), one network key and no key pair");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, ALL_F);
    body.keySeqNumber = 0x01;
    Test_ParseHex(s_newKeyHex, body.key, APS_TK_KEY_OCTETS);

    out = apdu;
    out[0] = 0x41;
    out[1] = 0x2b;
    out[2] = (uint8_t)APS_TK_COMMAND_ID;

    Test_ExpectStatus(Aps_TransportKeyCompose(&body, out + 3, (uint32_t)sizeof apdu - 3, &len), ZB_OK,
                  "and a command frame this suite writes by hand: an unsecured command header and Figure 4-10's body");
    len = len + 3;

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_KeyInstalled(&rig.aps) == 1 && Aps_KeyInstallFailed(&rig.aps) == 0,
          "the key lands: 4.6.3.4.2's install answered ZB_OK, and the door kept what 4.4.2.3 allowed");

    Security_Snapshot(&security, &state);

    Test_Expect(state.keyCount == 2,
          "which the key set shows as two descriptors: in the normal operating state 4.6.3.4.2 replaces the alternate entry, so the active key is untouched");
    Test_Expect(state.nwkActiveKeySeqNumber == 0x00,
          "and the active sequence number is still the one this device started with");

    Test_Expect(Aps_KeyIndicationQueue(&rig.aps) == 1,
          "one APSME-TRANSPORT-KEY.indication is owed, which is what 4.4.2.3 issues for a key it kept");

    Test_Expect(Aps_PollKeyIndications(&rig.aps, inds, 2) == 1, "and it is drained");
    Test_Expect(inds[0].standardKeyType == APS_TK_TYPE_NETWORK_KEY && inds[0].keySeqNumber == 0x01,
          "naming the key type and the sequence number the command carried");
    Test_Expect(Zb_memcmp(inds[0].key, body.key, APS_TK_KEY_OCTETS) == 0,
          "and the key itself, 16 octets of it");
    Test_Expect(inds[0].srcIeee == ALL_F,
          "with the SrcAddress parameter set to the command's own source field, which is 4.4.2.3's instruction for a key type of 0x01");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS, "and the status this module gives a key it installed");
    Test_Expect(Aps_KeyIndicationQueue(&rig.aps) == 0, "leaving the ring empty");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1,
          "and the command is acknowledged, which 4.4.11 asks of every unicast command: a trust centre that got no answer would re-send the key and count the transaction as failed");

    for (i = 0; i < 1; i++)
        (void)i;
}

/*
 * 4.6.3.2.3: "the joiner sets apsTrustCenterAddress to the indication's SrcAddress and is authorized". The install is
 * what carries that, so the predicate 3.6.1.6.1.1's wait reads answers differently before and after it.
 */
void caseTransportKeyAuthorizes(void)
{
    Rig rig;
    Security security;
    Security sender;
    Security_Config cfg;
    Security_Config senderCfg;
    Security_KeyPairEntry pairs[1];
    Security_KeyPairEntry senderPairs[1];
    Test_BandA peer;
    Aps_TransportKey body;
    Aps_TransportKeyReq keyReq;
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t plain[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t headerLen;
    uint32_t securedLen;
    uint32_t len;

    pairs[0] = keyPairFor(PEER_IEEE, ADDR_PEER);
    senderPairs[0] = keyPairFor(OWN_IEEE, OWN_SHORT);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = PEER_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 0;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;

    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "a joining device: a level, the trust centre's link key and no network key");
    Test_Expect(Security_IsEnabled(&security) == 0,
          "which is not enabled, because the active key it would protect with is the one it is waiting for");

    Zb_memset(&senderCfg, 0, (uint32_t)sizeof senderCfg);
    senderCfg.ownIeee = PEER_IEEE;
    senderCfg.trustCenterIeee = PEER_IEEE;
    senderCfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    senderCfg.authenticated = 1;
    senderCfg.keyPairs = senderPairs;
    senderCfg.keyPairCount = 1;

    Test_ExpectStatus(Security_Init(&sender, &senderCfg), ZB_OK,
                  "and the trust centre's own module, holding the same link key for this device");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, PEER_IEEE);
    body.keySeqNumber = 0x01;
    Test_ParseHex(s_newKeyHex, body.key, APS_TK_KEY_OCTETS);

    Zb_memset(&keyReq, 0, (uint32_t)sizeof keyReq);
    keyReq.destIeee = OWN_IEEE;
    keyReq.nwkDst = OWN_SHORT;
    keyReq.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    keyReq.keySeqNumber = 0x01;
    keyReq.destinationIeee = OWN_IEEE;
    Zb_memcpy(keyReq.key, body.key, APS_TK_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&keyReq, PEER_IEEE, 0x2b, 1, plain, (uint32_t)sizeof plain,
                                                   &len, &headerLen), ZB_OK,
                  "the command the trust centre composes, with its APS half secured and its NWK half not: 4.6.3.2.1's combination for a joiner");
    Test_ExpectStatus(Security_ProtectAps(&sender, 0, SECURITY_KEY_ID_KEY_TRANSPORT, plain, headerLen,
                                          plain + headerLen, len - headerLen, 1, apdu,
                                          (uint32_t)sizeof apdu, &securedLen), ZB_OK,
                  "protected with the key-transport key of the pair's link key, which 4.4.1.1 step 1 b ii selects");

    /* The octets as a receiver that shares none of this code reads them: the auxiliary
       header straight after the two header octets, and the command identifier inside the encrypted region. */
    Test_Expect(securedLen == 2 + 1 + 4 + 8 + 1 + APS_TK_NETWORK_BODY_OCTETS + 4,
          "two octets of header, five of auxiliary plus the source address, the encrypted identifier and body, and a 4-octet MIC at level 5");
    Test_Expect(apdu[0] == 0x61 && apdu[1] == 0x2b, "the frame control and the APS counter, and nothing else in front of the auxiliary header");
    Test_Expect(apdu[2] == 0x30,
          "then the security control 0x30: key identifier 0x02 the key-transport key, extended nonce set, level cleared on the air as 4.4.1.1 prints");
    Test_Expect(apdu[3] == 0x01 && apdu[4] == 0x00 && apdu[5] == 0x00 && apdu[6] == 0x00,
          "then the pair's outgoing frame counter, low octet first");
    Test_Expect(apdu[7] == 0x88 && apdu[8] == 0xa8 && apdu[9] == 0x05 && apdu[14] == 0x00,
          "then the trust centre's own address as the extended nonce source, low octet first");
    Test_Expect(apdu[15] != APS_TK_COMMAND_ID || apdu[16] != APS_TK_TYPE_NETWORK_KEY,
          "and the identifier and key type are not in clear after it: Figure 2-8 makes the identifier payload, so it is encrypted");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, securedLen, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_KeyInstalled(&rig.aps) == 1, "the key lands through 4.6.3.4.2");
    Test_Expect(Security_IsEnabled(&security) == 1,
          "and the device is authorized by it, which is 4.6.3.2.3's own sentence: the predicate the join's wait reads now answers enabled");
    Test_Expect(Security_IsAuthenticated(&security) == 1, "which is the state 3.6.2.2's unsecured discard applies in");
    Test_Expect(security.keyPairs[0].verifiedFrameCounter == 1,
          "and the pair the key came from is verified by it, with that command's own counter past the window: 4.6.3.8's last paragraph, which is why a joiner needs no challenge");
}

/* 4.9.2: apsTrustCenterAddress starts unset, so the first key is the trust centre's whichever pair opened it, and its
   install sets the address from the key's source field in the security module and the network layer's copy, which
   4.4.1.3 then compares against. */
void caseTransportKeyTeachesTheTrustCentre(void)
{
    Rig rig;
    Security security;
    Security sender;
    Security_Config cfg;
    Security_Config senderCfg;
    Security_KeyPairEntry pairs[1];
    Security_KeyPairEntry senderPairs[1];
    Test_BandA peer;
    Aps_TransportKey body;
    Aps_KeyPolicy policy;
    Aps_KeyReceipt receipt;
    Aps_KeyVerdict verdict;
    Aps_TransportKeyReq keyReq;
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t plain[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t headerLen;
    uint32_t securedLen;
    uint32_t len;

    Zb_memset(&policy, 0, (uint32_t)sizeof policy);
    policy.trustCenterIeee = APS_KEY_IEEE_UNSET;
    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, PEER_IEEE);
    receiptOf(&receipt, &body, &policy);
    receipt.secured = 1;
    receipt.keyPairIeee = OTHER_IEEE;
    receipt.keyPairKnown = 1;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "a receipt at a device that knows no trust centre");
    Test_Expect(verdict == APS_KEY_ACCEPT, "is the trust centre's, whichever pair secured it (4.9.2)");

    pairs[0] = keyPairFor(0, 0);
    pairs[0].shortKnown = 0;
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    senderPairs[0] = keyPairFor(OWN_IEEE, OWN_SHORT);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = APS_KEY_IEEE_UNSET;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                      "a joining device holding the global link key and no trust centre address");

    Zb_memset(&senderCfg, 0, (uint32_t)sizeof senderCfg);
    senderCfg.ownIeee = PEER_IEEE;
    senderCfg.trustCenterIeee = PEER_IEEE;
    senderCfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    senderCfg.authenticated = 1;
    senderCfg.keyPairs = senderPairs;
    senderCfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&sender, &senderCfg), ZB_OK, "and the trust centre's module");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    Nwk_SetTrustCenter(&rig.stack.nwk, 0);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    Zb_memset(&keyReq, 0, (uint32_t)sizeof keyReq);
    keyReq.destIeee = OWN_IEEE;
    keyReq.nwkDst = OWN_SHORT;
    keyReq.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    keyReq.keySeqNumber = 0x01;
    keyReq.destinationIeee = OWN_IEEE;
    Test_ParseHex(s_newKeyHex, keyReq.key, APS_TK_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyComposeFrame(&keyReq, PEER_IEEE, 0x2b, 1, plain, (uint32_t)sizeof plain,
                                                   &len, &headerLen), ZB_OK, "the trust centre's key for the joiner");
    Test_ExpectStatus(Security_ProtectAps(&sender, 0, SECURITY_KEY_ID_KEY_TRANSPORT, plain, headerLen,
                                          plain + headerLen, len - headerLen, 1, apdu,
                                          (uint32_t)sizeof apdu, &securedLen), ZB_OK,
                      "secured under the key-transport key");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, securedLen, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_ExpectCount(Aps_KeyInstalled(&rig.aps), 1, "the key lands");
    Test_Expect(security.trustCenterIeee == PEER_IEEE,
                "and apsTrustCenterAddress is the key's source field now, the address 4.9.2 says the packet carries");
    Test_Expect(rig.stack.nwk.trustCenterIeee == PEER_IEEE, "in the network layer's copy as well");

    policy.trustCenterIeee = security.trustCenterIeee;
    Test_ExpectStatus(Aps_KeyVerdictFor(&receipt, &verdict), ZB_OK, "so the same receipt again");
    Test_Expect(verdict == APS_KEY_DROP_NOT_TRUST_CENTER,
                "under a pair that is not the trust centre's is refused, 4.4.1.3 having an address to compare against");
}

/*
 * 2.2.4.1.1.3 and 2.2.4.1.3.2, the two halves of Table 3-66's nwkAddressMap that the APS layer reads: a mode-0x03
 * destination is mapped to its 16-bit address before the frame is sent, and a delivery whose source the map holds is
 * indicated with that 64-bit address.
 */
void caseAddressMapBothWays(void)
{
    Rig rig;
    Test_BandA peer;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication inds[2];
    Nwk_AddressMapEntry *map;
    uint8_t apdu[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    static const uint8_t asdu[ASDU_LEN] = { 1, 2, 3, 4, 5, 6 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    map = Nwk_AddrMapOf(&rig.stack.nwk);
    Test_Expect(map != 0, "the stack carries Table 3-66's map");
    Test_ExpectCount(Nwk_AddrMapCount(map), 0, "and it starts empty");

    req = sapReq(APS_ADDR_MODE_EXTENDED, 0, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, APS_TX_OPTION_ACK);
    req.dstExtendedAddress = PEER_IEEE;

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "a mode-0x03 destination is taken");
    Test_ExpectCount(Aps_ConfirmQueue(&rig.aps), 1, "and answered at once");
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1
           && confirms[0].apsStatus == APS_STATUS_NO_SHORT_ADDRESS,
           "with NO_SHORT_ADDRESS, which 2.2.4.1.1.3 prints for a 64-bit address the map cannot place");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing went on the air for it");

    Test_Expect(Nwk_AddrMapLearn(map, ADDR_PEER, PEER_IEEE, OWN_SHORT, 110) == NWK_ADDRMAP_LEARNED,
                "a row for the peer, as 3.6.1.10.1 would have made it from a frame");

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 120), ZB_OK, "and the same request again");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "now goes out, one frame");
    Test_Expect(airCount == 1 && airDestOf(&air[0]) == ADDR_PEER,
           "addressed to the short address the map gave it, and not to a broadcast or to 0x0000");

    /* The indication half: a data frame from the peer, whose source the map now holds. */
    len = 0;
    Zb_memset(apdu, 0, (uint32_t)sizeof apdu);
    apdu[len++] = 0x40;
    apdu[len++] = 0x2b;
    apdu[len++] = DST_EP;
    apdu[len++] = (uint8_t)CLUSTER_ID;
    apdu[len++] = (uint8_t)(CLUSTER_ID >> 8);
    apdu[len++] = (uint8_t)PROFILE_ID;
    apdu[len++] = (uint8_t)(PROFILE_ID >> 8);
    apdu[len++] = SRC_EP;

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 130);
    stepAt(&rig, air, &airCount, 131);

    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "the frame is delivered once");
    Test_Expect(inds[0].srcAddrMode == APS_ADDR_MODE_EXTENDED && inds[0].srcExtendedAddress == PEER_IEEE,
           "and its source is named by the 64-bit address the map holds, which is 2.2.4.1.3.2's mode 0x03");
    Test_Expect(inds[0].srcAddress == ADDR_PEER, "with the 16-bit address filled as well");

    Test_Expect(Nwk_AddrMapLearn(map, ADDR_PEER, 0x00212effff060000, OWN_SHORT, 140) == NWK_ADDRMAP_CONFLICT_OTHER,
                "and a second 64-bit address at that short address is a conflict, so the row cannot be silently rewritten");
}

/*
 * A Transport Key answered the way a TRÅDFRI bulb answers it: Figure 2-10's ACK format 1, which carries the frame
 * control and the APS counter and no endpoint or cluster, secured with the data key and the extended nonce clear
 * (Table 4-41's ACK to Command). The trust centre holds the global pair and learns the
 * joiner's address from its map. An ACK format 0 with the same counter answers a datagram and not this command.
 */
void caseTransportKeyAcknowledged(void)
{
    Rig rig;
    Security security;
    Security joiner;
    Security_Config cfg;
    Security_Config joinerCfg;
    Security_KeyDescriptor key;
    Security_KeyPairEntry pairs[1];
    Security_KeyPairEntry joinerPairs[1];
    Test_BandA peer;
    Aps_TransportKeyReq req;
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t sentBefore;
    uint32_t len;
    uint8_t counter;

    pairs[0] = keyPairFor(0, 0);
    pairs[0].shortKnown = 0;
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    joinerPairs[0] = keyPairFor(OWN_IEEE, OWN_SHORT);

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK, "a trust centre holding only the global pair");

    Zb_memset(&joinerCfg, 0, (uint32_t)sizeof joinerCfg);
    joinerCfg.ownIeee = PEER_IEEE;
    joinerCfg.trustCenterIeee = OWN_IEEE;
    joinerCfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    joinerCfg.keyPairs = joinerPairs;
    joinerCfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&joiner, &joinerCfg), ZB_OK, "and the joiner's module, holding the same link key");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(&rig.stack.nwk), ADDR_PEER, PEER_IEEE, OWN_SHORT, 90)
                == NWK_ADDRMAP_LEARNED, "the map holds the joiner, as its own NWK headers teach it");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = PEER_IEEE;
    req.nwkDst = ADDR_PEER;
    req.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    req.destinationIeee = PEER_IEEE;
    Test_ParseHex(s_nwkKeyHex, req.key, APS_TK_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyRequest(&rig.aps, &req, 100), ZB_OK, "the trust centre sends the joiner its key");
    stepAt(&rig, air, &airCount, 101);
    Test_Expect(airCount == 1 && rig.aps.tx[0].state == APS_TX_AWAITING_ACK,
          "one frame out, and the transaction waits for its acknowledgement (4.4.11)");
    counter = rig.aps.tx[0].apsCounter;

    len = ackApdu(apdu, counter, DST_EP, SRC_EP, CLUSTER_ID);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 110);
    stepAt(&rig, air, &airCount, 111);
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 1 && rig.aps.tx[0].state == APS_TX_AWAITING_ACK,
          "an ACK format 0 with the same counter answers a datagram, so it leaves the command waiting");

    plain[0] = 0x32;               /* Figure 2-4: frame type acknowledgement, ACK format 1, security set */
    plain[1] = counter;
    Test_ExpectStatus(Security_ProtectAps(&joiner, 0, SECURITY_KEY_ID_DATA, plain, 2, plain + 2, 0, 0, apdu,
                                          (uint32_t)sizeof apdu, &len), ZB_OK,
                      "the joiner secures its ACK format 1 with the data key and the extended nonce clear");
    Test_Expect(len == 2 + 5 + 4, "two octets of header, five of auxiliary and the MIC: the bulb's own shape");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 120);
    stepAt(&rig, air, &airCount, 121);
    Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_UnmatchedAcks(&rig.aps) == 1
           && rig.aps.tx[0].state == APS_TX_FREE,
          "and it releases the transaction: matched on the counter and the source, the only fields Figure 2-10 carries");

    sentBefore = airCount;
    stepAt(&rig, air, &airCount, 2000);
    Test_Expect(airCount == sentBefore, "so no retry follows apscAckWaitDuration later");
}

/* The first air frame from `from` on whose APS frame control `fcf` is written, or -1. */
static int keydoorFrameWith(const Air *air, uint32_t from, uint32_t count, uint8_t fcf)
{
    uint32_t i;

    for (i = from; i < count; i++)
    {
        if (apduLenOf(&air[i]) > 2 && apduOf(&air[i])[0] == fcf)
            return (int)i;
    }

    return -1;
}

/*
 * 4.7.3.8's exchange at a trust centre that holds only the global pair (D-218): a joiner's Request-Key for the trust
 * centre link key answered with a Transport-Key of type 0x04 under the key-load key of the key the joiner holds, the
 * new key the keyed hash of the joiner's address under the seed, written unverified; then the joiner's Verify-Key,
 * checked against B.1.4's hash of 0x03, verifying the entry and answered by a Confirm-Key under the new key; and a
 * Verify-Key with a wrong hash answered SECURITY_FAIL. The joiner's frames are its own module's, and the octets the
 * trust centre sent are read back by that module, not by the one that wrote them.
 */
void caseTcLinkKeyExchange(void)
{
    Rig rig;
    Security security;
    Security joiner;
    Security_Config cfg;
    Security_Config joinerCfg;
    Security_KeyDescriptor key;
    Security_KeyPairEntry pairs[1];
    Security_KeyPairEntry joinerPairs[1];
    Security_ApsResult result;
    Test_BandA peer;
    Aps_TransportKey body;
    uint8_t seed[SECURITY_KEY_OCTETS];
    uint8_t derived[SECURITY_KEY_OCTETS];
    uint8_t hash[SECURITY_KEY_OCTETS];
    uint8_t address[8];
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t clear[APS_FRAME_MAX];
    uint8_t verifyInput = 0x03;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t clearLen = 0;
    uint32_t before;
    uint32_t len = 0;
    uint32_t i;
    int found;
    int index;

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        seed[i] = (uint8_t)(0x40 + i);

    for (i = 0; i < 8; i++)
        address[i] = (uint8_t)((PEER_IEEE >> (8 * i)) & 0xff);

    Test_ExpectStatus(Aes_MmoHmac(seed, SECURITY_KEY_OCTETS, address, 8, derived), ZB_OK,
                      "the key the joiner should be given: B.1.4's keyed hash of its address under the seed");
    Test_ExpectStatus(Aes_MmoHmac(derived, SECURITY_KEY_OCTETS, &verifyInput, 1, hash), ZB_OK,
                      "and the Initiator Verify-Key Hash Value of that key (4.4.11.7.4)");

    pairs[0] = keyPairFor(0, 0);
    pairs[0].shortKnown = 0;
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    joinerPairs[0] = keyPairFor(OWN_IEEE, OWN_SHORT);

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;
    cfg.linkKeySeed = seed;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK, "a trust centre with the global pair and a link key seed");

    Zb_memset(&joinerCfg, 0, (uint32_t)sizeof joinerCfg);
    joinerCfg.ownIeee = PEER_IEEE;
    joinerCfg.trustCenterIeee = OWN_IEEE;
    joinerCfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    joinerCfg.keyPairs = joinerPairs;
    joinerCfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&joiner, &joinerCfg), ZB_OK, "and a joiner holding the same global key");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    plain[0] = 0x61;               /* Figure 2-4: command, unicast, security and acknowledgement request set */
    plain[1] = 0x40;
    plain[2] = 0x08;               /* Table 4-31's Request-Key */
    plain[3] = 0x04;               /* Table 4-19's trust centre link key */
    Test_ExpectStatus(Security_ProtectAps(&joiner, 0, SECURITY_KEY_ID_DATA, plain, 2, plain + 2, 2, 1, apdu,
                                          (uint32_t)sizeof apdu, &len), ZB_OK,
                      "the joiner's Request-Key, APS encrypted as 4.7.3.8 step 1 requires");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_TcLinkKeysSent(&rig.aps) == 1 && Aps_TcLinkKeyRequestsDropped(&rig.aps) == 0,
          "the trust centre answers it with a key (4.7.3.8.1)");

    found = keydoorFrameWith(air, 0, airCount, 0x61);
    Test_Expect(found >= 0 && apduOf(&air[found])[2] == 0x38,
          "a secured command on the air whose security control is 0x38: the key-load key, extended nonce set");

    if (found >= 0)
    {
        Test_ExpectStatus(Security_UnprotectAps(&joiner, apduOf(&air[found]), apduLenOf(&air[found]), 2, OWN_IEEE, 1,
                                                clear, (uint32_t)sizeof clear, &clearLen, &result), ZB_OK,
                          "which the joiner's module opens with the key it already holds");
        Test_Expect(clearLen > 1 && clear[0] == APS_TK_COMMAND_ID
                    && Aps_TransportKeyParse(clear + 1, clearLen - 1, &body) == ZB_OK,
              "and reads as a Transport-Key");
        Test_Expect(body.standardKeyType == APS_TK_TYPE_TC_LINK_KEY && Zb_memcmp(body.key, derived, 16) == 0
                    && body.destinationIeee == PEER_IEEE && body.sourceIeee == OWN_IEEE,
              "of type 0x04 carrying the derived key, addressed to the joiner from the trust centre (Figure 4-9)");
    }

    index = Security_FindKeyPairByIeee(&security, PEER_IEEE);
    Test_Expect(index >= 0 && security.keyPairs[index].deviceIeee == PEER_IEEE
                && security.keyPairs[index].keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED
                && security.keyPairs[index].linkKeyType == SECURITY_LINK_KEY_UNIQUE
                && Zb_memcmp(security.keyPairs[index].key, derived, 16) == 0,
          "and the trust centre holds a unique, unverified entry for the joiner with that key (4.7.3.8.1 step 2)");

    if (found >= 0)
    {
        uint8_t ack[2];

        ack[0] = 0x32;             /* ACK format 1, security set: the bulb's acknowledgement of a command */
        ack[1] = apduOf(&air[found])[1];
        Test_ExpectStatus(Security_ProtectAps(&joiner, 0, SECURITY_KEY_ID_DATA, ack, 2, ack + 2, 0, 0, apdu,
                                              (uint32_t)sizeof apdu, &len), ZB_OK,
                          "the joiner acknowledges the key under the key it still holds");
        peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 105);
        stepAt(&rig, air, &airCount, 106);
        Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_CommandAnswers(&rig.aps) == 1
                    && Aps_CommandFailures(&rig.aps) == 0,
              "and the trust centre reads it through the global key, the new entry being unverified (D-218), which releases the key's transaction");
    }

    Zb_memcpy(joiner.keyPairs[0].key, derived, SECURITY_KEY_OCTETS);
    joiner.keyPairs[0].incomingFrameCounter = 0;    /* the joiner installs the key as a fresh entry, counters at 0 */
    joiner.keyPairs[0].outgoingFrameCounter = 0;

    len = 0;
    plain[len++] = 0x41;           /* command, unicast, acknowledgement request set, APS security clear */
    plain[len++] = 0x41;
    plain[len++] = 0x0f;           /* Table 4-31's Verify-Key */
    plain[len++] = 0x04;

    for (i = 0; i < 8; i++)
        plain[len++] = address[i];

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        plain[len++] = hash[i];

    before = airCount;
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, plain, len, 110);
    stepAt(&rig, air, &airCount, 111);

    Test_Expect(Aps_VerifyKeysConfirmed(&rig.aps) == 1 && Aps_VerifyKeysRefused(&rig.aps) == 0
                && security.keyPairs[index].keyAttributes == SECURITY_KEYPAIR_ATTR_VERIFIED
                && security.keyPairs[index].incomingFrameCounter == 0,
          "the Verify-Key's hash matches, so the entry is verified and its incoming counter is 0 (4.4.7.2.3 step 9, 4.4.8.1 step 7)");

    found = keydoorFrameWith(air, before, airCount, 0x61);
    Test_Expect(found >= 0, "and a secured command answers it");

    if (found >= 0)
    {
        Test_ExpectStatus(Security_UnprotectAps(&joiner, apduOf(&air[found]), apduLenOf(&air[found]), 2, OWN_IEEE, 1,
                                                clear, (uint32_t)sizeof clear, &clearLen, &result), ZB_OK,
                          "which the joiner opens with the new key");
        Test_Expect(clearLen == 11 && clear[0] == 0x10 && clear[1] == APS_STATUS_SUCCESS && clear[2] == 0x04
                    && clear[3] == address[0] && clear[10] == address[7],
              "a Confirm-Key, status SUCCESS, key type 0x04, the joiner's address (Figure 4-19)");
    }

    plain[len - 1] = (uint8_t)(plain[len - 1] ^ 0x01);
    plain[1] = 0x42;
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, plain, len, 120);
    stepAt(&rig, air, &airCount, 121);

    Test_Expect(Aps_VerifyKeysRefused(&rig.aps) == 1,
          "a Verify-Key whose hash is wrong is refused (4.4.7.2.3 step 7b) and answered SECURITY_FAIL");
}

/* 4.4.2.3 after joining: a key the trust centre sends under the global link key, whose pair names no device, comes
   from the sender the decryption authenticated, so a joined device takes it rather than refusing it as not the trust
   centre's. */
void caseTransportKeyUnderTheGlobalKeyAfterJoining(void)
{
    Rig rig;
    Security security;
    Security trustCentre;
    Security_Config cfg;
    Security_Config centreCfg;
    Security_KeyDescriptor key;
    Security_KeyPairEntry pairs[1];
    Security_KeyPairEntry centrePairs[1];
    Test_BandA peer;
    Aps_TransportKey body;
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t bodyLen = 0;
    uint32_t len = 0;

    pairs[0] = keyPairFor(0, 0);
    pairs[0].shortKnown = 0;
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    centrePairs[0] = pairs[0];

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = PEER_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                      "a joined device: the network key, its trust centre known, and only the global link key");

    centreCfg = cfg;
    centreCfg.ownIeee = PEER_IEEE;
    centreCfg.keyPairs = centrePairs;
    Test_ExpectStatus(Security_Init(&trustCentre, &centreCfg), ZB_OK, "and its trust centre, holding the same key");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    bodyOf(&body, APS_TK_TYPE_NETWORK_KEY, OWN_IEEE, PEER_IEEE);
    Test_ParseHex(s_newKeyHex, body.key, APS_TK_KEY_OCTETS);
    plain[0] = 0x61;               /* Figure 2-4: command, unicast, security and acknowledgement request set */
    plain[1] = 0x42;
    plain[2] = (uint8_t)APS_TK_COMMAND_ID;
    Test_ExpectStatus(Aps_TransportKeyCompose(&body, plain + 3, (uint32_t)sizeof plain - 3, &bodyLen), ZB_OK,
                      "a network key unicast to the device, from the trust centre");
    Test_ExpectStatus(Security_ProtectAps(&trustCentre, 0, SECURITY_KEY_ID_KEY_TRANSPORT, plain, 2, plain + 2,
                                          bodyLen + 1, 1, apdu, (uint32_t)sizeof apdu, &len), ZB_OK,
                      "secured under the global key's key-transport key, the extended nonce naming the trust centre");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_ExpectCount(Aps_KeyDroppedNotTrustCenter(&rig.aps), 0, "the key is not refused as another device's");
    Test_ExpectCount(Aps_KeyInstalled(&rig.aps), 1, "and is installed");
}

/* A joiner's update at the APS door: a trust centre link key from its trust centre is held unverified and answered
   with Verify-Key, and a Confirm-Key whose status is not SUCCESS gives the update up, the device back on the key it
   joined with. */
void caseTcLinkKeyConfirmFailureGivesUp(void)
{
    Rig rig;
    Security security;
    Security trustCentre;
    Security_Config cfg;
    Security_Config centreCfg;
    Security_KeyDescriptor key;
    Security_KeyPairEntry pairs[2];
    Security_KeyPairEntry centrePairs[1];
    Test_BandA peer;
    Aps_TransportKey body;
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t bodyLen = 0;
    uint32_t len = 0;
    int index;

    pairs[0] = keyPairFor(0, 0);
    pairs[0].shortKnown = 0;
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    centrePairs[0] = pairs[0];

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = PEER_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK, "a joined device holding only the global link key");

    centreCfg = cfg;
    centreCfg.ownIeee = PEER_IEEE;
    centreCfg.keyPairs = centrePairs;
    Test_ExpectStatus(Security_Init(&trustCentre, &centreCfg), ZB_OK, "and its trust centre");

    rigBuild(&rig, OWN_SHORT);
    Aps_AttachSecurity(&rig.aps, &security);
    Aps_SetTcLinkKeyUpdate(&rig.aps, 1);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    bodyOf(&body, APS_TK_TYPE_TC_LINK_KEY, OWN_IEEE, PEER_IEEE);
    Test_ParseHex(s_newKeyHex, body.key, APS_TK_KEY_OCTETS);
    plain[0] = 0x61;
    plain[1] = 0x43;
    plain[2] = (uint8_t)APS_TK_COMMAND_ID;
    Test_ExpectStatus(Aps_TransportKeyCompose(&body, plain + 3, (uint32_t)sizeof plain - 3, &bodyLen), ZB_OK,
                      "a trust centre link key for the device");
    Test_ExpectStatus(Security_ProtectAps(&trustCentre, 0, SECURITY_KEY_ID_KEY_LOAD, plain, 2, plain + 2, bodyLen + 1,
                                          1, apdu, (uint32_t)sizeof apdu, &len), ZB_OK,
                      "under the global key's key-load key");
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    index = Security_FindKeyPairByIeee(&security, PEER_IEEE);
    Test_ExpectCount(Aps_TcLinkKeyState(&rig.aps), APS_TCLK_VERIFYING, "the key is held and its Verify-Key sent");
    Test_Expect(index >= 0 && security.keyPairs[index].deviceIeee == PEER_IEEE
                && security.keyPairs[index].keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED,
                "as an unverified entry for the trust centre");
    Test_Expect(keydoorFrameWith(air, 0, airCount, 0x41) >= 0,
                "and the Verify-Key went out APS-unsecured, as 4.4.7.1.3 step 5b asks");

    plain[0] = 0x61;
    plain[1] = 0x44;
    Test_ExpectStatus(Aps_ConfirmKeyCompose(APS_STATUS_SECURITY_FAIL, APS_TK_TYPE_TC_LINK_KEY, OWN_IEEE, plain + 2,
                                            (uint32_t)sizeof plain - 2, &bodyLen), ZB_OK,
                      "a Confirm-Key saying SECURITY_FAIL");
    Test_ExpectStatus(Security_ProtectAps(&trustCentre, 0, SECURITY_KEY_ID_DATA, plain, 2, plain + 2, bodyLen, 1, apdu,
                                          (uint32_t)sizeof apdu, &len), ZB_OK, "under the global key");
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 110);
    stepAt(&rig, air, &airCount, 111);

    index = Security_FindKeyPairByIeee(&security, PEER_IEEE);
    Test_ExpectCount(Aps_TcLinkKeyState(&rig.aps), APS_TCLK_ABANDONED, "gives the update up");
    Test_Expect(index >= 0 && security.keyPairs[index].linkKeyType == SECURITY_LINK_KEY_GLOBAL
                && Zb_memcmp(security.keyPairs[index].key, pairs[0].key, SECURITY_KEY_OCTETS) == 0,
                "and the device is back on the global key for its trust centre");
}
