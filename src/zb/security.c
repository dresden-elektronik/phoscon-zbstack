#include "security.h"

#include "aes.h"
#include "aes_hash.h"
#include "zb_bstream.h"
#include "zb_utils.h"

static uint32_t securityDoMicLen(uint32_t level)
{
    if (level == SECURITY_LEVEL_MIC_32 || level == SECURITY_LEVEL_ENC_MIC_32)
        return SECURITY_MIC_32_OCTETS;

    if (level == SECURITY_LEVEL_MIC_64 || level == SECURITY_LEVEL_ENC_MIC_64)
        return SECURITY_MIC_64_OCTETS;

    if (level == SECURITY_LEVEL_MIC_128 || level == SECURITY_LEVEL_ENC_MIC_128)
        return SECURITY_MIC_128_OCTETS;

    return 0;
}

static int securityDoEncrypts(uint32_t level)
{
    return (level & SECURITY_LEVEL_ENCRYPTED_MASK) ? 1 : 0;
}

/* R23.1: 4.2, 4.3, 4.3.1.1, 4.3.1.2, 4.3.2, 4.3.4, 4.3.4.1, 4.4, 4.4.1.1, 4.4.1.2, 4.5.1.1.4, 4.5.1.3, 4.5.3, 4.6.3.1,
   4.6.3.2.1, 4.6.3.2.3, 4.6.3.4.2, 4.6.3.8, 4.4.7.2.3, 4.4.8.1, 4.4.11.7.4, 4.7.3.1, 4.7.3.8.1 ok (D-218's derived key,
   its unverified entry, the global key it falls back to and the global entry a forgotten key becomes); 4.3.4 deferred
   (no counter is ever zeroed for the APSME-SWITCH-KEY case); 4.6.3.2.4 deferred (the reset it owes a device that got no
   key is the application's); 4.6.3.8.1 deferred (the challenge it starts is a ZDO command the device object does not send yet).
   */
static int securityDoNewer(uint8_t received, uint8_t active)
{
    uint8_t distance = (uint8_t)(received - active);

    return (distance != 0 && distance < SECURITY_KEY_SEQ_HALF) ? 1 : 0;
}

static int securityDoFindKey(const Security *self, uint8_t keySeqNumber)
{
    uint32_t index;

    for (index = 0; index < SECURITY_KEY_SET_MAX; index++)
    {
        if (self->keys[index].inUse && self->keys[index].keySeqNumber == keySeqNumber)
            return (int)index;
    }

    return -1;
}

static int securityDoFindIncoming(const Security *self, uint64_t senderIeee, uint8_t keySeqNumber)
{
    uint32_t index;

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        if (self->incoming[index].inUse && self->incoming[index].senderIeee == senderIeee
            && self->incoming[index].keySeqNumber == keySeqNumber)
            return (int)index;
    }

    return -1;
}

static int securityDoFindFreeIncoming(const Security *self)
{
    uint32_t index;

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        if (!self->incoming[index].inUse)
            return (int)index;
    }

    return -1;
}

static void securityDoWriteAux(U_BStream *stream, uint8_t control, uint32_t frameCounter,
                               uint64_t sourceIeee, uint8_t keySeqNumber)
{
    U_bstream_put_u8(stream, control);
    U_bstream_put_u32_le(stream, (unsigned long)frameCounter);
    U_bstream_put_u64_le(stream, (unsigned long long)sourceIeee);
    U_bstream_put_u8(stream, keySeqNumber);
}

static void securityDoWriteApsAux(U_BStream *stream, uint8_t control, uint32_t frameCounter,
                                  uint64_t sourceIeee, int extendedNonce)
{
    U_bstream_put_u8(stream, control);
    U_bstream_put_u32_le(stream, (unsigned long)frameCounter);

    if (extendedNonce)
        U_bstream_put_u64_le(stream, (unsigned long long)sourceIeee);
}

static void securityDoWriteNonce(U_BStream *stream, uint8_t control, uint32_t frameCounter,
                                 uint64_t sourceIeee)
{
    U_bstream_put_u64_le(stream, (unsigned long long)sourceIeee);
    U_bstream_put_u32_le(stream, (unsigned long)frameCounter);
    U_bstream_put_u8(stream, control);
}

static void securityDoReport(const Security *self, uint16_t component, uint16_t line,
                             uint16_t reason, uint32_t argument)
{
    if (!self->log)
        return;

    Log_Report(self->log, component, line, reason, argument);
}

static uint32_t securityDoControl(const Security *self)
{
    return self->nwkSecurityLevel
           | ((uint32_t)SECURITY_KEY_ID_NETWORK << SECURITY_CONTROL_KEY_ID_SHIFT)
           | ((uint32_t)SECURITY_CONTROL_EXTENDED_NONCE_MASK << SECURITY_CONTROL_EXTENDED_NONCE_SHIFT);
}

/* The Require Verified Frame Counter bit a frame of this frame control carries: 1 for a datagram and for an ACK to
   one, 0 for a command and for an ACK to one, the ACK format field telling the two ACKs apart */
static int securityDoApsRvfc(uint8_t frameControl)
{
    uint32_t frameType = frameControl & SECURITY_APS_FRAME_TYPE_MASK;

    if (frameType == SECURITY_APS_FRAME_TYPE_DATA)
        return 1;

    if (frameType == SECURITY_APS_FRAME_TYPE_ACK)
        return ((frameControl >> SECURITY_APS_ACK_FORMAT_SHIFT) & 0x01) ? 0 : 1;

    return 0;
}

static uint32_t securityDoApsControl(const Security *self, uint32_t keyIdentifier, int extendedNonce, int rvfc)
{
    return self->nwkSecurityLevel
           | (keyIdentifier << SECURITY_CONTROL_KEY_ID_SHIFT)
           | ((uint32_t)(extendedNonce ? 1 : 0) << SECURITY_CONTROL_EXTENDED_NONCE_SHIFT)
           | ((uint32_t)(rvfc ? 1 : 0) << SECURITY_CONTROL_RVFC_SHIFT);
}

static uint8_t securityDoAirControl(uint32_t control)
{
    return (uint8_t)(control & (SECURITY_CONTROL_MAX ^ SECURITY_CONTROL_LEVEL_MASK));
}

static ZbStatus securityDoDuplicateKey(const Security_Config *cfg, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (cfg->keys[index].keySeqNumber == cfg->keys[other].keySeqNumber)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

static ZbStatus securityDoDuplicateIncoming(const Security_Config *cfg, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (cfg->incomingSeeds[index].senderIeee == cfg->incomingSeeds[other].senderIeee
            && cfg->incomingSeeds[index].keySeqNumber == cfg->incomingSeeds[other].keySeqNumber)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

static ZbStatus securityDoDuplicatePairIeee(const Security_Config *cfg, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (cfg->keyPairs[index].deviceIeee == cfg->keyPairs[other].deviceIeee)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

static ZbStatus securityDoDuplicatePairShort(const Security_Config *cfg, uint32_t index)
{
    uint32_t other;

    if (!cfg->keyPairs[index].shortKnown)
        return ZB_OK;

    for (other = 0; other < index; other++)
    {
        if (cfg->keyPairs[other].shortKnown
            && cfg->keyPairs[index].shortAddress == cfg->keyPairs[other].shortAddress)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

static ZbStatus securityDoKeyPair(const Security_Config *cfg, uint32_t index)
{
    if (cfg->keyPairs[index].keyAttributes != SECURITY_KEYPAIR_ATTR_PROVISIONAL
        && cfg->keyPairs[index].keyAttributes != SECURITY_KEYPAIR_ATTR_UNVERIFIED
        && cfg->keyPairs[index].keyAttributes != SECURITY_KEYPAIR_ATTR_VERIFIED)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->keyPairs[index].linkKeyType != SECURITY_LINK_KEY_UNIQUE
        && cfg->keyPairs[index].linkKeyType != SECURITY_LINK_KEY_GLOBAL)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->keyPairs[index].featuresCapabilities != SECURITY_FEATURES_NONE
        && cfg->keyPairs[index].featuresCapabilities != SECURITY_FEATURES_FRAME_COUNTER_SYNC)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

static void securityDoFill(Security *self, const Security_Config *cfg, Log_Log *log)
{
    uint32_t index;

    self->ownIeee = cfg->ownIeee;
    self->trustCenterIeee = cfg->trustCenterIeee;
    self->requireLinkKeyEncryption = cfg->requireLinkKeyEncryption ? 1 : 0;
    self->nwkSecurityLevel = cfg->nwkSecurityLevel;
    self->nwkActiveKeySeqNumber = cfg->nwkActiveKeySeqNumber;
    self->authenticated = cfg->authenticated ? 1 : 0;
    self->nwkAllFresh = cfg->nwkAllFresh ? 1 : 0;
    self->log = log;

    for (index = 0; index < cfg->keyCount; index++)
    {
        self->keys[index] = cfg->keys[index];
        self->keys[index].inUse = 1;
    }

    for (index = 0; index < cfg->incomingSeedCount; index++)
    {
        self->incoming[index] = cfg->incomingSeeds[index];
        self->incoming[index].inUse = 1;
    }

    for (index = 0; index < cfg->keyPairCount; index++)
    {
        self->keyPairs[index] = cfg->keyPairs[index];
    }

    self->keyPairCount = cfg->keyPairCount;

    if (cfg->linkKeySeed)
    {
        Zb_memcpy(self->linkKeySeed, cfg->linkKeySeed, SECURITY_KEY_OCTETS);
        self->linkKeySeedKnown = 1;
    }
}

static ZbStatus securityDoValidate(const Security_Config *cfg)
{
    uint32_t index;
    int activeFound;

    if (cfg->nwkSecurityLevel > SECURITY_LEVEL_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->nwkSecurityLevel == SECURITY_LEVEL_ENC)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->keyCount > SECURITY_KEY_SET_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!cfg->keys && cfg->keyCount != 0)
        return ZB_ERR_BAD_ARGUMENT;


    if (!cfg->incomingSeeds && cfg->incomingSeedCount != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->incomingSeedCount > SECURITY_INCOMING_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    activeFound = 0;

    for (index = 0; index < cfg->keyCount; index++)
    {
        if (securityDoDuplicateKey(cfg, index) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;

        if (cfg->keys[index].keySeqNumber == cfg->nwkActiveKeySeqNumber)
            activeFound = 1;
    }

    if (cfg->keyCount != 0 && !activeFound)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->keyPairCount > SECURITY_KEYPAIR_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!cfg->keyPairs && cfg->keyPairCount != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->keyPairCount != 0 && cfg->nwkSecurityLevel == SECURITY_LEVEL_NONE)
        return ZB_ERR_BAD_ARGUMENT;

    for (index = 0; index < cfg->incomingSeedCount; index++)
    {
        if (securityDoDuplicateIncoming(cfg, index) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;
    }

    for (index = 0; index < cfg->keyPairCount; index++)
    {
        if (securityDoDuplicatePairIeee(cfg, index) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;

        if (securityDoDuplicatePairShort(cfg, index) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;

        if (securityDoKeyPair(cfg, index) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

ZbStatus Security_Init(Security *self, const Security_Config *cfg)
{
    ZbStatus status;

    if (!self || !cfg)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->trustCenterIeee = 0xffffffffffffffff;

    status = securityDoValidate(cfg);

    if (status != ZB_OK)
        return status;

    securityDoFill(self, cfg, cfg->log);

    return ZB_OK;
}

void Security_Reset(Security *self)
{
    if (!self)
        return;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->trustCenterIeee = 0xffffffffffffffff;
}

ZbStatus Security_Restore(Security *self, const Security_Config *cfg)
{
    Log_Log *log;
    ZbStatus status;

    if (!self || !cfg)
        return ZB_ERR_BAD_ARGUMENT;

    status = securityDoValidate(cfg);

    if (status != ZB_OK)
        return status;

    log = self->log;

    Security_Reset(self);

    securityDoFill(self, cfg, log);

    return ZB_OK;
}

int Security_IsEnabled(const Security *self)
{
    if (!self)
        return 0;

    if (self->nwkSecurityLevel == SECURITY_LEVEL_NONE)
        return 0;

    return securityDoFindKey(self, self->nwkActiveKeySeqNumber) >= 0 ? 1 : 0;
}

/* Every window kept under one key sequence number goes: the key installed starts from zero, and a key replaced leaves
   nothing behind in the store for a number the set no longer holds */
static void securityDoDropWindows(Security *self, uint8_t keySeqNumber)
{
    uint32_t index;

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        if (self->incoming[index].inUse && self->incoming[index].keySeqNumber == keySeqNumber)
            Zb_memset(&self->incoming[index], 0, (uint32_t)sizeof self->incoming[index]);
    }
}

/* 4.6.3.4.2 read as one rule: "Otherwise" answers "When in the normal operating state", since read against "only if"
   it would install a key the sentence has just refused. A trust center key re-sent under the active number and the
   same octets changes nothing, so no counter is reset that 4.3.4 says only APSME-SWITCH-KEY may reset. */
ZbStatus Security_InstallNetworkKey(Security *self, const uint8_t key[SECURITY_KEY_OCTETS],
                                    uint8_t keySeqNumber, int normalOperating, int fromTrustCenter)
{
    Security_KeyDescriptor *descriptor;
    int activeIndex;
    int target;
    uint32_t index;

    if (self == 0 || key == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (normalOperating && !fromTrustCenter)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    activeIndex = securityDoFindKey(self, self->nwkActiveKeySeqNumber);
    target = -1;

    if (normalOperating && activeIndex >= 0 && self->keys[activeIndex].keySeqNumber == keySeqNumber)
    {
        if (Zb_memcmp(self->keys[activeIndex].key, key, SECURITY_KEY_OCTETS) == 0)
            return ZB_OK;

        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_STATE);
        return ZB_ERR_BAD_STATE;
    }

    if (!normalOperating && activeIndex >= 0)
        target = activeIndex;

    for (index = 0; target < 0 && index < SECURITY_KEY_SET_MAX; index++)
    {
        if (!self->keys[index].inUse)
            target = (int)index;
    }

    for (index = 0; target < 0 && index < SECURITY_KEY_SET_MAX; index++)
    {
        if ((int)index != activeIndex)
            target = (int)index;
    }

    if (target < 0)
        return ZB_ERR_NO_SPACE;

    descriptor = &self->keys[target];

    if (descriptor->inUse)
        securityDoDropWindows(self, descriptor->keySeqNumber);

    Zb_memcpy(descriptor->key, key, SECURITY_KEY_OCTETS);
    descriptor->keySeqNumber = keySeqNumber;
    descriptor->inUse = 1;
    descriptor->outgoingFrameCounter = 0;

    if (!normalOperating)
        self->nwkActiveKeySeqNumber = keySeqNumber;

    for (index = 0; index < SECURITY_KEY_SET_MAX; index++)
    {
        if ((int)index != target && self->keys[index].inUse && self->keys[index].keySeqNumber == keySeqNumber)
            Zb_memset(&self->keys[index], 0, (uint32_t)sizeof self->keys[index]);
    }

    securityDoDropWindows(self, keySeqNumber);

    if (fromTrustCenter)
        self->authenticated = 1;

    if (self->log)
        Log_Report(self->log, LOG_COMP_SECURITY_KEY_ADOPTED, (uint16_t)__LINE__, LOG_REASON_STATE,
                   (uint32_t)keySeqNumber);

    return ZB_OK;
}

uint32_t Security_NwkOverhead(const Security *self)
{
    if (!self)
        return 0;

    return SECURITY_AUX_LEN + securityDoMicLen(self->nwkSecurityLevel);
}

int Security_IsAuthenticated(const Security *self)
{
    if (!self)
        return 0;

    return self->authenticated;
}

uint8_t Security_Level(const Security *self)
{
    if (!self)
        return 0;

    return (uint8_t)self->nwkSecurityLevel;
}

ZbStatus Security_Protect(Security *self, const uint8_t *header, uint32_t headerLen,
                          const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *outNpdu, uint32_t outMax, uint32_t *outLen)
{
    Aes_Key aesKey;
    U_BStream adata;
    U_BStream frame;
    U_BStream nonce;
    Security_KeyDescriptor *descriptor;
    const uint8_t *ccmIn;
    uint8_t *ccmMic;
    uint8_t *ccmOut;
    uint8_t nonceOctets[SECURITY_NONCE_LEN];
    uint8_t keySeqNumber;
    uint32_t adataLen;
    uint32_t ccmInLen;
    uint32_t control;
    uint32_t frameCounter;
    uint32_t micLen;
    uint32_t seamLen;
    uint32_t total;
    ZbStatus status;
    int encrypts;
    int keyIndex;

    if (!self || !header || !outNpdu || !outLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (!payload && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (headerLen == 0 || headerLen > SECURITY_HEADER_MAX || payloadLen > SECURITY_FRAME_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->nwkSecurityLevel == SECURITY_LEVEL_NONE)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    micLen = securityDoMicLen(self->nwkSecurityLevel);
    encrypts = securityDoEncrypts(self->nwkSecurityLevel);

    total = headerLen + SECURITY_AUX_LEN + payloadLen + micLen;

    if (total > SECURITY_FRAME_MAX)
    {
        securityDoReport(self, LOG_COMP_SECURITY_FRAME_TOO_LONG, (uint16_t)__LINE__, LOG_REASON_DROPPED, total);
        return ZB_ERR_NO_SPACE;
    }

    if (total > outMax)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_NO_SPACE);
        return ZB_ERR_NO_SPACE;
    }

    keyIndex = securityDoFindKey(self, self->nwkActiveKeySeqNumber);

    if (keyIndex < 0)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    descriptor = &self->keys[keyIndex];
    keySeqNumber = descriptor->keySeqNumber;
    frameCounter = descriptor->outgoingFrameCounter;

    if (frameCounter == SECURITY_FRAME_COUNTER_LAST)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    control = securityDoControl(self);

    encrypts = securityDoEncrypts(self->nwkSecurityLevel);

    U_bstream_init(&adata, self->adata, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&adata, header, (unsigned long)headerLen);
    securityDoWriteAux(&adata, (uint8_t)control, frameCounter, self->ownIeee, keySeqNumber);

    ccmIn = 0;
    ccmInLen = 0;

    if (!encrypts)
        U_bstream_put_bytes(&adata, payload, (unsigned long)payloadLen);
    else
    {
        ccmIn = payload;
        ccmInLen = payloadLen;
    }

    adataLen = headerLen + SECURITY_AUX_LEN;

    if (!encrypts)
        adataLen = adataLen + payloadLen;

    if (!Zb_bstream_ok(&adata) || Zb_bstream_pos(&adata) != adataLen)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&nonce, nonceOctets, (unsigned long)SECURITY_NONCE_LEN);
    securityDoWriteNonce(&nonce, (uint8_t)control, frameCounter, self->ownIeee);

    if (!Zb_bstream_ok(&nonce) || Zb_bstream_pos(&nonce) != SECURITY_NONCE_LEN)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&frame, self->frame, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&frame, header, (unsigned long)headerLen);
    securityDoWriteAux(&frame, securityDoAirControl(control), frameCounter, self->ownIeee, keySeqNumber);

    if (!Zb_bstream_ok(&frame) || Zb_bstream_pos(&frame) != headerLen + SECURITY_AUX_LEN)
        return ZB_ERR_INTERNAL;

    ccmOut = self->frame + headerLen + SECURITY_AUX_LEN;
    ccmMic = ccmOut + payloadLen;

    if (Aes_KeySchedule(&aesKey, descriptor->key) != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    status = Aes_CcmEncrypt(&aesKey, nonceOctets, SECURITY_NONCE_LEN, self->adata, adataLen,
                            ccmIn, ccmInLen, micLen, ccmOut, ccmMic);

    if (status != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    if (!encrypts)
        U_bstream_put_bytes(&frame, payload, (unsigned long)payloadLen);

    seamLen = micLen;

    if (encrypts)
        seamLen = seamLen + payloadLen;

    U_bstream_advance(&frame, (unsigned long)seamLen);

    if (!Zb_bstream_ok(&frame) || Zb_bstream_pos(&frame) != total)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    descriptor->outgoingFrameCounter = frameCounter + 1;

    Zb_memcpy(outNpdu, self->frame, total);
    *outLen = total;

    return ZB_OK;
}

ZbStatus Security_Unprotect(Security *self, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                            uint8_t *plainOut, uint32_t plainMax, uint32_t *plainLen,
                            Security_Result *resultOut)
{
    Aes_Key aesKey;
    U_BStream adata;
    U_BStream nonce;
    U_BStream reader;
    Security_IncomingEntry *entry;
    Security_KeyDescriptor *descriptor;
    const uint8_t *ccmIn;
    uint8_t nonceOctets[SECURITY_NONCE_LEN];
    uint8_t tag[SECURITY_MIC_MAX];
    uint8_t keySeqNumber;
    uint32_t adataLen;
    uint32_t ccmInLen;
    uint32_t controlAir;
    uint32_t controlUse;
    uint32_t micLen;
    uint32_t octet;
    uint32_t payloadLen;
    uint32_t receivedCounter;
    uint32_t securedLen;
    uint64_t senderIeee;
    ZbStatus status;
    int encrypts;
    int entryIndex;
    int freeIndex;
    int keyIndex;

    if (!self || !npdu || !plainOut || !plainLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->nwkSecurityLevel == SECURITY_LEVEL_NONE)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    if (npduLen == 0 || npduLen > SECURITY_FRAME_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (headerLen > SECURITY_HEADER_MAX || headerLen + SECURITY_AUX_LEN > npduLen)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&reader, npdu, npduLen);
    U_bstream_seek(&reader, (unsigned long)headerLen);
    controlAir = U_bstream_get_u8(&reader);

    if (((controlAir >> SECURITY_CONTROL_KEY_ID_SHIFT) & SECURITY_CONTROL_KEY_ID_MASK)
        != SECURITY_KEY_ID_NETWORK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    if (((controlAir >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT) & SECURITY_CONTROL_EXTENDED_NONCE_MASK) != 1)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    micLen = securityDoMicLen(self->nwkSecurityLevel);

    if (npduLen < headerLen + SECURITY_AUX_LEN + micLen)
        return ZB_ERR_BAD_ARGUMENT;

    receivedCounter = (uint32_t)U_bstream_get_u32_le(&reader);
    senderIeee = (uint64_t)U_bstream_get_u64_le(&reader);
    keySeqNumber = U_bstream_get_u8(&reader);

    if (!Zb_bstream_ok(&reader) || Zb_bstream_pos(&reader) != headerLen + SECURITY_AUX_LEN)
        return ZB_ERR_BAD_ARGUMENT;

    if (receivedCounter == SECURITY_FRAME_COUNTER_LAST)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    keyIndex = securityDoFindKey(self, keySeqNumber);

    if (keyIndex < 0)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    descriptor = &self->keys[keyIndex];

    entryIndex = securityDoFindIncoming(self, senderIeee, keySeqNumber);

    if (entryIndex >= 0 && receivedCounter < self->incoming[entryIndex].frameCounter)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    controlUse = (controlAir & (SECURITY_CONTROL_MAX ^ SECURITY_CONTROL_LEVEL_MASK)) | self->nwkSecurityLevel;
    encrypts = securityDoEncrypts(self->nwkSecurityLevel);

    securedLen = npduLen - headerLen - SECURITY_AUX_LEN;
    payloadLen = securedLen - micLen;

    U_bstream_init(&nonce, nonceOctets, (unsigned long)SECURITY_NONCE_LEN);
    securityDoWriteNonce(&nonce, (uint8_t)controlUse, receivedCounter, senderIeee);

    if (!Zb_bstream_ok(&nonce) || Zb_bstream_pos(&nonce) != SECURITY_NONCE_LEN)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&adata, self->adata, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&adata, npdu, (unsigned long)headerLen);
    securityDoWriteAux(&adata, (uint8_t)controlUse, receivedCounter, senderIeee, keySeqNumber);

    ccmIn = 0;
    ccmInLen = 0;

    for (octet = 0; octet < payloadLen; octet++)
    {
        if (encrypts)
            self->frame[octet] = U_bstream_get_u8(&reader);
        else
            U_bstream_put_u8(&adata, U_bstream_get_u8(&reader));
    }

    for (octet = 0; octet < micLen; octet++)
        tag[octet] = U_bstream_get_u8(&reader);

    if (encrypts)
    {
        ccmIn = self->frame;
        ccmInLen = payloadLen;
    }

    adataLen = headerLen + SECURITY_AUX_LEN;

    if (!encrypts)
        adataLen = adataLen + payloadLen;

    if (!Zb_bstream_ok(&adata) || Zb_bstream_pos(&adata) != adataLen)
        return ZB_ERR_INTERNAL;

    if (!Zb_bstream_ok(&reader) || Zb_bstream_pos(&reader) != npduLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen > plainMax)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_NO_SPACE);
        return ZB_ERR_NO_SPACE;
    }

    if (Aes_KeySchedule(&aesKey, descriptor->key) != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    status = Aes_CcmDecrypt(&aesKey, nonceOctets, SECURITY_NONCE_LEN, self->adata, adataLen,
                            ccmIn, ccmInLen, tag, micLen, plainOut);

    if (status != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    if (entryIndex >= 0)
        self->incoming[entryIndex].frameCounter = receivedCounter + 1;
    else
    {
        freeIndex = securityDoFindFreeIncoming(self);

        if (freeIndex < 0)
        {
            securityDoReport(self, LOG_COMP_SECURITY_INCOMING_FULL, (uint16_t)__LINE__,
                             LOG_REASON_DROPPED, SECURITY_INCOMING_MAX);

            if (self->nwkAllFresh)
                return ZB_ERR_NO_SPACE;
        }
        else
        {
            entry = &self->incoming[freeIndex];
            entry->inUse = 1;
            entry->senderIeee = senderIeee;
            entry->keySeqNumber = keySeqNumber;
            entry->frameCounter = receivedCounter + 1;
        }
    }

    if (!encrypts)
        Zb_memcpy(plainOut, self->adata + headerLen + SECURITY_AUX_LEN, payloadLen);

    *plainLen = payloadLen;

    if (resultOut)
    {
        resultOut->senderIeee = senderIeee;
        resultOut->keySeqNumber = keySeqNumber;
        resultOut->frameCounter = receivedCounter;
        resultOut->activeKeyAdopted = 0;
    }

    if (securityDoNewer(keySeqNumber, self->nwkActiveKeySeqNumber))
    {
        self->nwkActiveKeySeqNumber = keySeqNumber;

        securityDoReport(self, LOG_COMP_SECURITY_KEY_ADOPTED, (uint16_t)__LINE__,
                         LOG_REASON_STATE, keySeqNumber);

        if (resultOut)
            resultOut->activeKeyAdopted = 1;
    }

    return ZB_OK;
}

/* 4.6.3.8's last paragraph: the pair a transport key arrived from is verified by it, and its counter is that
   command's, no earlier message being replayable to a device that has just joined. */
ZbStatus Security_VerifyKeyPair(Security *self, int index, uint32_t frameCounter)
{
    if (self == 0 || index < 0 || (uint32_t)index >= self->keyPairCount)
        return ZB_ERR_NOT_FOUND;

    self->keyPairs[index].verifiedFrameCounter = 1;
    self->keyPairs[index].incomingFrameCounter = frameCounter + 1;

    return ZB_OK;
}

ZbStatus Security_DeriveLinkKey(const Security *self, uint64_t deviceIeee, uint8_t out[SECURITY_KEY_OCTETS])
{
    uint8_t address[8];
    uint32_t i;

    if (self == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->linkKeySeedKnown)
        return ZB_ERR_UNSUPPORTED;

    for (i = 0; i < 8; i++)
        address[i] = (uint8_t)((deviceIeee >> (8 * i)) & 0xff);

    return Aes_MmoHmac(self->linkKeySeed, SECURITY_KEY_OCTETS, address, (uint32_t)sizeof address, out);
}

int Security_SetUnverifiedPair(Security *self, uint64_t deviceIeee, uint16_t shortAddress,
                               const uint8_t key[SECURITY_KEY_OCTETS])
{
    Security_KeyPairEntry *entry;
    uint32_t index;
    int found = -1;

    if (self == 0 || key == 0 || deviceIeee == 0)
        return -1;

    for (index = 0; index < self->keyPairCount; index++)
    {
        if (self->keyPairs[index].deviceIeee == deviceIeee)
            found = (int)index;
        else if (self->keyPairs[index].shortKnown && self->keyPairs[index].shortAddress == shortAddress)
            self->keyPairs[index].shortKnown = 0;
    }

    if (found < 0)
    {
        if (self->keyPairCount >= SECURITY_KEYPAIR_MAX)
            return -1;

        found = (int)self->keyPairCount;
        self->keyPairCount++;
    }

    entry = &self->keyPairs[found];

    Zb_memset(entry, 0, (uint32_t)sizeof *entry);
    entry->deviceIeee = deviceIeee;
    entry->shortAddress = shortAddress;
    entry->shortKnown = 1;
    entry->keyAttributes = SECURITY_KEYPAIR_ATTR_UNVERIFIED;
    entry->linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry->featuresCapabilities = SECURITY_FEATURES_NONE;
    Zb_memcpy(entry->key, key, SECURITY_KEY_OCTETS);

    return found;
}

ZbStatus Security_ConfirmKeyPair(Security *self, int index)
{
    if (self == 0 || index < 0 || (uint32_t)index >= self->keyPairCount)
        return ZB_ERR_NOT_FOUND;

    self->keyPairs[index].keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    self->keyPairs[index].incomingFrameCounter = 0;
    self->keyPairs[index].verifiedFrameCounter = 1;

    return ZB_OK;
}

ZbStatus Security_VerifyKeyHash(const Security_KeyPairEntry *entry, uint8_t out[SECURITY_KEY_OCTETS])
{
    uint8_t input = SECURITY_KEY_HASH_VERIFY_INPUT;

    if (entry == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return Aes_MmoHmac(entry->key, SECURITY_KEY_OCTETS, &input, 1, out);
}

void Security_ForgetSender(Security *self, uint64_t senderIeee)
{
    uint32_t index;

    if (self == 0)
        return;

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        if (self->incoming[index].inUse && self->incoming[index].senderIeee == senderIeee)
            Zb_memset(&self->incoming[index], 0, (uint32_t)sizeof self->incoming[index]);
    }
}

int Security_KeyPairCount(const Security *self)
{
    if (!self)
        return 0;

    return (int)self->keyPairCount;
}

const Security_KeyDescriptor *Security_ActiveNetworkKey(const Security *self)
{
    int index;

    if (!self)
        return 0;

    index = securityDoFindKey(self, self->nwkActiveKeySeqNumber);

    return index >= 0 ? &self->keys[index] : 0;
}

/* The pair whose link key type is global, or -1: the one a device without a pair of its own is answered with. */
static int securityDoGlobalPair(const Security *self)
{
    int named = -1;
    uint32_t index;

    for (index = 0; index < self->keyPairCount; index++)
    {
        if (self->keyPairs[index].linkKeyType != SECURITY_LINK_KEY_GLOBAL)
            continue;

        if (self->keyPairs[index].deviceIeee == 0)
            return (int)index;

        if (named < 0)
            named = (int)index;
    }

    return named;
}

int Security_ForgetLinkKey(Security *self, uint64_t deviceIeee)
{
    Security_KeyPairEntry *entry;
    int global;
    int found;

    if (self == 0 || deviceIeee == 0)
        return -1;

    found = Security_FindKeyPairByIeee(self, deviceIeee);
    global = securityDoGlobalPair(self);

    if (found < 0 || global < 0 || self->keyPairs[found].deviceIeee != deviceIeee)
        return -1;

    entry = &self->keyPairs[found];
    Zb_memcpy(entry->key, self->keyPairs[global].key, SECURITY_KEY_OCTETS);
    entry->keyAttributes = SECURITY_KEYPAIR_ATTR_PROVISIONAL;
    entry->linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    entry->incomingFrameCounter = 0;
    entry->verifiedFrameCounter = 0;

    return found;
}

/* 4.6.3.2.1: a trust centre answers a device it holds no pair for with the global link key, so the exact lookup falls
   back to that one pair. A device configured with none is unaffected, and a pair with a device address of 0 is never
   an exact match. */
int Security_FindKeyPairByIeee(const Security *self, uint64_t ieee)
{
    uint32_t index;

    if (!self)
        return -1;

    for (index = 0; index < self->keyPairCount; index++)
    {
        if (self->keyPairs[index].deviceIeee == ieee && ieee != 0)
            return (int)index;
    }

    return securityDoGlobalPair(self);
}

int Security_FindKeyPairByShort(const Security *self, uint16_t shortAddress)
{
    uint32_t index;

    if (!self)
        return -1;

    for (index = 0; index < self->keyPairCount; index++)
    {
        if (self->keyPairs[index].shortKnown && self->keyPairs[index].shortAddress == shortAddress)
            return (int)index;
    }

    return securityDoGlobalPair(self);
}

const Security_KeyPairEntry *Security_KeyPairAt(const Security *self, int index)
{
    if (!self)
        return 0;

    if (index < 0 || (uint32_t)index >= self->keyPairCount)
        return 0;

    return &self->keyPairs[index];
}

/* 4.5.3's three keys out of one pair: the data key is the link key itself, and the two transport keys are the
   keyed hash of one octet under it. The frame counters are shared by all three (4.5.3: "All keys derived from the
   link key SHALL share the associated frame counters"), so this hands back material only. */
ZbStatus Security_KeyForIdentifier(const Security_KeyPairEntry *entry, uint32_t keyIdentifier,
                                   uint8_t out[SECURITY_KEY_OCTETS])
{
    uint8_t input;
    uint32_t i;

    if (entry == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (keyIdentifier == SECURITY_KEY_ID_DATA)
    {
        Zb_memcpy(out, entry->key, SECURITY_KEY_OCTETS);
        return ZB_OK;
    }

    if (keyIdentifier == SECURITY_KEY_ID_KEY_TRANSPORT)
        input = SECURITY_KEY_HASH_TRANSPORT_INPUT;
    else if (keyIdentifier == SECURITY_KEY_ID_KEY_LOAD)
        input = SECURITY_KEY_HASH_LOAD_INPUT;
    else
        return ZB_ERR_BAD_ARGUMENT;

    if (Aes_MmoHmac(entry->key, SECURITY_KEY_OCTETS, &input, 1, out) != ZB_OK)
    {
        for (i = 0; i < SECURITY_KEY_OCTETS; i++)
            out[i] = 0;

        return ZB_ERR_INTERNAL;
    }

    return ZB_OK;
}

ZbStatus Security_ProtectAps(Security *self, int keyPairIndex, uint32_t keyIdentifier, const uint8_t *header,
                             uint32_t headerLen, const uint8_t *payload, uint32_t payloadLen, int extendedNonce,
                             uint8_t *outSecured, uint32_t outMax, uint32_t *outLen)
{
    Aes_Key aesKey;
    U_BStream adata;
    U_BStream frame;
    U_BStream nonce;
    Security_KeyPairEntry *entry;
    const uint8_t *ccmIn;
    uint8_t *ccmMic;
    uint8_t *ccmOut;
    uint8_t nonceOctets[SECURITY_NONCE_LEN];
    uint8_t material[SECURITY_KEY_OCTETS];
    uint32_t adataLen;
    uint32_t auxLen;
    uint32_t ccmInLen;
    uint32_t control;
    uint32_t frameCounter;
    uint32_t micLen;
    uint32_t seamLen;
    uint32_t total;
    uint32_t frameType;
    uint32_t i;
    ZbStatus status;
    int encrypts;
    int useExtendedNonce;

    if (!self || !header || !outSecured || !outLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (!payload && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (headerLen == 0 || headerLen > SECURITY_APS_HEADER_MAX || payloadLen > SECURITY_FRAME_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->nwkSecurityLevel == SECURITY_LEVEL_NONE)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    micLen = securityDoMicLen(self->nwkSecurityLevel);
    encrypts = securityDoEncrypts(self->nwkSecurityLevel);

    frameType = header[0] & SECURITY_APS_FRAME_TYPE_MASK;
    useExtendedNonce = (extendedNonce || frameType == SECURITY_APS_FRAME_TYPE_COMMAND) ? 1 : 0;

    if (keyIdentifier != SECURITY_KEY_ID_DATA && frameType != SECURITY_APS_FRAME_TYPE_COMMAND)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_ARGUMENT);
        return ZB_ERR_BAD_ARGUMENT;
    }

    auxLen = useExtendedNonce ? SECURITY_APS_AUX_MAX : SECURITY_APS_AUX_MIN;

    total = headerLen + auxLen + payloadLen + micLen;

    if (total > SECURITY_APS_MSDU_MAX)
    {
        securityDoReport(self, LOG_COMP_SECURITY_FRAME_TOO_LONG, (uint16_t)__LINE__, LOG_REASON_DROPPED, total);
        return ZB_ERR_NO_SPACE;
    }

    if (total > outMax)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_NO_SPACE);
        return ZB_ERR_NO_SPACE;
    }

    if (keyPairIndex < 0 || (uint32_t)keyPairIndex >= self->keyPairCount)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    if (keyIdentifier == SECURITY_KEY_ID_NETWORK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    if (self->keyPairs[keyPairIndex].keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED)
        keyPairIndex = securityDoGlobalPair(self);

    if (keyPairIndex < 0)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    entry = &self->keyPairs[keyPairIndex];

    if (Security_KeyForIdentifier(entry, keyIdentifier, material) != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_ARGUMENT);
        return ZB_ERR_BAD_ARGUMENT;
    }

    frameCounter = entry->outgoingFrameCounter;

    if (frameCounter == SECURITY_FRAME_COUNTER_LAST)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    control = securityDoApsControl(self, keyIdentifier, useExtendedNonce, securityDoApsRvfc(header[0]));

    U_bstream_init(&adata, self->adata, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&adata, header, (unsigned long)headerLen);
    securityDoWriteApsAux(&adata, (uint8_t)control, frameCounter, self->ownIeee, useExtendedNonce);

    ccmIn = 0;
    ccmInLen = 0;

    if (!encrypts)
        U_bstream_put_bytes(&adata, payload, (unsigned long)payloadLen);
    else
    {
        ccmIn = payload;
        ccmInLen = payloadLen;
    }

    adataLen = headerLen + auxLen;

    if (!encrypts)
        adataLen = adataLen + payloadLen;

    if (!Zb_bstream_ok(&adata) || Zb_bstream_pos(&adata) != adataLen)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&nonce, nonceOctets, (unsigned long)SECURITY_NONCE_LEN);
    securityDoWriteNonce(&nonce, (uint8_t)control, frameCounter, self->ownIeee);

    if (!Zb_bstream_ok(&nonce) || Zb_bstream_pos(&nonce) != SECURITY_NONCE_LEN)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&frame, self->frame, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&frame, header, (unsigned long)headerLen);
    securityDoWriteApsAux(&frame, securityDoAirControl(control), frameCounter, self->ownIeee, useExtendedNonce);

    if (!Zb_bstream_ok(&frame) || Zb_bstream_pos(&frame) != headerLen + auxLen)
        return ZB_ERR_INTERNAL;

    ccmOut = self->frame + headerLen + auxLen;
    ccmMic = ccmOut + payloadLen;

    if (Aes_KeySchedule(&aesKey, material) != ZB_OK)
    {
        for (i = 0; i < SECURITY_KEY_OCTETS; i++)
            material[i] = 0;

        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    status = Aes_CcmEncrypt(&aesKey, nonceOctets, SECURITY_NONCE_LEN, self->adata, adataLen,
                            ccmIn, ccmInLen, micLen, ccmOut, ccmMic);

    Aes_KeyWipe(&aesKey);

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        material[i] = 0;

    if (status != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    if (!encrypts)
        U_bstream_put_bytes(&frame, payload, (unsigned long)payloadLen);

    seamLen = micLen;

    if (encrypts)
        seamLen = seamLen + payloadLen;

    U_bstream_advance(&frame, (unsigned long)seamLen);

    if (!Zb_bstream_ok(&frame) || Zb_bstream_pos(&frame) != total)
    {
        securityDoReport(self, LOG_COMP_SECURITY_PROTECT_REFUSED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_INTERNAL);
        return ZB_ERR_INTERNAL;
    }

    entry->outgoingFrameCounter = frameCounter + 1;

    Zb_memcpy(outSecured, self->frame, total);
    *outLen = total;

    return ZB_OK;
}

/* 4.4.1.2's nine steps over one received APDU: the identifier is read first, `01` is refused, step 2's SourceAddress is
   the address map's where the caller knows it and, once this device is authorized, an auxiliary source naming anyone
   else is refused (before, step 2 takes the pre-installed key, as a parent's relay of the trust centre's key needs);
   step 4's replay check runs for a unique link key only, and step 8 is UNVERIFIED_FRAME_COUNTER for 4.6.3.8's pair. */
/* One CCM* open under one entry's material: ZB_ERR_AUTH for a tag that does not verify, so the caller can try the key
   a device may still be using (D-218). */
static ZbStatus securityDoApsOpen(const Security_KeyPairEntry *entry, uint32_t keyIdentifier, const uint8_t *nonce,
                                  const uint8_t *adata, uint32_t adataLen, const uint8_t *ccmIn, uint32_t ccmInLen,
                                  const uint8_t *tag, uint32_t micLen, uint8_t *plainOut)
{
    Aes_Key aesKey;
    uint8_t material[SECURITY_KEY_OCTETS];
    ZbStatus status;
    uint32_t i;

    if (Security_KeyForIdentifier(entry, keyIdentifier, material) != ZB_OK)
        return ZB_ERR_BAD_ARGUMENT;

    status = Aes_KeySchedule(&aesKey, material);

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        material[i] = 0;

    if (status != ZB_OK)
        return ZB_ERR_INTERNAL;

    status = Aes_CcmDecrypt(&aesKey, nonce, SECURITY_NONCE_LEN, adata, adataLen, ccmIn, ccmInLen, tag, micLen, plainOut);

    Aes_KeyWipe(&aesKey);

    return status == ZB_OK ? ZB_OK : ZB_ERR_AUTH;
}

ZbStatus Security_UnprotectAps(Security *self, const uint8_t *apsdu, uint32_t apsduLen, uint32_t headerLen,
                               uint64_t partnerHint, int hintKnown,
                               uint8_t *plainOut, uint32_t plainMax, uint32_t *plainLen,
                               Security_ApsResult *resultOut)
{
    U_BStream adata;
    U_BStream nonce;
    U_BStream reader;
    Security_KeyPairEntry *entry;
    const uint8_t *ccmIn;
    uint8_t nonceOctets[SECURITY_NONCE_LEN];
    uint8_t tag[SECURITY_MIC_MAX];
    uint64_t auxSource;
    uint64_t partnerIeee;
    uint32_t adataLen;
    uint32_t auxLen;
    uint32_t ccmInLen;
    uint32_t controlAir;
    uint32_t controlUse;
    uint32_t keyIdentifier;
    uint32_t micLen;
    uint32_t octet;
    uint32_t payloadLen;
    uint32_t receivedCounter;
    uint32_t securedLen;
    ZbStatus status;
    int extendedNonce;
    int encrypts;
    int entryIndex;

    if (!self || !apsdu || !plainOut || !plainLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->nwkSecurityLevel == SECURITY_LEVEL_NONE)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    if (apsduLen == 0 || apsduLen > SECURITY_FRAME_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (headerLen > SECURITY_APS_HEADER_MAX || headerLen + SECURITY_APS_AUX_MIN > apsduLen)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&reader, apsdu, apsduLen);
    U_bstream_seek(&reader, (unsigned long)headerLen);
    controlAir = U_bstream_get_u8(&reader);

    keyIdentifier = (controlAir >> SECURITY_CONTROL_KEY_ID_SHIFT) & SECURITY_CONTROL_KEY_ID_MASK;

    if (keyIdentifier == SECURITY_KEY_ID_NETWORK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED);
        return ZB_ERR_UNSUPPORTED;
    }

    extendedNonce = ((controlAir >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT)
                     & SECURITY_CONTROL_EXTENDED_NONCE_MASK) ? 1 : 0;
    auxLen = extendedNonce ? SECURITY_APS_AUX_MAX : SECURITY_APS_AUX_MIN;

    micLen = securityDoMicLen(self->nwkSecurityLevel);

    if (apsduLen < headerLen + auxLen + micLen)
        return ZB_ERR_BAD_ARGUMENT;

    receivedCounter = (uint32_t)U_bstream_get_u32_le(&reader);
    auxSource = 0;

    if (extendedNonce)
        auxSource = (uint64_t)U_bstream_get_u64_le(&reader);

    if (!Zb_bstream_ok(&reader) || Zb_bstream_pos(&reader) != headerLen + auxLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (receivedCounter == SECURITY_FRAME_COUNTER_LAST)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    entryIndex = -1;

    if (extendedNonce && hintKnown && auxSource != partnerHint && self->authenticated)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    if (extendedNonce)
        entryIndex = Security_FindKeyPairByIeee(self, auxSource);
    else if (hintKnown)
        entryIndex = Security_FindKeyPairByIeee(self, partnerHint);

    if (entryIndex < 0)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    entry = &self->keyPairs[entryIndex];

    if (entry->linkKeyType == SECURITY_LINK_KEY_UNIQUE && receivedCounter < entry->incomingFrameCounter)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER);
        return ZB_ERR_BAD_FRAME_COUNTER;
    }

    controlUse = (controlAir & (SECURITY_CONTROL_MAX ^ SECURITY_CONTROL_LEVEL_MASK)) | self->nwkSecurityLevel;
    encrypts = securityDoEncrypts(self->nwkSecurityLevel);

    securedLen = apsduLen - headerLen - auxLen;
    payloadLen = securedLen - micLen;

    partnerIeee = extendedNonce ? auxSource : partnerHint;

    U_bstream_init(&nonce, nonceOctets, (unsigned long)SECURITY_NONCE_LEN);
    securityDoWriteNonce(&nonce, (uint8_t)controlUse, receivedCounter, partnerIeee);

    if (!Zb_bstream_ok(&nonce) || Zb_bstream_pos(&nonce) != SECURITY_NONCE_LEN)
        return ZB_ERR_INTERNAL;

    U_bstream_init(&adata, self->adata, (unsigned long)SECURITY_FRAME_MAX);
    U_bstream_put_bytes(&adata, apsdu, (unsigned long)headerLen);
    securityDoWriteApsAux(&adata, (uint8_t)controlUse, receivedCounter, partnerIeee, extendedNonce);

    ccmIn = 0;
    ccmInLen = 0;

    for (octet = 0; octet < payloadLen; octet++)
    {
        if (encrypts)
            self->frame[octet] = U_bstream_get_u8(&reader);
        else
            U_bstream_put_u8(&adata, U_bstream_get_u8(&reader));
    }

    for (octet = 0; octet < micLen; octet++)
        tag[octet] = U_bstream_get_u8(&reader);

    if (encrypts)
    {
        ccmIn = self->frame;
        ccmInLen = payloadLen;
    }

    adataLen = headerLen + auxLen;

    if (!encrypts)
        adataLen = adataLen + payloadLen;

    if (!Zb_bstream_ok(&adata) || Zb_bstream_pos(&adata) != adataLen)
        return ZB_ERR_INTERNAL;

    if (!Zb_bstream_ok(&reader) || Zb_bstream_pos(&reader) != apsduLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen > plainMax)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_NO_SPACE);
        return ZB_ERR_NO_SPACE;
    }

    status = securityDoApsOpen(entry, keyIdentifier, nonceOctets, self->adata, adataLen, ccmIn, ccmInLen, tag, micLen,
                               plainOut);

    if (status == ZB_ERR_AUTH && entry->linkKeyType == SECURITY_LINK_KEY_UNIQUE
        && entry->keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED && securityDoGlobalPair(self) >= 0)
    {
        entryIndex = securityDoGlobalPair(self);
        entry = &self->keyPairs[entryIndex];
        status = securityDoApsOpen(entry, keyIdentifier, nonceOctets, self->adata, adataLen, ccmIn, ccmInLen, tag,
                                   micLen, plainOut);
    }

    if (status == ZB_ERR_BAD_ARGUMENT || status == ZB_ERR_INTERNAL)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__, LOG_REASON_ERROR,
                         (uint32_t)status);
        return status;
    }

    if (status != ZB_OK)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH);
        return ZB_ERR_AUTH;
    }

    if ((entry->featuresCapabilities & SECURITY_FEATURES_FRAME_COUNTER_SYNC) != 0
        && !entry->verifiedFrameCounter)
    {
        securityDoReport(self, LOG_COMP_SECURITY_UNPROTECT_FAILED, (uint16_t)__LINE__,
                         LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNVERIFIED_FRAME_COUNTER);
        return ZB_ERR_UNVERIFIED_FRAME_COUNTER;
    }

    entry->incomingFrameCounter = receivedCounter + 1;

    if (!encrypts)
        Zb_memcpy(plainOut, self->adata + headerLen + auxLen, payloadLen);

    *plainLen = payloadLen;

    if (resultOut)
    {
        resultOut->keyPairIndex = entryIndex;
        resultOut->partnerIeee = partnerIeee;
        resultOut->frameCounter = receivedCounter;
        resultOut->rvfcSeen = ((controlAir >> SECURITY_CONTROL_RVFC_SHIFT) & SECURITY_CONTROL_RVFC_MASK) ? 1 : 0;
    }

    return ZB_OK;
}

void Security_Snapshot(const Security *self, Security_KeyState *out)
{
    uint32_t index;
    uint32_t count;

    if (!self || !out)
        return;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->nwkActiveKeySeqNumber = self->nwkActiveKeySeqNumber;

    count = 0;

    for (index = 0; index < SECURITY_KEY_SET_MAX; index++)
    {
        if (!self->keys[index].inUse)
            continue;

        out->keySeqNumber[count] = self->keys[index].keySeqNumber;
        out->outgoingFrameCounter[count] = self->keys[index].outgoingFrameCounter;
        count++;
    }

    out->keyCount = count;

    for (index = 0; index < self->keyPairCount; index++)
    {
        out->keyPairDeviceIeee[index] = self->keyPairs[index].deviceIeee;
        out->keyPairOutgoingFrameCounter[index] = self->keyPairs[index].outgoingFrameCounter;
    }

    out->keyPairCount = self->keyPairCount;
}
