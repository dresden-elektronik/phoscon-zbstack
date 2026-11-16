#include "zb_layers.h"

#include "zb_utils.h"

static int zbStackDeviceTypeUsable(uint32_t deviceType)
{
    if (deviceType == NWK_DEVICE_COORDINATOR)
        return 1;

    if (deviceType == NWK_DEVICE_ROUTER)
        return 1;

    return deviceType == NWK_DEVICE_END_DEVICE;
}

static int zbStackSecurityLevelUsable(uint32_t level)
{
    switch (level)
    {
        case SECURITY_LEVEL_NONE:
        case SECURITY_LEVEL_MIC_32:
        case SECURITY_LEVEL_MIC_64:
        case SECURITY_LEVEL_MIC_128:
        case SECURITY_LEVEL_ENC_MIC_32:
        case SECURITY_LEVEL_ENC_MIC_64:
        case SECURITY_LEVEL_ENC_MIC_128:
            return 1;

        default:
            return 0;
    }
}

static uint64_t zbStackExtendedValue(const uint8_t *octets)
{
    uint64_t value;
    uint32_t index;

    value = 0;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        value = value | ((uint64_t)octets[index] << (index * 8));

    return value;
}

static void zbStackExtendedOctets(uint64_t value, uint8_t *octets)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        octets[index] = (uint8_t)(value >> (index * 8));
}

static ZbStatus zbStackValidate(const Zb_LayersConfig *cfg)
{
    if (!zbStackDeviceTypeUsable(cfg->deviceType))
        return ZB_ERR_BAD_ARGUMENT;

    if (!zbStackSecurityLevelUsable(cfg->nwkSecurityLevel))
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->nwkSecurityLevel != SECURITY_LEVEL_NONE && !cfg->security)
        return ZB_ERR_BAD_ARGUMENT;

    if (!cfg->security)
        return ZB_OK;

    if (cfg->security->nwkSecurityLevel != cfg->nwkSecurityLevel)
        return ZB_ERR_BAD_ARGUMENT;

    if ((cfg->present & RADIO_PIB_EXTENDED_ADDRESS) == 0)
        return ZB_OK;

    if (zbStackExtendedValue(cfg->extendedAddress) != cfg->security->ownIeee)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

static void zbStackPibOf(const Zb_LayersConfig *cfg, Radio_Pib *pib)
{
    Zb_memset(pib, 0, (uint32_t)sizeof *pib);

    pib->present = cfg->present;
    pib->channel = cfg->channel;
    pib->page = cfg->page;
    pib->panId = cfg->panId;
    pib->shortAddress = cfg->shortAddress;
    pib->rxOnWhenIdle = cfg->rxOnWhenIdle;

    if ((cfg->present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
        Zb_memcpy(pib->extendedAddress, cfg->extendedAddress, RADIO_ADDR_LEN);
}

/* The operational address is the security config's ownIeee whatever the device's factory field reports, which stays
   read and never written: a replacement unit takes over its predecessor's identity (D-242). */
static ZbStatus zbStackOperationalAddress(Mac_Mac *mac, const Zb_LayersConfig *cfg)
{
    Radio_Pib pib;

    if ((cfg->present & RADIO_PIB_EXTENDED_ADDRESS) != 0 || !cfg->security)
        return ZB_OK;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    zbStackExtendedOctets(cfg->security->ownIeee, pib.extendedAddress);

    return Mac_SetPib(mac, &pib);
}

ZbStatus Zb_LayersInit(Zb_Layers *self, Radio_Radio *radio, const Zb_LayersConfig *cfg)
{
    Mac_Config macCfg;
    Nwk_Config nwkCfg;
    Radio_Pib pib;
    ZbStatus status;

    if (!self)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    if (!cfg)
        return ZB_ERR_BAD_ARGUMENT;

    status = zbStackValidate(cfg);

    if (status != ZB_OK)
        return status;

    Zb_memset(&macCfg, 0, (uint32_t)sizeof macCfg);
    macCfg.dsnStart = (uint8_t)cfg->dsnStart;

    macCfg.log = cfg->log;
    macCfg.hearsWhileAsleep = cfg->hearsWhileAsleep;

    Zb_memset(&nwkCfg, 0, (uint32_t)sizeof nwkCfg);
    nwkCfg.deviceType = cfg->deviceType;
    nwkCfg.seqStart = cfg->seqStart;
    nwkCfg.jitterSeed = cfg->jitterSeed;
    nwkCfg.joinSeed = cfg->joinSeed;
    nwkCfg.endDeviceTimeout = cfg->endDeviceTimeout;
    nwkCfg.indirectPollRateMs = cfg->indirectPollRateMs;
    nwkCfg.trustCenterIeee = cfg->trustCenterIeee;

    zbStackPibOf(cfg, &pib);

    status = Mac_Init(&self->mac, radio, &macCfg);

    if (status == ZB_OK)
        status = Mac_SetPib(&self->mac, &pib);

    if (status == ZB_OK)
        status = zbStackOperationalAddress(&self->mac, cfg);

    if (status == ZB_OK && cfg->security)
        status = Security_Init(&self->security, cfg->security);

    if (status == ZB_OK)
        status = Nwk_Init(&self->nwk, &self->mac, &nwkCfg);

    if (status == ZB_OK && cfg->security)
        Nwk_AttachSecurity(&self->nwk, &self->security);

    if (status == ZB_OK)
        status = Aps_Init(&self->aps, &self->nwk);

    if (status == ZB_OK && cfg->security)
        Aps_AttachSecurity(&self->aps, &self->security);

    if (status != ZB_OK)
    {
        Zb_memset(self, 0, (uint32_t)sizeof *self);

        return status;
    }

    Zb_memcpy(self->extendedPanId, cfg->extendedPanId, RADIO_ADDR_LEN);
    self->running = 1;

    return ZB_OK;
}

ZbStatus Zb_LayersStep(Zb_Layers *self, uint32_t nowMs)
{
    if (!self || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    return Aps_Step(&self->aps, nowMs);
}

uint32_t Zb_LayersPollConfirms(Zb_Layers *self, Aps_Confirm *out, uint32_t max)
{
    if (!self || !out || max == 0)
        return 0;

    return Aps_PollConfirms(&self->aps, out, max);
}

uint32_t Zb_LayersPollIndications(Zb_Layers *self, Aps_Indication *out, uint32_t max)
{
    if (!self || !out || max == 0)
        return 0;

    return Aps_PollIndications(&self->aps, out, max);
}

ZbStatus Zb_LayersDataRequest(Zb_Layers *self, const Aps_ApsdeReq *req, uint32_t nowMs)
{
    if (!self || !req || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    return Aps_DataRequest(&self->aps, req, nowMs);
}

Mac_Mac *Zb_LayersMac(Zb_Layers *self)
{
    return self ? &self->mac : 0;
}

Nwk_Nwk *Zb_LayersNwk(Zb_Layers *self)
{
    return self ? &self->nwk : 0;
}

Aps_Aps *Zb_LayersAps(Zb_Layers *self)
{
    return self ? &self->aps : 0;
}

Security *Zb_LayersSecurity(Zb_Layers *self)
{
    return self ? &self->security : 0;
}

void Zb_LayersExtendedPanId(const Zb_Layers *self, uint8_t out[RADIO_ADDR_LEN])
{
    if (!out)
        return;

    if (!self)
    {
        Zb_memset(out, 0, RADIO_ADDR_LEN);

        return;
    }

    Zb_memcpy(out, self->extendedPanId, RADIO_ADDR_LEN);
}

/* nwkExtendedPANID is the joined network's for a joiner and the configured one for the device that formed it, which
   joins nothing and so leaves the join's field empty. */
ZbStatus Zb_LayersCapture(const Zb_Layers *self, int includeKeys, Zb_State *out)
{
    ZbStatus status;
    uint32_t i;

    if (!self || !self->running || !out)
        return ZB_ERR_BAD_ARGUMENT;

    status = Zb_StateCapture(&self->security, &self->nwk, &self->aps, &self->mac, includeKeys, out);

    if (status != ZB_OK || out->extendedPanId != 0)
        return status;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        out->extendedPanId |= (uint64_t)self->extendedPanId[i] << (8 * i);

    return ZB_OK;
}

ZbStatus Zb_LayersRestore(Zb_Layers *self, const Zb_State *in)
{
    if (!self || !self->running || !in)
        return ZB_ERR_BAD_ARGUMENT;

    return Zb_StateRestore(&self->security, &self->nwk, &self->aps, &self->mac, in);
}
