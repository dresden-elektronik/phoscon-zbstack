#ifndef ZB_LAYERS_H
#define ZB_LAYERS_H

#include <stdint.h>

#include "aps.h"
#include "log.h"
#include "mac.h"
#include "nwk.h"
#include "radio.h"
#include "security.h"
#include "zb_state.h"
#include "zb_status.h"

typedef struct Zb_LayersConfig
{
    uint32_t present;
    uint32_t channel;
    uint32_t page;
    uint16_t panId;
    uint16_t shortAddress;
    uint8_t extendedAddress[RADIO_ADDR_LEN];
    uint8_t extendedPanId[RADIO_ADDR_LEN];
    int rxOnWhenIdle;

    uint32_t deviceType;
    uint32_t seqStart;
    uint32_t jitterSeed;
    uint32_t joinSeed;
    uint32_t dsnStart;
    uint32_t endDeviceTimeout;     /* an end device's: the Table 3-58 enumeration it asks its parent for, 0 being 10 s */
    uint32_t indirectPollRateMs;   /* a resting end device's :Config_NWK_indirectPollRate, 0 its default */
    int hearsWhileAsleep;          /* 1: a resting device keeps what its radio heard between polls, for debugging */

    uint32_t nwkSecurityLevel;
    const Security_Config *security;

    uint64_t trustCenterIeee;      /* the AIB's apsTrustCenterAddress: 0 names none, the all-ones 3.6.1.6.1.3 reads */

    /* The diagnostics pool the modules below report through, or 0 for none: the caller owns it and drains it,
       the way it owns the security config's pool (docs/internals/coding-rules.md §5). A 0 sink costs no report. */
    Log_Log *log;
} Zb_LayersConfig;

typedef struct Zb_Layers
{
    Mac_Mac mac;
    Nwk_Nwk nwk;
    Aps_Aps aps;
    Security security;
    uint8_t extendedPanId[RADIO_ADDR_LEN];
    int running;
} Zb_Layers;

ZbStatus Zb_LayersInit(Zb_Layers *self, Radio_Radio *radio, const Zb_LayersConfig *cfg);
ZbStatus Zb_LayersStep(Zb_Layers *self, uint32_t nowMs);
uint32_t Zb_LayersPollConfirms(Zb_Layers *self, Aps_Confirm *out, uint32_t max);
uint32_t Zb_LayersPollIndications(Zb_Layers *self, Aps_Indication *out, uint32_t max);
ZbStatus Zb_LayersDataRequest(Zb_Layers *self, const Aps_ApsdeReq *req, uint32_t nowMs);
Mac_Mac *Zb_LayersMac(Zb_Layers *self);
Nwk_Nwk *Zb_LayersNwk(Zb_Layers *self);
Aps_Aps *Zb_LayersAps(Zb_Layers *self);
Security *Zb_LayersSecurity(Zb_Layers *self);
void Zb_LayersExtendedPanId(const Zb_Layers *self, uint8_t out[RADIO_ADDR_LEN]);
ZbStatus Zb_LayersCapture(const Zb_Layers *self, int includeKeys, Zb_State *out);
ZbStatus Zb_LayersRestore(Zb_Layers *self, const Zb_State *in);

#endif
