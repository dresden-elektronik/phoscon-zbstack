#include "nwk.h"

#include "nwk_poll.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_join.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 2.5.4.5.5.1, 2.5.4.5.5.2, 3.2.2.24, 3.2.2.25, 3.6.1.15, 3.6.2.2 ok (the rate is the application's, the
   retries and the default rate the house's, both open; a fragmented message's faster rate is asked from above). */

static int nwkPollJoined(const Nwk_Nwk *self)
{
    return self->cfg.deviceType == NWK_DEVICE_END_DEVICE && self->joinState == NWK_JOIN_JOINED
           && self->joinParentShortKnown;
}

/* Attaching: the layer above negotiating, or a joined device still waiting for its network key. */
static uint32_t nwkPollIntervalMs(const Nwk_Nwk *self)
{
    if (self->pollFast || (self->security != 0 && Security_Level(self->security) != SECURITY_LEVEL_NONE
                           && !Security_IsEnabled(self->security)))
        return NWK_POLL_ATTACH_MS;

    return self->pollRateMs != 0 ? self->pollRateMs : NWK_POLL_RATE_DEFAULT_MS;
}

static int nwkPollRetried(ZbStatus status)
{
    return status == ZB_ERR_TRANSACTION_OVERFLOW || status == ZB_ERR_NO_SPACE
           || status == ZB_ERR_CHANNEL_ACCESS_FAILURE;
}

static void nwkPollSyncEnd(Nwk_Nwk *self, ZbStatus status)
{
    if (nwkPollRetried(status) && self->syncRetries < NWK_POLL_ADDITIONAL_RETRIES)
    {
        self->syncRetries++;
        self->syncOwed = 1;
        return;
    }

    self->syncConfirm.status = status == ZB_ERR_NO_SPACE ? ZB_ERR_TRANSACTION_OVERFLOW : status;
    self->syncConfirmReady = 1;
}

/* A failed indirect request is a poll the parent never acknowledged; an acknowledged one held the link. */
static void nwkPollTaken(Nwk_Nwk *self, const Mac_PollConfirmParameters *confirm)
{
    int wasSync = self->pollIsSync;

    self->pollOut = 0;
    self->pollIsSync = 0;

    if (confirm->status == ZB_OK || confirm->status == ZB_ERR_NO_DATA)
        Nwk_JoinParentLinkHeld(self, (uint16_t)self->joinParentShort);
    else if (confirm->status == ZB_ERR_NO_ACK)
        Nwk_JoinParentLinkFailed(self, (uint16_t)self->joinParentShort);

    self->pollAgain = confirm->status == ZB_OK && confirm->framePending;

    if (wasSync)
        nwkPollSyncEnd(self, confirm->status);
}

void Nwk_PollStep(Nwk_Nwk *self, uint32_t nowMs)
{
    Mac_PollRequestParameters req;
    Mac_PollConfirmParameters confirm;
    int sync;
    ZbStatus status;

    if (self == 0 || self->mac == 0)
        return;

    if (self->pollOut && Mac_PollRequestConfirm(self->mac, &confirm) == 1)
        nwkPollTaken(self, &confirm);

    if (self->pollOut || !nwkPollJoined(self))
        return;

    sync = self->syncOwed;

    if (!sync && !self->pollAgain)
    {
        if (Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(self->mac)))
            return;

        if (self->pollLastKnown && Zb_timeWithin(nowMs, self->pollLastMs, nwkPollIntervalMs(self)))
            return;
    }

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.coordAddrMode = MAC_ADDR_SHORT;
    req.coordPanId = Mac_Pib(self->mac)->panId;
    req.coordShort = (uint16_t)self->joinParentShort;

    status = Mac_PollRequest(self->mac, &req, nowMs);

    if (status == ZB_ERR_BUSY)
        return;

    self->pollLastMs = nowMs;
    self->pollLastKnown = 1;
    self->pollAgain = 0;
    self->syncOwed = 0;

    if (status == ZB_OK)
    {
        self->pollOut = 1;
        self->pollIsSync = sync;
        self->pollsSent++;
        return;
    }

    if (sync)
        nwkPollSyncEnd(self, status);
}

ZbStatus Nwk_SyncRequest(Nwk_Nwk *self)
{
    if (self == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!nwkPollJoined(self))
        return ZB_ERR_BAD_STATE;

    if (self->syncOwed || (self->pollOut && self->pollIsSync))
        return ZB_ERR_BUSY;

    self->syncOwed = 1;
    self->syncRetries = 0;

    return ZB_OK;
}

uint32_t Nwk_PollSyncConfirm(Nwk_Nwk *self, Nwk_SyncConfirmParameters *out)
{
    if (self == 0 || out == 0 || !self->syncConfirmReady)
        return 0;

    *out = self->syncConfirm;
    self->syncConfirmReady = 0;

    return 1;
}

void Nwk_SetPollRate(Nwk_Nwk *self, uint32_t rateMs)
{
    if (self != 0)
        self->pollRateMs = rateMs;
}

void Nwk_SetPollFast(Nwk_Nwk *self, int fast)
{
    if (self != 0)
        self->pollFast = fast ? 1 : 0;
}
