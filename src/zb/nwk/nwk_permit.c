#include "nwk_permit.h"

#include "nwk_beacon.h"
#include "zb_utils.h"

/* R23.1: 3.2.2.7, 3.2.2.7.3, 3.2.2.8.1, Table 3-15, Table 3-16 ok. */

/* 3.2.2.7.3's three arms: 0x00 sets the permit false, 0xff sets it true for as long as the device stands, and
   anything between sets it true until the seconds have passed. Every request overwrites the one before it. */
uint32_t Nwk_PermitJoining(Nwk_Nwk *self, uint32_t permitDuration, uint32_t nowMs)
{
    int permit;

    if (self == 0 || self->mac == 0)
        return NWK_PERMIT_INV_REQUESTTYPE;

    if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        return NWK_PERMIT_INV_REQUESTTYPE;

    if (permitDuration > NWK_PERMIT_UNLIMITED)
        return NWK_PERMIT_INV_REQUESTTYPE;

    permit = permitDuration != NWK_PERMIT_OFF ? 1 : 0;

    if (!self->beaconInfoKnown || Nwk_SetBeaconInfo(self, &self->beaconInfo, permit) != ZB_OK)
        return NWK_PERMIT_INV_REQUESTTYPE;

    self->permitRequests++;

    self->permitUntilMs = permitDuration == NWK_PERMIT_OFF || permitDuration == NWK_PERMIT_UNLIMITED
        ? 0
        : nowMs + permitDuration * 1000;

    return NWK_PERMIT_SUCCESS;
}

int Nwk_PermitJoiningActive(const Nwk_Nwk *self)
{
    return self != 0 ? self->associationPermit : 0;
}

/* The timer 3.2.2.7.3 arms for a duration: on expiration the permit is set false the same way it was set true. */
void Nwk_PermitExpire(Nwk_Nwk *self, uint32_t nowMs)
{
    if (self == 0 || self->permitUntilMs == 0 || nowMs < self->permitUntilMs)
        return;

    self->permitUntilMs = 0;

    if (Nwk_SetBeaconInfo(self, &self->beaconInfo, 0) == ZB_OK)
        self->permitExpiries++;
}

uint32_t Nwk_PermitJoiningRequests(const Nwk_Nwk *self)
{
    return self != 0 ? self->permitRequests : 0;
}

uint32_t Nwk_PermitJoiningExpiries(const Nwk_Nwk *self)
{
    return self != 0 ? self->permitExpiries : 0;
}
