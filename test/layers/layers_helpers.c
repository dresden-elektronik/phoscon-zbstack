/* The `stack` suite's shared machinery: the bodies. See `layers_helpers.h` for what this file is and why it is
   here. */

#include "layers_helpers.h"

#include "rig_band_a.h"
#include "zb_utils.h"

/* The extended PAN ID this device carries: the octets an application would have named, in the order the frame
   field travels in. Nothing in band A reads it yet. */
static const uint8_t s_extendedPan[RADIO_ADDR_LEN] =
{
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
};

/* The first key octet: the rest follow it, so one key is told from another by any of its octets. */
#define STACK_KEY_FIRST_OCTET 0xc0

void stackModelAt(Loopback_Radio *model)
{
    Radio_Caps caps;

    Test_BandACapsAcks(&caps);

    LoopbackRadio_Init(model, &caps);
}

void stackDeviceFactory(Loopback_Radio *model, uint64_t ieee)
{
    uint8_t octets[RADIO_ADDR_LEN];

    stackExtendedOctets(ieee, octets);

    LoopbackRadio_SetFactoryAddress(model, octets);
}

void stackKeyAt(Security_KeyDescriptor *key, uint8_t keySeq)
{
    uint32_t index;

    Zb_memset(key, 0, (uint32_t)sizeof *key);

    key->keySeqNumber = keySeq;
    key->inUse = 1;

    for (index = 0; index < SECURITY_KEY_OCTETS; index++)
        key->key[index] = (uint8_t)(STACK_KEY_FIRST_OCTET + index);
}

void stackExtendedOctets(uint64_t value, uint8_t *out)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        out[index] = (uint8_t)(value >> (index * 8));
}

int stackIsZeroOctets(const uint8_t *octets, uint32_t len)
{
    uint32_t index;

    for (index = 0; index < len; index++)
    {
        if (octets[index] != 0)
            return 0;
    }

    return 1;
}

int stackIsZero(const Zb_Layers *stack)
{
    uint8_t zero[sizeof(Zb_Layers)];

    Zb_memset(zero, 0, (uint32_t)sizeof zero);

    return Zb_memcmp(stack, zero, (uint32_t)sizeof zero) == 0;
}

/* The identity the application names: every field the seam's mask has a word for, and the two extended
   addresses it carries. */
static void stackIdentity(Zb_LayersConfig *cfg)
{
    cfg->present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                   | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE;

    cfg->channel = STACK_CHANNEL;
    cfg->page = 0;
    cfg->panId = STACK_PAN_ID;
    cfg->shortAddress = STACK_SHORT_ADDRESS;
    cfg->rxOnWhenIdle = 1;

    stackExtendedOctets(STACK_OWN_IEEE, cfg->extendedAddress);

    Zb_memcpy(cfg->extendedPanId, s_extendedPan, RADIO_ADDR_LEN);
}

void stackDevicePlain(StackDevice *dev)
{
    Zb_memset(dev, 0, (uint32_t)sizeof *dev);

    stackModelAt(&dev->model);
    stackIdentity(&dev->cfg);

    dev->cfg.deviceType = NWK_DEVICE_COORDINATOR;
    dev->cfg.seqStart = STACK_SEQ_START;
    dev->cfg.jitterSeed = 0;
    dev->cfg.dsnStart = STACK_DSN_START;
}

void stackDevice(StackDevice *dev)
{
    stackDevicePlain(dev);

    stackKeyAt(&dev->key, STACK_KEY_SEQ);

    dev->secCfg.ownIeee = STACK_OWN_IEEE;
    dev->secCfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    dev->secCfg.nwkActiveKeySeqNumber = STACK_KEY_SEQ;
    dev->secCfg.authenticated = 1;
    dev->secCfg.nwkAllFresh = 1;
    dev->secCfg.keys = &dev->key;
    dev->secCfg.keyCount = 1;

    dev->cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    dev->cfg.security = &dev->secCfg;
}

ZbStatus stackInit(StackDevice *dev)
{
    return Zb_LayersInit(&dev->stack, LoopbackRadio_Seam(&dev->model), &dev->cfg);
}
