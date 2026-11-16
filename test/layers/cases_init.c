/* The `stack` suite's init half: the build, the extended-address binding, the refusal matrix and the level-0
   scaffold. See `layers_cases.h` for the case list and `layers_helpers.h` for the machinery. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "zb_utils.h"

/* A struct full of something that is not a stack, which is what a caller's storage may hold and what a refusal
   has to leave cleared rather than populated up to the point it got to. */
static void stackPrefault(Zb_Layers *stack)
{
    Zb_memset(stack, 0xa5, (uint32_t)sizeof *stack);
}

void caseBuildNamed(void)
{
    StackDevice dev;
    const Radio_Pib *pib;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    uint8_t extendedPan[RADIO_ADDR_LEN];
    uint32_t count;
    uint32_t index;

    stackDevice(&dev);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "case 1: a coordinator at level 0x05 holding one key descriptor, with PAN, channel, short and extended address named, builds");

    Test_Expect(dev.stack.running == 1, "and the façade reports itself running");

    Test_Expect(Zb_LayersMac(&dev.stack) == &dev.stack.mac
                && Zb_LayersNwk(&dev.stack) == &dev.stack.nwk
                && Zb_LayersAps(&dev.stack) == &dev.stack.aps
                && Zb_LayersSecurity(&dev.stack) == &dev.stack.security,
                "the four accessors answer the modules the struct embeds: the façade composes them and hides none");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectCount(pib->channel, STACK_CHANNEL, "the MAC's PIB mirror carries the channel the config named");
    Test_ExpectCount(pib->page, 0, "and the page");
    Test_ExpectCount(pib->panId, STACK_PAN_ID, "and the PAN id");
    Test_ExpectCount(pib->shortAddress, STACK_SHORT_ADDRESS, "and the short address");
    Test_Expect(pib->rxOnWhenIdle == 1, "and the receiver duty, which Table 3-80's destination classes read back");
    Test_ExpectHex("and the extended address as the eight octets the frame field travels in, least significant octet first",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);

    Test_Expect(Zb_LayersSecurity(&dev.stack)->ownIeee == STACK_OWN_IEEE,
                "the security module answers the extended address the config named, which is the identity every auxiliary header it composes carries (3.2.1.1.3)");
    Test_ExpectCount(Zb_LayersSecurity(&dev.stack)->nwkSecurityLevel, SECURITY_LEVEL_ENC_MIC_32,
                     "and the level the stack config named, applied to the key material the application supplied");
    Test_Expect(Security_IsEnabled(Zb_LayersSecurity(&dev.stack)) == 1,
                "so the module is protecting with the key it was handed at sequence number 0x00");
    Test_Expect(Zb_LayersNwk(&dev.stack)->security == &dev.stack.security
                && Zb_LayersAps(&dev.stack)->security == &dev.stack.security,
                "and the network layer and the APS service are both attached to that one module");

    Test_ExpectCount(Zb_LayersMac(&dev.stack)->tx.dsn, STACK_DSN_START,
                     "the MAC numbers from the seed the config gave it (6.6.1)");
    Test_ExpectCount(Zb_LayersNwk(&dev.stack)->seq, STACK_SEQ_START,
                     "the network layer from its own (3.3.1.5)");
    Test_ExpectCount(Zb_LayersNwk(&dev.stack)->cfg.deviceType, NWK_DEVICE_COORDINATOR,
                     "and it knows the device type the config named");

    count = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);

    Test_Expect(count >= 1,
                "the backend was handed at least one PIB write, so what follows is a claim about a record and not about an empty one");

    for (index = 0; index < count; index++)
    {
        if ((writes[index].present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
            break;
    }

    Test_Expect(index < count,
                "and one record carried the operational long address, which is what the radio's receive filter runs on and what an unnamed session could not deliver to");

    Test_ExpectHex("in the PIB's octet order, least significant first, which is the reverse of the order the wire carries it in",
                   writes[index].extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);

    for (index = 0; index < count; index++)
    {
        if ((writes[index].present & RADIO_PIB_HW_ADDRESS) != 0)
            break;
    }

    Test_Expect(index == count,
                "and no record carried the factory address: the device's own is read and never written");

    Zb_memset(extendedPan, 0xff, RADIO_ADDR_LEN);
    Zb_LayersExtendedPanId(&dev.stack, extendedPan);

    Test_ExpectHex("the extended PAN ID is carried in the façade: an application may persist its own copy of it, nothing in band A reads it yet",
                   extendedPan, RADIO_ADDR_LEN, STACK_EXTENDED_PAN_HEX);

    Test_Expect(!Zb_LayersMac(0) && !Zb_LayersNwk(0) && !Zb_LayersAps(0) && !Zb_LayersSecurity(0),
                "each accessor answers 0 for a null stack rather than a pointer into nothing");

    Zb_memset(extendedPan, 0xff, RADIO_ADDR_LEN);
    Zb_LayersExtendedPanId(0, extendedPan);

    Test_Expect(stackIsZeroOctets(extendedPan, RADIO_ADDR_LEN),
                "and the getter answers eight zero octets for one, whatever the output held");
}

void caseBoundToOwnIeee(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.cfg.extendedAddress[3] = (uint8_t)(dev.cfg.extendedAddress[3] ^ 0xff);

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "case 2: an extended address on the air that is not the one the CCM* nonce uses is a build this stack refuses before anything runs, when the config is what names it");

    Test_Expect(dev.stack.running == 0, "so the façade is not running");

    Test_Expect(stackIsZero(&dev.stack),
                "and not one field of the four modules a partial apply would have filled survives: the whole struct is zero bytes");
}

void caseDeviceNamesOwnIeee(void)
{
    StackDevice dev;
    const Radio_Pib *pib;

    stackDevice(&dev);

    dev.cfg.present = dev.cfg.present & ~((uint32_t)RADIO_PIB_EXTENDED_ADDRESS);
    stackDeviceFactory(&dev.model, STACK_OWN_IEEE);
    stackExtendedOctets(STACK_OTHER_IEEE, dev.model.pib.extendedAddress);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a device whose factory address is the one the security config names, with the config naming no address of its own, is bound by that read and builds");

    Test_Expect(dev.stack.running == 1, "so the façade reports itself running");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectHex("with the PIB mirror carrying ownIeee, the operational address the receive filter has to match",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_Expect((pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0,
                "and that bit present in the mirror, because the façade wrote it when the config named no address");
    Test_ExpectHex("while the operational address the device held before the build is gone, which is what proves the binding read the factory field and not this one",
                   dev.model.pib.extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_ExpectHex("and the factory field still carries the device's own address, unreplaced",
                   pib->hwAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_Expect(Zb_LayersSecurity(&dev.stack)->ownIeee == STACK_OWN_IEEE,
                "while the security module carries the ownIeee the read agreed with");
}

/* D-242: a replacement unit reports its own factory address and takes over the identity it is configured with. */
void caseDeviceNamesOtherIeee(void)
{
    StackDevice dev;
    const Radio_Pib *pib;

    stackDevice(&dev);

    dev.cfg.present = dev.cfg.present & ~((uint32_t)RADIO_PIB_EXTENDED_ADDRESS);
    stackDeviceFactory(&dev.model, STACK_OTHER_IEEE);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a device whose factory address is not the configured ownIeee builds: the configuration is the identity");

    Test_Expect(dev.stack.running == 1, "so the façade reports itself running");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectHex("with the operational address the receive filter matches and every frame carries set to ownIeee",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_ExpectHex("written through to the device", dev.model.pib.extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_Expect(dev.model.pib.hwAddress[0] == (uint8_t)(STACK_OTHER_IEEE & 0xff)
                && dev.model.pib.hwAddress[7] == (uint8_t)(STACK_OTHER_IEEE >> 56),
                "while the device's factory field still reports its own address, never written");
    Test_Expect(Zb_LayersSecurity(&dev.stack)->ownIeee == STACK_OWN_IEEE,
                "and the nonce built from the same address the air carries");
}

void caseDeviceNamesNoIeee(void)
{
    StackDevice dev;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    const Radio_Pib *pib;
    uint32_t count;
    uint32_t index;

    stackDevice(&dev);

    dev.cfg.present = dev.cfg.present & ~((uint32_t)RADIO_PIB_EXTENDED_ADDRESS);
    stackDeviceFactory(&dev.model, 0);

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a part that reports no factory address at all (an unprogrammed user row, all zero) is absence rather than disagreement, so the config's ownIeee stands and the stack builds");

    Test_Expect(dev.stack.running == 1, "so the façade reports itself running");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectHex("with the PIB mirror carrying ownIeee, because the operational address is written even when the config names none: it is what the receive filter has to match",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_ExpectHex("and the factory field still the zero the device answered, since the façade writes the operational address and never the device's own",
                   pib->hwAddress, RADIO_ADDR_LEN, "0000000000000000");
    Test_Expect(Zb_LayersSecurity(&dev.stack)->ownIeee == STACK_OWN_IEEE,
                "and the security module carrying the address the application named, for every auxiliary header and the nonce to be composed from");

    count = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);

    Test_Expect(count >= 2,
                "the backend was handed the identity and then the operational address, so what follows is a claim about two records and not about an empty list");

    for (index = 0; index < count; index++)
    {
        if ((writes[index].present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
            break;
    }

    Test_Expect(index < count,
                "and one write carried the extended address: the address the filter matches is written even though the config named none");

    Test_ExpectHex("in the PIB's octet order, least significant first, which is the reverse of the order the wire carries it in",
                   writes[index].extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
}

void caseRefuseNullSelf(void)
{
    StackDevice dev;

    stackDevice(&dev);

    Test_ExpectStatus(Zb_LayersInit(0, LoopbackRadio_Seam(&dev.model), &dev.cfg), ZB_ERR_BAD_ARGUMENT,
                      "case 3: a null façade is refused before the radio, the config or anything behind them is read");
}

void caseRefuseNullConfig(void)
{
    StackDevice dev;

    stackDevice(&dev);
    stackPrefault(&dev.stack);

    Test_ExpectStatus(Zb_LayersInit(&dev.stack, LoopbackRadio_Seam(&dev.model), 0), ZB_ERR_BAD_ARGUMENT,
                      "a null config is refused whatever the caller's storage held");
    Test_Expect(stackIsZero(&dev.stack), "and the struct is zero bytes afterwards, not the 0xa5 it arrived with");
}

void caseRefuseDeviceType(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.cfg.deviceType = NWK_DEVICE_END_DEVICE + 1;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "a device type outside Table 3-75's three is refused: there is no fourth way to be a device");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack), "and every byte of it zero");
}

void caseRefuseLevelEncOnly(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "level 0x04 is refused: it is encryption with an MIC length of zero, which Table 4-38 leaves unusable and no NWK frame is protected at");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack), "and every byte of it zero");
}

void caseRefuseLevelAboveMax(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.cfg.nwkSecurityLevel = SECURITY_LEVEL_MAX + 1;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "a level above 0x07 is refused: the security level is three bits and 0x08 names nothing");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack), "and every byte of it zero");
}

void caseRefuseLevelWithoutSecurity(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.cfg.security = 0;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "a level that is not 0 with no security config to carry the key material is a contradiction, and refused as one");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack), "and every byte of it zero");
}

void caseRefuseLevelDisagreement(void)
{
    StackDevice dev;

    stackDevice(&dev);

    dev.secCfg.nwkSecurityLevel = SECURITY_LEVEL_MIC_32;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "a security config carrying key material at a level the stack config does not name is refused: one fact in two places is checked, as the extended address is");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack), "and every byte of it zero");
}

void caseJoiningEmptyKeySet(void)
{
    StackDevice dev;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t payload[4];
    uint32_t frameLen;

    stackDevice(&dev);

    dev.secCfg.keyCount = 0;

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a security config that names a level and no key is the joining device of 4.6.3.2.4: it can do security and waits for the network key, so the stack builds");
    Test_Expect(dev.stack.running == 1, "and reports itself running");
    Test_Expect(Security_IsEnabled(Zb_LayersSecurity(&dev.stack)) == 0,
                "and it reports itself not enabled, which is the very predicate 3.6.1.6.1.1's NO_KEY hangs on: the level is stated and the active network key is not there");

    Zb_memset(payload, 0x5a, (uint32_t)sizeof payload);

    Test_Expect(Security_Protect(Zb_LayersSecurity(&dev.stack), payload, 4, payload, 4, frame,
                                 (uint32_t)sizeof frame, &frameLen) != ZB_OK,
                "and a frame it is asked to protect is refused: the key it would use is the one 3.6.1.6.1.1 is still waiting for");
}

void caseLevelZeroScaffold(void)
{
    StackDevice dev;
    const Radio_Pib *pib;

    stackDevicePlain(&dev);

    Test_ExpectCount(dev.cfg.nwkSecurityLevel, SECURITY_LEVEL_NONE,
                     "case 4: a config at level 0x00 with no security module is the scaffold the modules already support");
    Test_Expect(!dev.cfg.security, "and it names no key material at all");

    stackPrefault(&dev.stack);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "so the stack builds: nothing about it is incomplete, it simply runs unsecured");
    Test_Expect(dev.stack.running == 1, "and reports itself running");

    Test_Expect(Security_IsEnabled(Zb_LayersSecurity(&dev.stack)) == 0,
                "the security module the struct embeds answers not-enabled");
    Test_Expect(Zb_LayersNwk(&dev.stack)->security == 0 && Zb_LayersAps(&dev.stack)->security == 0,
                "and neither layer above it was attached to one, which is what a zero attachment means");

    Test_ExpectStatus(Nwk_Step(Zb_LayersNwk(&dev.stack), 0), ZB_OK,
                      "and the network layer is initialised and usable: its own turn over the MAC runs and answers");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectHex("with the PIB carrying the extended address the config named, since there is no ownIeee to resolve it from",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
}
