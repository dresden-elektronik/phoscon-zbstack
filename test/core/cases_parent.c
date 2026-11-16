/* An end device that loses its parent (2.5.4.5.5.2), and a device a saved state puts back on its network. */

#include "core_helpers.h"
#include "nwk_join.h"
#include "test_harness.h"
#include "zb_utils.h"

/* Turns of the device alone, from `from` to `until`, ten milliseconds apart. */
static void parentTurns(DeviceRig *rig, uint32_t from, uint32_t until)
{
    uint32_t now;

    for (now = from; now <= until; now += 10)
        (void)Zb_CoreStep(&rig->dev, now);
}

void caseParentLostThenRejoined(void)
{
    static DeviceRig rig;
    Nwk_Nwk *nwk;
    uint32_t i;
    uint32_t failedAt;

    Test_Case("caseParentLostThenRejoined");

    deviceRigBuildEndDevice(&rig);
    nwk = Zb_CoreNwk(&rig.dev);

    for (i = 1; i <= ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT; i++)
    {
        nwk->keepalive = NWK_KEEPALIVE_NONE;
        Nwk_JoinParentLinkFailed(nwk, DEVICE_PEER_SHORT);
        (void)Zb_CoreStep(&rig.dev, 100 * i);

        Test_ExpectCount(Zb_CoreParentLinkFailures(&rig.dev), i, "an end device counts each parent link failure");
        Test_Expect(nwk->keepalive == NWK_KEEPALIVE_OWED && rig.dev.joinState == ZB_CORE_JOIN_IDLE,
                    "and up to the threshold tries its parent again with a keepalive, not a rejoin (5403-5405)");
    }

    nwk->keepalive = NWK_KEEPALIVE_NONE;
    Nwk_JoinParentLinkFailed(nwk, DEVICE_PEER_SHORT);
    (void)Zb_CoreStep(&rig.dev, 1000);

    Test_ExpectCount(rig.dev.joinState, ZB_CORE_JOIN_REJOIN_DISCOVERING,
                     "the failure past the threshold starts the rejoin, with a discovery of its network's parents (5405-5407)");

    for (failedAt = 1010; failedAt < 5000 && Zb_CoreRejoinsFailed(&rig.dev) == 0; failedAt += 10)
        (void)Zb_CoreStep(&rig.dev, failedAt);

    Test_ExpectCount(Zb_CoreRejoinsFailed(&rig.dev), 1, "no parent answers, so the rejoin fails");
    Test_Expect(rig.dev.rejoinOwed && rig.dev.rejoinIntervalMs == ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS,
                "and another is owed after the configured interval, not yet a longer one (5421-5423)");

    parentTurns(&rig, failedAt, 1000 + ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS - 10);
    Test_ExpectCount(rig.dev.joinState, ZB_CORE_JOIN_IDLE,
                     "it waits out the interval since the last rejoin started (5421-5423)");

    parentTurns(&rig, 1000 + ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS + 10, 1000 + ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS + 10);
    Test_ExpectCount(rig.dev.joinState, ZB_CORE_JOIN_REJOIN_DISCOVERING, "and then starts the next");

    rig.dev.rejoinIntervalMs = ZB_CORE_MAX_REJOIN_INTERVAL_DEFAULT_MS - 1;

    for (failedAt = 1000 + ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS + 20;
         failedAt < 1000 + 2 * ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS && Zb_CoreRejoinsFailed(&rig.dev) == 1; failedAt += 10)
        (void)Zb_CoreStep(&rig.dev, failedAt);

    Test_ExpectCount(Zb_CoreRejoinsFailed(&rig.dev), 2, "that one fails too");
    Test_ExpectCount(rig.dev.rejoinIntervalMs, ZB_CORE_MAX_REJOIN_INTERVAL_DEFAULT_MS,
                     "and the second failure in a row doubles the interval, from just under its maximum to it, which it SHOULD NOT exceed (5424-5426)");
}

void caseParentAnswerEndsTheRun(void)
{
    static DeviceRig rig;
    Nwk_Nwk *nwk;
    uint32_t i;

    Test_Case("caseParentAnswerEndsTheRun");

    deviceRigBuildEndDevice(&rig);
    nwk = Zb_CoreNwk(&rig.dev);

    for (i = 1; i <= ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT; i++)
    {
        nwk->keepalive = NWK_KEEPALIVE_NONE;
        Nwk_JoinParentLinkFailed(nwk, DEVICE_PEER_SHORT);
        (void)Zb_CoreStep(&rig.dev, 100 * i);
    }

    Test_ExpectCount(Zb_CoreParentLinkFailures(&rig.dev), ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT,
                     "an end device at its threshold of parent link failures");

    Nwk_JoinParentLinkHeld(nwk, DEVICE_PEER_SHORT);
    (void)Zb_CoreStep(&rig.dev, 1000);
    Test_ExpectCount(Zb_CoreParentLinkFailures(&rig.dev), 0,
                     "an exchange its parent answers ends the run: the threshold counts consecutive failures (5378-5380)");

    nwk->keepalive = NWK_KEEPALIVE_NONE;
    Nwk_JoinParentLinkFailed(nwk, DEVICE_PEER_SHORT);
    (void)Zb_CoreStep(&rig.dev, 1100);
    Test_Expect(rig.dev.joinState == ZB_CORE_JOIN_IDLE && !rig.dev.rejoinOwed,
                "so the next failure, the fourth in all, starts no rejoin");
}

void caseRouterLinkFailureStartsNothing(void)
{
    static DeviceRig rig;

    Test_Case("caseRouterLinkFailureStartsNothing");

    deviceRigBuildRouter(&rig);
    Zb_CoreNwk(&rig.dev)->joinParentShort = DEVICE_PEER_SHORT;
    Zb_CoreNwk(&rig.dev)->joinParentShortKnown = 1;
    Nwk_JoinParentLinkFailed(Zb_CoreNwk(&rig.dev), DEVICE_PEER_SHORT);
    (void)Zb_CoreStep(&rig.dev, 100);

    Test_ExpectCount(Zb_CoreParentLinkFailures(&rig.dev), 0,
                     "a router raises no parent link failure, so its core counts none and owes no rejoin");
    Test_Expect(!rig.dev.rejoinOwed, "and starts nothing");
}

void caseRestoreAnnouncesOnlyWhenAsked(void)
{
    static DeviceRig rig;
    static Zb_State state;

    Test_Case("caseRestoreAnnouncesOnlyWhenAsked");

    deviceRigBuildEndDevice(&rig);
    Test_ExpectStatus(Zb_LayersCapture(Zb_CoreLayers(&rig.dev), 0, &state), ZB_OK, "an end device is captured");

    deviceRigBuildEndDevice(&rig);
    Test_ExpectStatus(Zb_CoreRestore(&rig.dev, &state, 0), ZB_OK, "and restored");
    Test_Expect(rig.dev.joinAnnounced, "with no announcement owed, since no join or rejoin happened (2.4.3.1.11.1)");

    deviceRigBuildEndDevice(&rig);
    Test_ExpectStatus(Zb_CoreRestore(&rig.dev, &state, 1), ZB_OK, "restored again, asking for one");
    Test_Expect(!rig.dev.joinAnnounced, "it owes the Device_annce it sends on its next turn");
    (void)Zb_CoreStep(&rig.dev, 100);
    Test_Expect(rig.dev.joinAnnounced, "and sends it");

    state.deviceType = NWK_DEVICE_ROUTER;
    deviceRigBuildEndDevice(&rig);
    Test_ExpectStatus(Zb_CoreRestore(&rig.dev, &state, 0), ZB_ERR_BAD_ARGUMENT,
                      "a state of another role is refused");
}

void caseTrustCentreForgetsALinkKey(void)
{
    static DeviceRig rig;
    static const uint8_t unique[SECURITY_KEY_OCTETS] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                          0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    uint8_t global[SECURITY_KEY_OCTETS];
    Security *security;
    const Security_KeyPairEntry *entry;
    int index;

    Test_Case("caseTrustCentreForgetsALinkKey");

    deviceRigBuildTrustCentre(&rig);
    security = &Zb_CoreLayers(&rig.dev)->security;
    Test_ParseHex(DEVICE_LINK_KEY_HEX, global, SECURITY_KEY_OCTETS);

    index = Security_SetUnverifiedPair(security, DEVICE_PEER_IEEE, DEVICE_PEER_SHORT, unique);
    Test_ExpectStatus(Security_ConfirmKeyPair(security, index), ZB_OK,
                      "a device that asked for a link key of its own holds a verified one");
    Test_ExpectCount((uint32_t)Security_FindKeyPairByIeee(security, DEVICE_PEER_IEEE), (uint32_t)index,
                     "and a key sent to it is protected with that key, as 11542-11543 says it is on a later join");

    Test_ExpectStatus(Zb_CoreForgetLinkKey(&rig.dev, DEVICE_PEER_IEEE), ZB_OK,
                      "the operator has the trust centre forget it");
    entry = Security_KeyPairAt(security, index);
    Test_Expect(entry != 0 && entry->deviceIeee == DEVICE_PEER_IEEE && entry->linkKeyType == SECURITY_LINK_KEY_GLOBAL
                && entry->keyAttributes == SECURITY_KEYPAIR_ATTR_PROVISIONAL
                && Zb_memcmp(entry->key, global, SECURITY_KEY_OCTETS) == 0,
                "and its entry, in its place, is the one 4.7.3.1 gives a device joining with no key: global, provisional");
    Test_ExpectCount((uint32_t)Security_FindKeyPairByIeee(security, DEVICE_PEER_IEEE), (uint32_t)index,
                     "so a factory-reset device that joins again is sent the network key under the global key");
    Test_Expect(Security_KeyPairAt(security, Security_FindKeyPairByIeee(security, 0x0102030405060708))->deviceIeee == 0,
                "while a device the trust centre never met still gets the global entry that names no device");

    Test_ExpectStatus(Zb_CoreForgetLinkKey(&rig.dev, 0x0102030405060708), ZB_ERR_NOT_FOUND,
                      "a device with no key of its own has none to forget");

    deviceRigBuildRouter(&rig);
    Test_ExpectStatus(Zb_CoreForgetLinkKey(&rig.dev, DEVICE_PEER_IEEE), ZB_ERR_BAD_STATE,
                      "and only a trust centre forgets one");
}
