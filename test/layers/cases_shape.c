/* The `stack` suite's shape half: what the four embedded pools cost, and that a refusal leaves a struct a
   second init can build on. See `layers_cases.h` for the case list and `layers_helpers.h` for the machinery. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "zb_utils.h"

/* The footprint as this build measures it. The four modules are statically sized pools by design, so each of
   these numbers is a decision already taken inside the module it belongs to; pinned here, a growth shows up as
   a failing case and in the line `main` prints, rather than as a struct that quietly stopped fitting a device.
   The numbers are the host build's: pointer-free fields but 64-bit alignment, so a 32-bit target is smaller. */
#define STACK_SIZE_MAC 13152
#define STACK_SIZE_NWK 38976
#define STACK_SIZE_SECURITY 14656
#if ZB_APS_FRAGMENTATION
#define STACK_SIZE_APS 7272
#define STACK_SIZE_STACK 74072
#else
#define STACK_SIZE_APS 5352             /* no fragmented ASDU per transaction and no reassembly pool */
#define STACK_SIZE_STACK 72152
#endif

/* A build that sizes a table its own way (ZB_LIMIT_*) has other numbers, which `main` prints and this case leaves. */
void caseFootprint(void)
{
#ifdef ZB_LIMITS_CHANGED
    Test_Expect(sizeof(Zb_Layers) > sizeof(Nwk_Nwk), "case 5: a build of its own sizes is not held to the defaults' footprint");
#else
    Test_ExpectCount((uint32_t)sizeof(Mac_Mac), STACK_SIZE_MAC,
                     "case 5: Mac_Mac is the pool it was measured at: 8 tracks, 8 indications (one radio poll's), 32 transactions, 8 poll events, 8 association events, the scan's record with an orphan scan's realignment and 10.20.4.2's four orphan indications, an ED scan's sixteen levels and the dwell it owes, the child association exchange (its state, its confirm, the parent and handle it holds, and the request and PIB write it re-asks while the door has no room), 127-octet buffers, the two PIB records (the mirror adopted from the device and the mask band A applied) and the beacon's two pools, the payload as the layer above set it and the MAC payload composed around it, the two version-2 frame control bits a parsed header now carries, the log sink a refusal is reported through, the beacon reply held while the door has no room, the two beacons waiting as 8.2.4.3's own events with the address list 10.22.3 reads, the poll it owes, the four confirmations its transactions finish with, the 32 short/extended pairs the association door learns, the four MLME-COMM-STATUS indications a response-instigated transaction finishes with, the count of beacons 8.2.4.3 does not owe, the delivery mode stated and its restatement owed after a loss, and the receive counts that came with it, four of them 6.6.2's refusals by reason, five the association answer's and five the parent's, and the device's own poll (10.22.3's two windows, MLME-POLL's and the other Data Requests', its confirm and four counts)");
    Test_ExpectCount((uint32_t)sizeof(Nwk_Nwk), STACK_SIZE_NWK,
                     "Nwk_Nwk is the largest of the four: 8 transmit slots with NPDU buffers, 64 neighbours with Table 3-75's age, failure count, two activity counters, the two metrics 3.6.4.4.2 derives, its SecurityTimer, 3.6.10's device timeout and counter with its clock mark and Keepalive Received, 3.6.4.4.3.1's promotion count and 3.6.4.4.1's broadcast clock, Table 3-68's 200-row address map and the 8-deep ring of its changes, 128 routes, Table 3-67's 200 source route records and the 16-deep ring of their changes, the BTT records with their relay buffers, the four held-relay records, the discovery table's six ranked entries and the discovery request it is filled by, the ED scan running and the channels it asked, 3.6.6's passive-acknowledgement mark, the mark that says a record is a broadcast this device sent, and the count of the marks a neighbour's relay landed, 8 route discovery entries, the two Route Request schedule pools with their copies of the octets (eight initiations' and 3.6.4.5.1.4's relays', each pool the discovery table's size), 3.6.4.8.1's one relayed unicast, Table 3-74's six discovery entries, the 8-deep ring of 3.2.2.14's join indications and the 8 association answers waiting on their delivery, Table 3-25's four status indications, the confirmation ring's own count of the answers it had no room for the scratch the MAC's MLME-COMM-STATUS and MLME-POLL indications are drained into, the one MCPS-DATA.indication being decided, 3.6.10.4's two counts, and a resting end device's poll schedule with NLME-SYNC's retries and confirm");
    Test_ExpectCount((uint32_t)sizeof(Aps_Aps), STACK_SIZE_APS,
                     "Aps_Aps is its transaction, group, duplicate, binding, key-indication, update-device, remove-device and delivery ring pools plus one call's scratch, each transaction carrying the caller's tag and the Table 4-39 identifier its protection names, whether it owes a Table 2-3 confirm and whether the network layer may protect it, a joiner's trust centre link key update and its account, and each indication carrying 2.2.4.1.3.2's 64-bit source, and, where fragmentation is built, each transaction 2.2.8.4.5's fragmented ASDU and the reassembly pool");
    Test_ExpectCount((uint32_t)sizeof(Security), STACK_SIZE_SECURITY,
                     "Security is the two key-set descriptors, 128 incoming windows, 200 key pairs, apsTrustCenterAddress with the transport-key policy value, D-218's link key seed, and the 127-octet work buffers");
    Test_ExpectCount((uint32_t)sizeof(Zb_Layers), STACK_SIZE_STACK,
                     "and Zb_Layers is the four of them by value plus the identity copy and the running flag: no allocation, so this is the whole of what a device spends on the stack, 48 octets of it band A's own record of what it applied");
#endif
}

void caseRetryAfterRefusal(void)
{
    StackDevice dev;
    const Radio_Pib *pib;

    stackDevice(&dev);

    dev.secCfg.ownIeee = STACK_OTHER_IEEE;

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "case 6: a config the binding refuses leaves the struct zero bytes");

    dev.secCfg.ownIeee = STACK_OWN_IEEE;

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "and the same struct, with the config corrected, builds: the refusal left nothing that a second init trips over");
    Test_Expect(dev.stack.running == 1, "so it is running");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectHex("with the PIB mirror the corrected config named, so the second apply wrote every field the first never reached",
                   pib->extendedAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);
    Test_ExpectCount((uint32_t)Zb_LayersMac(&dev.stack)->tx.dsn, STACK_DSN_START,
                     "and the DSN seed applied rather than accumulated across the two attempts");

    LoopbackRadio_SetLost(&dev.model, 1);

    Test_ExpectStatus(stackInit(&dev), ZB_ERR_NOT_READY,
                      "a backend that is not there is a refusal from the apply itself, the one class validate-first cannot catch");
    Test_Expect(dev.stack.running == 0, "with the façade not running");
    Test_Expect(stackIsZero(&dev.stack),
                "and nothing of the stack that was running a moment ago left behind: the half-applied struct is cleared too");

    LoopbackRadio_SetLost(&dev.model, 0);

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "so a backend that answers again builds the same struct a third time");

    pib = Mac_Pib(&dev.stack.mac);

    Test_ExpectCount(pib->panId, STACK_PAN_ID, "with the PIB written from the config again");
    Test_Expect(Zb_LayersSecurity(&dev.stack)->ownIeee == STACK_OWN_IEEE,
                "and the security module holding the identity the config carries");
}
