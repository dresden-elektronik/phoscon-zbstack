/* The `stack` suite's state half: the two calls that carry a built façade through `zb_state`, and the guards
   both of them answer with. See `layers_cases.h` for the case list and `layers_helpers.h` for the machinery. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "zb_utils.h"

/* A state object filled with something that is not a state, which is what a refused capture has to leave as
   it found it. */
#define STACK_STATE_FAULT 0xa5

void caseCaptureRestore(void)
{
    StackDevice dev;
    Zb_State state;
    Security *security;

    stackDevice(&dev);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "case 19: a built stack is what Zb_LayersCapture takes, and one call reaches the four modules it composes");

    Zb_memset(&state, 0, (uint32_t)sizeof state);

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 1, &state), ZB_OK, "the object the call fills");
    Test_ExpectCount(state.version, ZB_STATE_VERSION, "names the schema it was made by");
    Test_Expect(state.ownIeee == STACK_OWN_IEEE, "and this device's extended address");
    Test_Expect(state.nwkSecurityLevel == SECURITY_LEVEL_ENC_MIC_32
                && state.nwkActiveKeySeqNumber == STACK_KEY_SEQ,
                "the level and the active key sequence number the module runs with");
    Test_Expect(state.authenticated == 1 && state.nwkAllFresh == 1, "and the two joined flags as configured");
    Test_ExpectCount(state.keyCount, 1, "one descriptor, which is the whole of this device's material set");
    Test_ExpectCount(state.keys[0].keyPresent, 1,
                     "includeKeys 1 travels: the descriptor carries its key in the object");
    Test_ExpectOctets("and the key it carries is the one the application configured",
                      state.keys[0].key, SECURITY_KEY_OCTETS, dev.key.key, SECURITY_KEY_OCTETS);
    Test_ExpectCount(state.pairCount, 0, "no key pair, because this device seeds none");
    Test_ExpectCount(state.nwkSequenceNumber, STACK_SEQ_START, "nwkSequenceNumber is the seed the config named");
    Test_ExpectCount(state.macDsn, STACK_DSN_START, "and the MAC's DSN its own");
    Test_ExpectCount(state.apsCounter, 0, "and no APS transaction has been made");

    Test_ExpectStatus(Zb_LayersRestore(&dev.stack, &state), ZB_OK,
                      "and that object restores into the stack it came from");
    Test_Expect(dev.stack.running == 1,
                "the façade is still running after the restore: the call writes the state object's counters and the security module, not the façade's own flag");

    security = Zb_LayersSecurity(&dev.stack);

    Test_Expect(security->ownIeee == STACK_OWN_IEEE
                && security->nwkSecurityLevel == SECURITY_LEVEL_ENC_MIC_32
                && security->nwkActiveKeySeqNumber == STACK_KEY_SEQ,
                "the restored module names the identity and the level the object carried");
    Test_Expect(security->authenticated == 1 && security->nwkAllFresh == 1, "and the two flags with them");
    Test_Expect(Security_IsEnabled(security) == 1, "so it protects with the key it was handed");
    Test_Expect(security->keys[0].inUse == 1, "and the descriptor is in the material set");
    Test_ExpectOctets("under the key the object carried, octet for octet",
                      security->keys[0].key, SECURITY_KEY_OCTETS, dev.key.key, SECURITY_KEY_OCTETS);
    Test_ExpectCount(security->keys[0].outgoingFrameCounter, ZB_STATE_COUNTER_BANK,
                     "whose outgoing counter lands the bank past the larger of the stored value and this boot's, which is the restore rule and not a capture's");

    Test_ExpectCount(Zb_LayersNwk(&dev.stack)->seq, STACK_SEQ_START + ZB_STATE_OCTET_STEP,
                     "the NWK sequence number moved one octet step (3.3.1.5)");
    Test_ExpectCount(Zb_LayersMac(&dev.stack)->tx.dsn, STACK_DSN_START + ZB_STATE_OCTET_STEP,
                     "and the MAC's DSN its one");
    Test_ExpectCount(Zb_LayersAps(&dev.stack)->apsCounter, ZB_STATE_OCTET_STEP, "and the APS counter its one");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 100), ZB_OK,
                      "and one turn of the layers still answers ZB_OK: a restore leaves the façade a stack, not a struct that has to be built again");
}

void caseCaptureRestoreGuards(void)
{
    StackDevice dev;
    Zb_Layers unbuilt;
    Zb_State state;
    Zb_State before;

    stackDevice(&dev);
    Zb_memset(&unbuilt, 0, (uint32_t)sizeof unbuilt);

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "a device for the guards to be refused against");

    Zb_memset(&state, STACK_STATE_FAULT, (uint32_t)sizeof state);
    before = state;

    Test_ExpectStatus(Zb_LayersCapture(0, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "case 20: a null façade is refused before any of the four modules is read");
    Test_ExpectStatus(Zb_LayersCapture(&unbuilt, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a stack that was never built, which is the running flag and not a field of the object");
    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, 0), ZB_ERR_BAD_ARGUMENT, "and a built stack with no object to fill");
    Test_Expect(Zb_memcmp(&state, &before, (uint32_t)sizeof state) == 0,
                "not one of the three wrote a byte into the caller's object, so a refused capture is not a partial one");

    Test_ExpectStatus(Zb_LayersRestore(0, &state), ZB_ERR_BAD_ARGUMENT, "the restore refuses a null façade the same way");
    Test_ExpectStatus(Zb_LayersRestore(&unbuilt, &state), ZB_ERR_BAD_ARGUMENT, "and a stack that was never built");
    Test_ExpectStatus(Zb_LayersRestore(&dev.stack, 0), ZB_ERR_BAD_ARGUMENT, "and a built stack with no state to restore");

    Test_Expect(stackIsZero(&unbuilt), "the unbuilt façade is still zero bytes after both refusals against it");
    Test_Expect(dev.stack.running == 1, "and the built one is still running");
    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, &state), ZB_OK,
                      "so the guards left it a stack a capture can still read");
}
