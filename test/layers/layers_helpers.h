/* The `stack` suite's shared machinery.

   What more than one case needs: the device the façade is built on (the
   hardware-free backend, the config an application would name, and the security
   config it hands over) plus the byte image a refused init is judged against.

   The identity is this suite's own: one extended address on the air and in the CCM* nonce, the PAN, the short
   address and channel 26, the channel every band-A rig in this tree arms so nothing composed here could be
   taken for measured traffic if the model were an RCP (docs/internals/hardware.md §7). */

#ifndef STACK_HELPERS_H
#define STACK_HELPERS_H

#include <stdint.h>

#include "loopback_radio.h"
#include "security.h"
#include "test_harness.h"
#include "zb_layers.h"

/* This device's extended address, and one that is not: the mismatch a refused init is built from. */
#define STACK_OWN_IEEE 0x0123456789abcdef
#define STACK_OTHER_IEEE 0x0011223344556676

/* The same address as the octets the PIB carries and the frame field travels in: least significant octet
   first (7.2.1.4, 802.15.4-2006 6.3). */
#define STACK_OWN_IEEE_HEX "efcdab8967452301"

/* The identity this device's PIB names: PAN, short address, channel, and the extended PAN ID carried and read
   by nothing yet. */
#define STACK_PAN_ID 0x1a2b
#define STACK_SHORT_ADDRESS 0x0042
#define STACK_CHANNEL 26
#define STACK_EXTENDED_PAN_HEX "0f0e0d0c0b0a0908"

/* The three seeds the application supplies: the NWK sequence number, the MAC DSN and no relay jitter. */
#define STACK_SEQ_START 0x11
#define STACK_DSN_START 0x21

/* The key this device holds at sequence number 0x00: one descriptor, which is the whole of the material set a
   stack at a level that protects frames needs. */
#define STACK_KEY_SEQ 0x00

/* A device as this suite builds it: the model backend, the façade over it, and the two configs the application
   owns, caller-owned storage on the case's stack (§4.3). */
typedef struct StackDevice
{
    Loopback_Radio model;
    Zb_Layers stack;
    Security_KeyDescriptor key;
    Security_Config secCfg;
    Zb_LayersConfig cfg;
} StackDevice;

/* The device a case starts from: a coordinator on channel 26 at level 0x05 holding one key descriptor, with
   every identity field named and this device's extended address in both places it appears. Nothing is
   initialised yet: the case calls `stackInit` and asserts what it answers, so a case that builds a refused
   config edits this one. */
void stackDevice(StackDevice *dev);

/* The same device without a security module: level 0 and no key material, which is the scaffold. */
void stackDevicePlain(StackDevice *dev);

/* The model backend alone, brought up the way the band-A rig brings it up. */
void stackModelAt(Loopback_Radio *model);

/* The factory address the device reports, scripted through the model's own call because no write above the
   seam reaches it: it stands where an RCP's silicon does, and an application does not own it. Zero is a part
   that has none, which the model then reports as absent. */
void stackDeviceFactory(Loopback_Radio *model, uint64_t ieee);

/* One Table 4-3 descriptor at `keySeq`, with key octets this suite names. */
void stackKeyAt(Security_KeyDescriptor *key, uint8_t keySeq);

/* One init of the device already described by `dev->cfg`, over the seam of `dev->model`. */
ZbStatus stackInit(StackDevice *dev);

/* Whether the façade is still all zero bytes: a refusal is a claim about the whole struct (four embedded
   modules, the identity copy and the running flag) and not about the fields a case thought to name. */
int stackIsZero(const Zb_Layers *stack);

/* Whether a run of octets is all zero, for the output a null stack's getter answers. */
int stackIsZeroOctets(const uint8_t *octets, uint32_t len);

/* A 64-bit address as the eight octets the PIB carries, for a comparison against what a build wrote. */
void stackExtendedOctets(uint64_t value, uint8_t *out);

#endif /* STACK_HELPERS_H */
