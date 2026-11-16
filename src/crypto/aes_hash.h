#ifndef AES_HASH_H
#define AES_HASH_H

/*
 * The hash band: R23.1 Annex B.4's Matyas-Meyer-Oseas hash over the AES-128 of aes.h, which B.1.3
 * chooses as the specification's own hash, and Annex B.1.4's keyed hash, FIPS-198's HMAC over it with
 * a 16-octet block. 4.5.3's key-transport and key-load keys are the second taken over a one-octet
 * input, so they are a use of this band rather than part of it.
 */

#include <stdint.h>
#include "zb_status.h"

/* Hash0 is all zero and Hashj = E(Hashj-1, Mj) XOR Mj over the padded message (Annex B.4 (3)), 16
   octets out for any input shorter than the bound B.4 prints. ZB_OK, or ZB_ERR_BAD_ARGUMENT for a 0
   pointer or an input at or above that bound. */
ZbStatus Aes_MmoHash(const uint8_t *in, uint32_t inLen, uint8_t out[16]);

/* FIPS-198 HMAC over that hash with B = 16 and HMAClen = 16 (Annex B.1.4): a key longer than the block
   is hashed down to the block first, as C.6.2 prints. ZB_OK, or ZB_ERR_BAD_ARGUMENT for a 0 pointer, a
   0 key length, or an input at or above the bound above. */
ZbStatus Aes_MmoHmac(const uint8_t *key, uint32_t keyLen, const uint8_t *in, uint32_t inLen, uint8_t out[16]);

#endif /* AES_HASH_H */
