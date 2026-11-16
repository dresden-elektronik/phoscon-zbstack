#include "aes.h"
#include "aes_hash.h"

/*
 * The two hash constructions R23.1 Annex B instantiates over the AES-128 this band already
 * provides: B.4's Matyas-Meyer-Oseas hash, which B.1.3 chooses as the specification's hash, and
 * B.1.4's keyed hash, which is FIPS-198's HMAC over it with a 16-octet block.
 *
 * Both live here rather than in the layer that uses them because 4.5.3's key-transport and
 * key-load keys are that keyed hash over a one-octet input: the derivation is a use of a
 * primitive, and the primitive is this band's.
 */

enum
{
    AES_HASH_BLOCK_OCTETS = 16,      /* n: B.1.1 makes the block and the key the same size, which is what lets MMO use its own digest as a key */
    AES_HASH_SHORT_MAX_OCTETS = 8192,  /* the "2^16 bit string" B.4's two paddings turn on: C.5.3 short-pads 8191 octets, C.5.4 long-pads 8192 */
    AES_HASH_INPUT_MAX_OCTETS = 536870912, /* B.4 (13322, 13350): the hash is defined for bit strings shorter than 2^(2n) bits, n being 16 */
    AES_HASH_SHORT_PAD_OCTETS = 14,  /* B.4 step 1 a: l + 1 + k == 7n (mod 8n), so the message plus its padding run ends 14 octets into a block, leaving two for the length */
    AES_HASH_LONG_PAD_OCTETS = 10,   /* B.4 step 2 a: l + 1 + k == 5n (mod 8n), the same rule for the longer form */
    AES_HASH_SHORT_LEN_OCTETS = 2,   /* B.4 step 1 b: the n-bit binary representation of l */
    AES_HASH_LONG_LEN_OCTETS = 4,    /* B.4 step 2 b: its 2n-bit representation */
    AES_HASH_LONG_TAIL_OCTETS = 2,   /* B.4 step 2 b: and the n bits of zeros right-concatenated after it */
    AES_HASH_IPAD_OCTET = 0x36,      /* B.1.4's HMAC, FIPS-198 with B = 16: the pads C.6.1 prints across the whole block */
    AES_HASH_OPAD_OCTET = 0x5c,
    AES_HASH_MARK_BIT = 0x80         /* B.4's "the binary consisting of the bit '1' followed by k '0' bits", seen as one octet */
};

/* The streaming state: the digest so far, up to 15 octets of a last block not yet compressed, and
   the length of the whole input, which the padding is written from (B.4 pads the message, not the
   block it happens to end in). */
typedef struct AesHash_Mmo
{
    uint8_t digest[AES_HASH_BLOCK_OCTETS];
    uint8_t held[AES_HASH_BLOCK_OCTETS];
    uint32_t heldLen;
    uint32_t totalOctets;
} AesHash_Mmo;

/* Hash0 is the all-zero digest and Hashj = E(Hashj-1, Mj) XOR Mj (B.4 (3)): the digest the previous
   block produced is the key this block is encrypted with, and the plaintext of this block is what
   the ciphertext is folded with. */
static void aesHashDoCompress(AesHash_Mmo *self, const uint8_t block[16])
{
    uint8_t cipher[AES_HASH_BLOCK_OCTETS];
    Aes_Key key;
    uint32_t i;

    Aes_KeySchedule(&key, self->digest);
    Aes_EncryptBlock(&key, block, cipher);

    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
        self->digest[i] = (uint8_t)(cipher[i] ^ block[i]);

    Aes_KeyWipe(&key);
}

static void aesHashDoStart(AesHash_Mmo *self)
{
    uint32_t i;

    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
    {
        self->digest[i] = 0;
        self->held[i] = 0;
    }

    self->heldLen = 0;
    self->totalOctets = 0;
}

/* Whole blocks out of the caller's buffer, the remainder held: which octets are whole is not known
   until the message ends, because how much padding follows depends on the message's total length. */
static void aesHashDoFeed(AesHash_Mmo *self, const uint8_t *in, uint32_t inLen)
{
    uint32_t used = 0;
    uint32_t take;

    while (used < inLen)
    {
        take = AES_HASH_BLOCK_OCTETS - self->heldLen;

        if (take > inLen - used)
            take = inLen - used;

        for (; take != 0; take--)
        {
            self->held[self->heldLen] = in[used];
            self->heldLen++;
            used++;
            self->totalOctets++;
        }

        if (self->heldLen == AES_HASH_BLOCK_OCTETS)
        {
            aesHashDoCompress(self, self->held);
            self->heldLen = 0;
        }
    }
}

/* The octet at a position past the message's last held octet: B.4's one bit, the zeros it solves,
   then the length, and in the long form the n zero bits step 2 b appends after that. */
static uint8_t aesHashDoPadOctet(uint32_t offset, uint32_t padLen, uint32_t lenOctets, uint32_t bitLen)
{
    uint32_t index;

    if (offset == 0)
        return AES_HASH_MARK_BIT;

    if (offset < padLen)
        return 0;


    if (offset < padLen + lenOctets)
    {
        index = offset - padLen;
        return (uint8_t)(bitLen >> (8 * (lenOctets - 1 - index)));
    }

    return 0;
}

/* B.4's two paddings, one of them chosen by the message's bit length, appended as one or two blocks. */
static void aesHashDoFinish(AesHash_Mmo *self, uint8_t out[16])
{
    uint8_t block[AES_HASH_BLOCK_OCTETS];
    uint32_t bitLen = self->totalOctets * 8;
    uint32_t padLen;
    uint32_t lenOctets;
    uint32_t tail;
    uint32_t shortBits = (uint32_t)AES_HASH_SHORT_MAX_OCTETS * 8;
    uint32_t i;

    /* C.5.3 ends the short form at 8191 octets and C.5.4 opens the long form at 8192, which is the
       "2^16 bit string" threshold B.4's two cases turn on */
    int longForm = (bitLen >= shortBits) ? 1 : 0;

    /* After the padding run the message must sit 14 octets into a block for the 16-bit length
       (B.4 step 1 a: l + 1 + k == 7n mod 8n) or 10 for the 32-bit one plus two zero octets
       (step 2 a: l + 1 + k == 5n mod 8n). */
    padLen = 1;

    while (((self->totalOctets + padLen) % AES_HASH_BLOCK_OCTETS) !=
            (uint32_t)(longForm ? AES_HASH_LONG_PAD_OCTETS : AES_HASH_SHORT_PAD_OCTETS))
        padLen++;

    lenOctets = (uint32_t)(longForm ? AES_HASH_LONG_LEN_OCTETS : AES_HASH_SHORT_LEN_OCTETS);
    tail = self->heldLen + padLen + lenOctets + (uint32_t)(longForm ? AES_HASH_LONG_TAIL_OCTETS : 0);

    for (i = 0; i < tail; i += AES_HASH_BLOCK_OCTETS)
    {
        uint32_t j;

        for (j = 0; j < AES_HASH_BLOCK_OCTETS; j++)
        {
            if (i + j < self->heldLen)
                block[j] = self->held[i + j];
            else
                block[j] = aesHashDoPadOctet(i + j - self->heldLen, padLen, lenOctets, bitLen);
        }

        aesHashDoCompress(self, block);
    }

    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
        out[i] = self->digest[i];
}

/* The hash B.1.3 names (Annex B.4): 16 octets out for any input shorter than the bound B.4 prints
   at 13322 and 13350, "less than 2^(2n) bits" with n = 16. */
ZbStatus Aes_MmoHash(const uint8_t *in, uint32_t inLen, uint8_t out[16])
{
    AesHash_Mmo state;

    if (in == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (inLen >= AES_HASH_INPUT_MAX_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    aesHashDoStart(&state);
    aesHashDoFeed(&state, in, inLen);
    aesHashDoFinish(&state, out);

    return ZB_OK;
}

/* The keyed hash B.1.4 names: FIPS-198's HMAC over the hash above, with the block size B the clause
   states as 16 and HMAClen the digest itself. A key longer than the block is hashed down to it, as
   C.6.2 prints, and a shorter one is zero-filled to it. */
ZbStatus Aes_MmoHmac(const uint8_t *key, uint32_t keyLen, const uint8_t *in, uint32_t inLen, uint8_t out[16])
{
    uint8_t keyBlock[AES_HASH_BLOCK_OCTETS];
    uint8_t pad[AES_HASH_BLOCK_OCTETS];
    uint8_t inner[AES_HASH_BLOCK_OCTETS];
    AesHash_Mmo state;
    uint32_t i;

    if (key == 0 || keyLen == 0 || in == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (inLen >= AES_HASH_INPUT_MAX_OCTETS - AES_HASH_BLOCK_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    if (keyLen > AES_HASH_BLOCK_OCTETS)
    {
        if (Aes_MmoHash(key, keyLen, keyBlock) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;
    }
    else
    {
        for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
            keyBlock[i] = (i < keyLen) ? key[i] : 0;
    }

    /* H(Key XOR ipad || M), then H(Key XOR opad || that), the two hashes C.6.1 walks through with
       ipad 0x36 and opad 0x5c across the whole block */
    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
        pad[i] = (uint8_t)(keyBlock[i] ^ AES_HASH_IPAD_OCTET);

    aesHashDoStart(&state);
    aesHashDoFeed(&state, pad, AES_HASH_BLOCK_OCTETS);
    aesHashDoFeed(&state, in, inLen);
    aesHashDoFinish(&state, inner);

    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
        pad[i] = (uint8_t)(keyBlock[i] ^ AES_HASH_OPAD_OCTET);

    aesHashDoStart(&state);
    aesHashDoFeed(&state, pad, AES_HASH_BLOCK_OCTETS);
    aesHashDoFeed(&state, inner, AES_HASH_BLOCK_OCTETS);
    aesHashDoFinish(&state, out);

    for (i = 0; i < AES_HASH_BLOCK_OCTETS; i++)
    {
        keyBlock[i] = 0;
        pad[i] = 0;
        inner[i] = 0;
    }

    return ZB_OK;
}
