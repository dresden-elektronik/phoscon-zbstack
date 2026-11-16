/* Suite for the two hash constructions R23.1 Annex B instantiates over AES-128: B.4's
 * Matyas-Meyer-Oseas hash (chosen by B.1.3) and B.1.4's keyed hash, FIPS-198's HMAC over it with a
 * 16-octet block. Every known answer here is a vector the specification's own Annex C prints, quoted
 * the way the annex prints it, including the two padding methods C.5.3 and C.5.4 sit either side of
 * and the 32-octet key C.6.2 hashes down before using (docs/internals/refs.md). */

#include "aes.h"
#include "aes_hash.h"
#include "test_harness.h"
#include "zb_utils.h"

/* C.5.1: one octet, the short padding, the single block the annex prints with it. */
static void aesDoMmoOneOctetCheck(void)
{
    static const char *msgHex = "c0";
    static const char *wantedHex = "ae3a102a28d43ee0d4a09e22788b206c";
    uint8_t msg[1];
    uint8_t got[16];
    uint8_t wanted[16];

    Test_Expect(Test_ParseHex(msgHex, msg, sizeof msg) == 1, "the C.5.1 message is one octet");
    Test_Expect(Test_ParseHex(wantedHex, wanted, sizeof wanted) == 16, "the digest the annex prints is sixteen octets");

    Test_ExpectStatus(Aes_MmoHash(msg, (uint32_t)sizeof msg, got), ZB_OK, "one octet hashes");
    Test_ExpectOctets("and the digest is C.5.1's", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);
}

/* C.5.2: sixteen octets, which is a whole block of message and a second block of padding: the
   length never rides in the block the message happened to fill. */
static void aesDoMmoOneBlockCheck(void)
{
    static const char *msgHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
    static const char *wantedHex = "a7977e88bc0b61e8210827109a228f2d";
    uint8_t msg[16];
    uint8_t got[16];
    uint8_t wanted[16];
    uint32_t i;

    Test_Expect(Test_ParseHex(msgHex, msg, sizeof msg) == 16, "the C.5.2 message is a whole block");
    Test_Expect(Test_ParseHex(wantedHex, wanted, sizeof wanted) == 16, "and its published digest");

    Test_ExpectStatus(Aes_MmoHash(msg, (uint32_t)sizeof msg, got), ZB_OK, "a message of exactly one block hashes");
    Test_ExpectOctets("with the digest C.5.2 prints", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    /* The running key: Hash0 is all zero and every later key is the previous digest (B.4 (3)), so a
       message whose first block is zero is not the same hash as the empty one. */
    for (i = 0; i < 16; i++)
        msg[i] = 0;

    Test_ExpectStatus(Aes_MmoHash(msg, 16, got), ZB_OK, "a block of zeros hashes");
    Test_Expect(got[0] != 0 || got[1] != 0, "and the digest is not the all-zero key it started from");
}

/* C.5.3 (8191 octets) and C.5.4 (8192 octets) either side of the threshold B.4's two paddings turn
   on: 8191 takes the 16-bit length, 8192 the 32-bit one with the extra n bits of zeros. Both
   messages are the same 0,1,2,... sequence the annex writes out. */
static void aesDoMmoPaddingThresholdCheck(void)
{
    static const char *shortHex = "24ec2fe75bbffcb34789bc0610e7f165";
    static const char *longHex = "dc6b0687f09f8607131c170b3bd31591";
    static uint8_t msg[8192];
    uint8_t got[16];
    uint8_t wanted[16];
    uint32_t i;

    for (i = 0; i < 8192; i++)
        msg[i] = (uint8_t)(i & 0xff);

    Test_Expect(Test_ParseHex(shortHex, wanted, sizeof wanted) == 16, "the 8191-octet digest is sixteen octets");
    Test_ExpectStatus(Aes_MmoHash(msg, 8191, got), ZB_OK, "the last message that takes the short padding hashes");
    Test_ExpectOctets("with C.5.3's digest", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    Test_Expect(Test_ParseHex(longHex, wanted, sizeof wanted) == 16, "the 8192-octet digest is sixteen octets too");
    Test_ExpectStatus(Aes_MmoHash(msg, 8192, got), ZB_OK, "and the first message that does not hashes under the other padding");
    Test_ExpectOctets("which is C.5.4's digest, over a message that differs from the one above by one octet",
                      got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);
}

/* C.5.6: 8202 octets, where the padding run plus the length fills a whole block and the tail is two
   blocks wide. Its last block is printed as eleven zeros, the 32-bit length and two more zeros, which
   is the shape that only a two-block tail can make. */
static void aesDoMmoTwoBlockTailCheck(void)
{
    static const char *wantedHex = "bc9828d59b2aa323daf20be5f2e66511";
    static uint8_t msg[8202];
    uint8_t got[16];
    uint8_t wanted[16];
    uint32_t i;

    for (i = 0; i < 8202; i++)
        msg[i] = (uint8_t)(i & 0xff);

    Test_Expect(Test_ParseHex(wantedHex, wanted, sizeof wanted) == 16, "the C.5.6 digest is sixteen octets");
    Test_ExpectStatus(Aes_MmoHash(msg, (uint32_t)sizeof msg, got), ZB_OK, "a message whose tail needs two blocks hashes");
    Test_ExpectOctets("with the digest C.5.6 prints", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);
}

/* C.6.1: a 16-octet key and a one-octet message, the inner and outer pads the annex prints in full. */
static void aesDoKeyedHashCheck(void)
{
    static const char *keyHex = "404142434445464748494a4b4c4d4e4f";
    static const char *msgHex = "c0";
    static const char *wantedHex = "4512807bf94cb3400f0e2c25fb76e999";
    uint8_t key[16];
    uint8_t msg[1];
    uint8_t got[16];
    uint8_t wanted[16];

    Test_Expect(Test_ParseHex(keyHex, key, sizeof key) == 16, "the C.6.1 key is one block");
    Test_Expect(Test_ParseHex(msgHex, msg, sizeof msg) == 1, "and its message is one octet");
    Test_Expect(Test_ParseHex(wantedHex, wanted, sizeof wanted) == 16, "with the digest the annex prints");

    Test_ExpectStatus(Aes_MmoHmac(key, (uint32_t)sizeof key, msg, (uint32_t)sizeof msg, got), ZB_OK,
                      "the keyed hash of one octet under a one-block key");
    Test_ExpectOctets("is C.6.1's HMAC", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    Test_ExpectOctets("and it is not the plain hash of the same octet, which C.5.1 printed",
                      got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);
}

/* C.6.2: a 32-octet key. B.1.4's HMAC hashes a key longer than the block down to the block first,
   and the annex prints both steps: Key0 = H(key) = 22f40cbe... and the HMAC over C.5.2's message. */
static void aesDoKeyedHashLongKeyCheck(void)
{
    static const char *keyHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    static const char *keyHashHex = "22f40cbe1566accfeb7777e1c4a9bb43";
    static const char *msgHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
    static const char *wantedHex = "a3b0079984bf1557f74a0d6387e0a11a";
    uint8_t key[32];
    uint8_t msg[16];
    uint8_t got[16];
    uint8_t wanted[16];

    Test_Expect(Test_ParseHex(keyHex, key, sizeof key) == 32, "the C.6.2 key is two blocks");
    Test_Expect(Test_ParseHex(msgHex, msg, sizeof msg) == 16, "its message one block");
    Test_Expect(Test_ParseHex(keyHashHex, wanted, sizeof wanted) == 16, "and its hashed-down key is what C.6.2 prints");

    Test_ExpectStatus(Aes_MmoHash(key, (uint32_t)sizeof key, got), ZB_OK, "the key alone hashes");
    Test_ExpectOctets("to the Key0 the annex names", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    Test_Expect(Test_ParseHex(wantedHex, wanted, sizeof wanted) == 16, "the published HMAC is sixteen octets");
    Test_ExpectStatus(Aes_MmoHmac(key, (uint32_t)sizeof key, msg, (uint32_t)sizeof msg, got), ZB_OK,
                      "and the keyed hash over a two-block key");
    Test_ExpectOctets("is C.6.2's HMAC", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);
}

/* 4.5.3's two derivatives are this keyed hash over one octet: 0x00 feeds the key-transport key that
   protects a transported network key, 0x02 the key-load key that protects a transported link key.
   The octets below are what this construction yields under the global Trust Center link key
   4.2.1.2.1 prints (5A..39), quoted as a cross-check against what other stacks derive from the same
   key rather than as a vector the standard itself prints. */
static void aesDoKeyDerivationCheck(void)
{
    static const char *tcKeyHex = "5a6967426565416c6c69616e63653039";
    static const char *transportHex = "4bab0f173e1434a2d572e1c1ef478782";
    static const char *loadHex = "c5a47035c332ccbf251571d8baded188";
    uint8_t key[16];
    uint8_t got[16];
    uint8_t wanted[16];
    uint8_t one;

    Test_Expect(Test_ParseHex(tcKeyHex, key, sizeof key) == 16, "the global Trust Center link key is sixteen octets");

    one = 0x00;
    Test_ExpectStatus(Aes_MmoHmac(key, (uint32_t)sizeof key, &one, 1, got), ZB_OK, "the key-transport key is the keyed hash of 0x00");
    Test_Expect(Test_ParseHex(transportHex, wanted, sizeof wanted) == 16, "and its published value is sixteen octets");
    Test_ExpectOctets("under the global link key it matches what the upstream stacks derive",
                      got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    one = 0x02;
    Test_ExpectStatus(Aes_MmoHmac(key, (uint32_t)sizeof key, &one, 1, got), ZB_OK, "the key-load key is the keyed hash of 0x02");
    Test_Expect(Test_ParseHex(loadHex, wanted, sizeof wanted) == 16, "again sixteen octets");
    Test_ExpectOctets("and again it matches", got, (uint32_t)sizeof got, wanted, (uint32_t)sizeof wanted);

    one = 0x01;
    Test_Expect(Aes_MmoHmac(key, (uint32_t)sizeof key, &one, 1, got) == ZB_OK
                && (got[0] != wanted[0] || got[15] != wanted[15]),
                "and a third one-octet input is a third key: the octet hashed is what distinguishes them");
}

/* What the two functions refuse: a 0 pointer, a 0-length key, and an input at the length B.4 says it
   does not hash. */
static void aesDoHashArgumentCheck(void)
{
    uint8_t key[16];
    uint8_t msg[16];
    uint8_t out[16];

    Zb_memset(key, 0x00, (uint32_t)sizeof key);
    Zb_memset(msg, 0x00, (uint32_t)sizeof msg);

    Test_ExpectStatus(Aes_MmoHash(0, 16, out), ZB_ERR_BAD_ARGUMENT, "a missing message is refused");
    Test_ExpectStatus(Aes_MmoHash(msg, 16, 0), ZB_ERR_BAD_ARGUMENT, "and a missing output");
    Test_ExpectStatus(Aes_MmoHash(msg, 536870912, out), ZB_ERR_BAD_ARGUMENT,
                      "and an input at the bound B.4 prints for bit strings shorter than 2^(2n)");

    Test_ExpectStatus(Aes_MmoHash(msg, 0, out), ZB_OK, "an empty message is a message: B.4 allows l = 0");

    Test_ExpectStatus(Aes_MmoHmac(0, 16, msg, 16, out), ZB_ERR_BAD_ARGUMENT, "the keyed hash refuses a missing key");

    Test_ExpectStatus(Aes_MmoHmac(key, 0, msg, 16, out), ZB_ERR_BAD_ARGUMENT,
                      "a key of no length, because B.1.4's HMAC is keyed");
    Test_ExpectStatus(Aes_MmoHmac(key, 16, 0, 16, out), ZB_ERR_BAD_ARGUMENT, "and a missing message");
    Test_ExpectStatus(Aes_MmoHmac(key, 16, msg, 536870912 - 16, out), ZB_ERR_BAD_ARGUMENT,
                      "and a message that is inside B.4's bound alone but not once the inner pad is in front of it, the inner hash being of 16 + l octets");
}

int main(void)
{
    Test_Begin("crypto_hash");

    aesDoMmoOneOctetCheck();
    aesDoMmoOneBlockCheck();
    aesDoMmoPaddingThresholdCheck();
    aesDoMmoTwoBlockTailCheck();
    aesDoKeyedHashCheck();
    aesDoKeyedHashLongKeyCheck();
    aesDoKeyDerivationCheck();
    aesDoHashArgumentCheck();

    return Test_Report();
}
