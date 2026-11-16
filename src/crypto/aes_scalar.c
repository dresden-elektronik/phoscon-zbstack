#include "aes.h"

/*
 * The reference implementation of the AES-128 seam: FIPS-197 direct, the state a
 * sixteen-octet byte array, and no tables beyond the S-box and Rcon. It is what the build
 * links when ZB_AES_IMPLEMENTATION is scalar, and the measure another implementation of
 * the same contract is checked against.
 */

/* The S-box (FIPS-197). */
static const unsigned char s_box[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Rcon: the xtime chain mod 0x11b, ten values for Nr = 10. FIPS-197 writes Rcon[i / 4]
   1-based; this table is 0-based, so the schedule indexes it at i / 4 - 1. */
static const uint8_t rcon[10] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* FIPS-197's counts for a 128-bit key: Nr rounds, 44 schedule words, 176 round-key octets. */
enum
{
    AES_NR = 10,
    AES_KEY_WORDS = 44,
    AES_BLOCK_OCTETS = 16,
    AES_ROUND_KEY_OCTETS = 176
};

/* Multiplication in GF(2^8) mod 0x11b (FIPS-197 §4.2): double-and-xor, bit by bit. */
static uint8_t aesDoGmul(uint8_t a, uint8_t b)
{
    uint8_t product = 0;
    uint32_t bit;

    for (bit = 0; bit < 8; bit++)
    {
        if ((b & 1) != 0)
            product = (uint8_t)(product ^ a);

        if ((a & 0x80) != 0)
            a = (uint8_t)((a << 1) ^ 0x1b);
        else
            a = (uint8_t)(a << 1);

        b = (uint8_t)(b >> 1);
    }

    return product;
}

/* SubWord (FIPS-197 §5.1): the S-box on the four octets of a word, in place. */
static void aesDoSubWord(uint8_t word[4])
{
    word[0] = s_box[word[0]];
    word[1] = s_box[word[1]];
    word[2] = s_box[word[2]];
    word[3] = s_box[word[3]];
}

static void aesDoSubBytes(uint8_t state[4][4])
{
    uint32_t row;

    for (row = 0; row < 4; row++)
        aesDoSubWord(state[row]);
}

/* ShiftRows (FIPS-197 §5.1.1.2): row r moves left r positions, cyclically. */
static void aesDoShiftRows(uint8_t state[4][4])
{
    uint8_t shifted[4][4];
    uint32_t row;
    uint32_t col;

    for (row = 0; row < 4; row++)
        for (col = 0; col < 4; col++)
            shifted[row][col] = state[row][(col + row) % 4];

    for (row = 0; row < 4; row++)
        for (col = 0; col < 4; col++)
            state[row][col] = shifted[row][col];
}

/* MixColumns (FIPS-197 §5.1.1.4): each column times the fixed polynomial, in GF(2^8). */
static void aesDoMixColumns(uint8_t state[4][4])
{
    uint8_t mixed[4][4];
    uint32_t row;
    uint32_t col;

    for (col = 0; col < 4; col++)
        for (row = 0; row < 4; row++)
            mixed[row][col] = (uint8_t)(aesDoGmul(state[row][col], 2)
                ^ aesDoGmul(state[(row + 1) % 4][col], 3)
                ^ state[(row + 2) % 4][col]
                ^ state[(row + 3) % 4][col]);

    for (row = 0; row < 4; row++)
        for (col = 0; col < 4; col++)
            state[row][col] = mixed[row][col];
}

static void aesDoAddRoundKey(uint8_t state[4][4], const uint8_t *roundKey)
{
    uint32_t col;
    uint32_t row;

    for (col = 0; col < 4; col++)
        for (row = 0; row < 4; row++)
            state[row][col] = (uint8_t)(state[row][col] ^ roundKey[4 * col + row]);
}

ZbStatus Aes_KeySchedule(Aes_Key *key, const uint8_t key16[16])
{
    uint8_t word[AES_KEY_WORDS][4];
    uint8_t temp[4];
    uint8_t first;
    uint32_t i;
    uint32_t j;

    if (!key || !key16)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            word[i][j] = key16[4 * i + j];

    for (i = 4; i < AES_KEY_WORDS; i++)
    {
        temp[0] = word[i - 1][0];
        temp[1] = word[i - 1][1];
        temp[2] = word[i - 1][2];
        temp[3] = word[i - 1][3];

        if (i % 4 == 0)
        {
            first = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = first;

            aesDoSubWord(temp);
            temp[0] = (uint8_t)(temp[0] ^ rcon[i / 4 - 1]);
        }

        word[i][0] = (uint8_t)(word[i - 4][0] ^ temp[0]);
        word[i][1] = (uint8_t)(word[i - 4][1] ^ temp[1]);
        word[i][2] = (uint8_t)(word[i - 4][2] ^ temp[2]);
        word[i][3] = (uint8_t)(word[i - 4][3] ^ temp[3]);
    }

    for (j = 0; j < AES_BLOCK_OCTETS; j++)
        key->key[j] = key16[j];

    for (i = 0; i < AES_KEY_WORDS; i++)
        for (j = 0; j < 4; j++)
            key->roundKey[4 * i + j] = word[i][j];

    return ZB_OK;
}

void Aes_KeyWipe(Aes_Key *key)
{
    uint32_t i;

    if (!key)
        return;

    for (i = 0; i < AES_BLOCK_OCTETS; i++)
        key->key[i] = 0;

    for (i = 0; i < AES_ROUND_KEY_OCTETS; i++)
        key->roundKey[i] = 0;
}

void Aes_EncryptBlock(const Aes_Key *key, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[4][4];
    uint32_t round;
    uint32_t col;
    uint32_t row;

    for (col = 0; col < 4; col++)
        for (row = 0; row < 4; row++)
            state[row][col] = in[4 * col + row];

    aesDoAddRoundKey(state, key->roundKey);

    for (round = 1; round <= AES_NR; round++)
    {
        aesDoSubBytes(state);
        aesDoShiftRows(state);

        if (round != AES_NR)
            aesDoMixColumns(state);

        aesDoAddRoundKey(state, key->roundKey + AES_BLOCK_OCTETS * round);
    }

    for (col = 0; col < 4; col++)
        for (row = 0; row < 4; row++)
            out[4 * col + row] = state[row][col];
}
