#include "ex_config.h"

#include "port_file.h"
#include "u_sstream.h"
#include "zb_utils.h"

/* How a value is written: decimal, a 0/1 flag, hex most significant digit first, a key's octets in order, and the
   two a "-" stands in for when the entry holds none. */
enum
{
    EX_DEC,                           /* uint32_t */
    EX_DEC8,                          /* uint8_t */
    EX_FLAG,                          /* int, written 0 or 1 */
    EX_HEX16,                         /* uint16_t */
    EX_HEX64,                         /* uint64_t */
    EX_KEY,                           /* ZB_STACK_KEY_OCTETS octets */
    EX_OPT_HEX16,                     /* EX_HEX16 or "-", `present` says which */
    EX_OPT_KEY                        /* EX_KEY or "-" */
};

enum
{
    EX_FIELDS_MAX = 8,                /* the most values one entry line carries: a key pair's seven */
    EX_SCALARS_MAX = 24,
    EX_READ_CHUNK = 64
};

typedef struct ExField
{
    uint32_t kind;
    void *value;
    int *present;
} ExField;

typedef struct ExScalar
{
    const char *name;
    ExField field;
} ExScalar;

/* One kind of entry line: its name, the pool it fills, and the values entry `index` is written from. */
typedef struct ExTable
{
    const char *name;
    uint32_t max;
    uint32_t (*fields)(Ex_Config *cfg, uint32_t index, ExField *out);
    uint32_t *(*count)(Ex_Config *cfg);
} ExTable;

static ExField exField(uint32_t kind, void *value, int *present)
{
    ExField field;

    field.kind = kind;
    field.value = value;
    field.present = present;

    return field;
}

/* Every field that stands on a line of its own, in the order a save writes them. */
static uint32_t exScalars(Ex_Config *cfg, ExScalar *out)
{
    Zb_State *s = &cfg->state;
    uint32_t n = 0;

    out[n].name = "channel";            out[n++].field = exField(EX_DEC, &cfg->channel, 0);
    out[n].name = "link-key-seed";      out[n++].field = exField(EX_KEY, cfg->linkKeySeed, 0);
    out[n].name = "state-version";      out[n++].field = exField(EX_DEC, &s->version, 0);
    out[n].name = "ieee";               out[n++].field = exField(EX_HEX64, &s->ownIeee, 0);
    out[n].name = "device-type";        out[n++].field = exField(EX_DEC, &s->deviceType, 0);
    out[n].name = "trust-centre";       out[n++].field = exField(EX_HEX64, &s->trustCenterIeee, 0);
    out[n].name = "pan";                out[n++].field = exField(EX_HEX16, &s->panId, 0);
    out[n].name = "extended-pan";       out[n++].field = exField(EX_HEX64, &s->extendedPanId, 0);
    out[n].name = "network-address";    out[n++].field = exField(EX_HEX16, &s->networkAddress, 0);
    out[n].name = "update-id";          out[n++].field = exField(EX_DEC, &s->nwkUpdateId, 0);
    out[n].name = "parent-information"; out[n++].field = exField(EX_DEC, &s->parentInformation, 0);
    out[n].name = "parent";             out[n++].field = exField(EX_HEX16, &s->parentShort, 0);
    out[n].name = "parent-ieee";        out[n++].field = exField(EX_HEX64, &s->parentIeee, 0);
    out[n].name = "stack-profile";      out[n++].field = exField(EX_DEC, &s->stackProfile, 0);
    out[n].name = "security-level";     out[n++].field = exField(EX_DEC, &s->nwkSecurityLevel, 0);
    out[n].name = "active-key";         out[n++].field = exField(EX_DEC8, &s->nwkActiveKeySeqNumber, 0);
    out[n].name = "authenticated";      out[n++].field = exField(EX_FLAG, &s->authenticated, 0);
    out[n].name = "all-fresh";          out[n++].field = exField(EX_FLAG, &s->nwkAllFresh, 0);
    out[n].name = "nwk-sequence";       out[n++].field = exField(EX_DEC, &s->nwkSequenceNumber, 0);
    out[n].name = "routing-sequence";   out[n++].field = exField(EX_DEC, &s->nwkRoutingSequenceNumber, 0);
    out[n].name = "mac-dsn";            out[n++].field = exField(EX_DEC, &s->macDsn, 0);
    out[n].name = "aps-counter";        out[n++].field = exField(EX_DEC, &s->apsCounter, 0);

    return n;
}

/* key <sequence number> <outgoing counter> <key or -> */
static uint32_t exKeyAt(Ex_Config *cfg, uint32_t index, ExField *out)
{
    Zb_StateKey *key = &cfg->state.keys[index];

    out[0] = exField(EX_DEC8, &key->keySeqNumber, 0);
    out[1] = exField(EX_DEC, &key->outgoingFrameCounter, 0);
    out[2] = exField(EX_OPT_KEY, key->key, &key->keyPresent);

    return 3;
}

/* window <sender> <sequence number> <frame counter> */
static uint32_t exWindowAt(Ex_Config *cfg, uint32_t index, ExField *out)
{
    Zb_StateWindow *window = &cfg->state.windows[index];

    out[0] = exField(EX_HEX64, &window->senderIeee, 0);
    out[1] = exField(EX_DEC8, &window->keySeqNumber, 0);
    out[2] = exField(EX_DEC, &window->frameCounter, 0);

    return 3;
}

/* pair <device> <short or -> <attributes> <type> <outgoing counter> <features> <link key or -> */
static uint32_t exPairAt(Ex_Config *cfg, uint32_t index, ExField *out)
{
    Zb_StatePair *pair = &cfg->state.pairs[index];

    out[0] = exField(EX_HEX64, &pair->deviceIeee, 0);
    out[1] = exField(EX_OPT_HEX16, &pair->shortAddress, &pair->shortKnown);
    out[2] = exField(EX_DEC, &pair->keyAttributes, 0);
    out[3] = exField(EX_DEC, &pair->linkKeyType, 0);
    out[4] = exField(EX_DEC, &pair->outgoingFrameCounter, 0);
    out[5] = exField(EX_DEC8, &pair->featuresCapabilities, 0);
    out[6] = exField(EX_OPT_KEY, pair->linkKey, &pair->keyPresent);

    return 7;
}

/* child <extended address> <network address> <end device configuration> <device timeout> */
static uint32_t exChildAt(Ex_Config *cfg, uint32_t index, ExField *out)
{
    Zb_StateChild *child = &cfg->state.children[index];

    out[0] = exField(EX_HEX64, &child->extendedAddress, 0);
    out[1] = exField(EX_HEX16, &child->networkAddress, 0);
    out[2] = exField(EX_DEC, &child->endDeviceConfiguration, 0);
    out[3] = exField(EX_DEC, &child->deviceTimeout, 0);

    return 4;
}

static uint32_t *exKeyCount(Ex_Config *cfg)
{
    return &cfg->state.keyCount;
}

static uint32_t *exWindowCount(Ex_Config *cfg)
{
    return &cfg->state.windowCount;
}

static uint32_t *exPairCount(Ex_Config *cfg)
{
    return &cfg->state.pairCount;
}

static uint32_t *exChildCount(Ex_Config *cfg)
{
    return &cfg->state.childCount;
}

static const ExTable s_tables[] =
{
    { "key", SECURITY_KEY_SET_MAX, exKeyAt, exKeyCount },
    { "window", SECURITY_INCOMING_MAX, exWindowAt, exWindowCount },
    { "pair", SECURITY_KEYPAIR_MAX, exPairAt, exPairCount },
    { "child", NWK_NEIGHBOR_MAX, exChildAt, exChildCount }
};

#define EX_TABLE_COUNT ((uint32_t)(sizeof s_tables / sizeof s_tables[0]))

/* `value` as `octets` octets most significant first, which put_hex then writes in that order. */
static void exPutBig(U_SStream *ss, uint64_t value, uint32_t octets)
{
    uint8_t big[8];
    uint32_t i;

    for (i = 0; i < octets; i++)
        big[i] = (uint8_t)(value >> (8 * (octets - 1 - i)));

    U_sstream_put_hex(ss, big, octets);
}

static void exPutField(U_SStream *ss, const ExField *field)
{
    if ((field->kind == EX_OPT_HEX16 || field->kind == EX_OPT_KEY) && !*field->present)
    {
        U_sstream_put_str(ss, "-");
        return;
    }

    switch (field->kind)
    {
    case EX_DEC:
        U_sstream_put_ulonglong(ss, *(const uint32_t *)field->value);
        break;

    case EX_DEC8:
        U_sstream_put_ulonglong(ss, *(const uint8_t *)field->value);
        break;

    case EX_FLAG:
        U_sstream_put_ulonglong(ss, *(const int *)field->value != 0);
        break;

    case EX_HEX16:
    case EX_OPT_HEX16:
        exPutBig(ss, *(const uint16_t *)field->value, 2);
        break;

    case EX_HEX64:
        exPutBig(ss, *(const uint64_t *)field->value, 8);
        break;

    default:
        U_sstream_put_hex(ss, field->value, ZB_STACK_KEY_OCTETS);
        break;
    }
}

/* One line, `name` and its values, built whole before it is written. */
static int exWriteLine(PortFile *file, const char *name, const ExField *fields, uint32_t count)
{
    char line[EX_CONFIG_LINE_MAX];
    U_SStream ss;
    uint32_t written;
    uint32_t i;

    U_sstream_init(&ss, line, (unsigned)sizeof line);
    U_sstream_put_str(&ss, name);

    for (i = 0; i < count; i++)
    {
        U_sstream_put_str(&ss, " ");
        exPutField(&ss, &fields[i]);
    }

    U_sstream_put_str(&ss, "\n");

    if (ss.status != U_SSTREAM_OK)
        return 0;

    return Port_FileWrite(file, (const uint8_t *)line, (uint32_t)U_sstream_pos(&ss), &written);
}

static int exWriteAll(PortFile *file, Ex_Config *cfg)
{
    ExScalar scalars[EX_SCALARS_MAX];
    ExField fields[EX_FIELDS_MAX];
    uint32_t version = EX_CONFIG_VERSION;
    uint32_t scalarCount = exScalars(cfg, scalars);
    uint32_t t;
    uint32_t i;
    int ok;

    ok = exWriteLine(file, "# Phoscon Zigbee Stack example config, written by examples/common/ex_config.c", 0, 0);
    fields[0] = exField(EX_DEC, &version, 0);
    ok = ok && exWriteLine(file, "version", fields, 1);

    for (i = 0; ok && i < scalarCount; i++)
        ok = exWriteLine(file, scalars[i].name, &scalars[i].field, 1);

    for (t = 0; ok && t < EX_TABLE_COUNT; t++)
    {
        for (i = 0; ok && i < *s_tables[t].count(cfg) && i < s_tables[t].max; i++)
            ok = exWriteLine(file, s_tables[t].name, fields, s_tables[t].fields(cfg, i, fields));
    }

    return ok;
}

/* `<path>.tmp`, the name a save writes before it renames. */
static int exTempPath(const char *path, char *out, uint32_t cap)
{
    U_SStream ss;

    U_sstream_init(&ss, out, (unsigned)cap);
    U_sstream_put_str(&ss, path);
    U_sstream_put_str(&ss, ".tmp");

    return ss.status == U_SSTREAM_OK;
}

int Ex_ConfigSave(const Ex_Config *in, const char *path)
{
    char temp[EX_CONFIG_PATH_MAX];
    PortFile file;
    Ex_Config copy;
    int ok;

    if (in == 0 || path == 0 || !exTempPath(path, temp, (uint32_t)sizeof temp))
        return 0;

    /* The field tables point into a config they may also fill, so a save writes from a copy of its own */
    copy = *in;

    if (!Port_FileOpen(&file, temp, PORT_FILE_WRITE))
        return 0;

    ok = exWriteAll(&file, &copy);
    Port_FileClose(&file);

    if (ok && Port_FileRename(temp, path))
        return 1;

    (void)Port_FileDelete(temp);

    return 0;
}

/* The end of a value: the line's end or the space before the next one. */
static int exValueEnds(const U_SStream *ss)
{
    return U_sstream_at_end(ss) || U_sstream_peek_char(ss) == ' ';
}

static void exSkip(U_SStream *ss)
{
    U_sstream_seek(ss, U_sstream_pos(ss) + 1);
}

static int exHexDigit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';

    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;

    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;

    return -1;
}

/* Exactly 2 * `octets` hex digits, the value's whole token, into `out` in the order they are written. */
static int exGetHex(U_SStream *ss, uint8_t *out, uint32_t octets)
{
    uint32_t i;
    int high;
    int low;

    for (i = 0; i < octets; i++)
    {
        high = exHexDigit(U_sstream_peek_char(ss));
        exSkip(ss);
        low = exHexDigit(U_sstream_peek_char(ss));
        exSkip(ss);

        if (high < 0 || low < 0)
            return 0;

        out[i] = (uint8_t)((high << 4) | low);
    }

    return exValueEnds(ss);
}

static int exGetBig(U_SStream *ss, uint32_t octets, uint64_t *out)
{
    uint8_t big[8];
    uint32_t i;

    if (!exGetHex(ss, big, octets))
        return 0;

    *out = 0;

    for (i = 0; i < octets; i++)
        *out = (*out << 8) | big[i];

    return 1;
}

/* A decimal of one digit or more, at most `max`. U_sstream_get_long reads a long, which is 32 bits on some targets
   and signed on all of them, so a frame counter needs this one. */
static int exGetDec(U_SStream *ss, uint32_t max, uint32_t *out)
{
    uint32_t value = 0;
    uint32_t digits = 0;
    uint32_t digit;
    char ch;

    while (!exValueEnds(ss))
    {
        ch = U_sstream_peek_char(ss);

        if (ch < '0' || ch > '9')
            return 0;

        digit = (uint32_t)(ch - '0');

        if (digit > max || value > (max - digit) / 10)
            return 0;

        value = value * 10 + digit;
        digits++;
        exSkip(ss);
    }

    *out = value;

    return digits != 0;
}

/* The narrow kinds: a 16-bit hex value, an octet and a flag. */
static int exGetNarrow(U_SStream *ss, const ExField *field)
{
    uint64_t big;
    uint32_t value;

    if (field->kind == EX_HEX16 || field->kind == EX_OPT_HEX16)
    {
        if (!exGetBig(ss, 2, &big))
            return 0;

        *(uint16_t *)field->value = (uint16_t)big;

        return 1;
    }

    if (!exGetDec(ss, field->kind == EX_FLAG ? 1 : 0xff, &value))
        return 0;

    if (field->kind == EX_FLAG)
        *(int *)field->value = (int)value;
    else
        *(uint8_t *)field->value = (uint8_t)value;

    return 1;
}

static int exGetField(U_SStream *ss, const ExField *field)
{
    if (U_sstream_peek_char(ss) != ' ')
        return 0;

    exSkip(ss);

    if (field->kind == EX_OPT_HEX16 || field->kind == EX_OPT_KEY)
    {
        *field->present = U_sstream_peek_char(ss) != '-';

        if (!*field->present)
        {
            exSkip(ss);
            return exValueEnds(ss);
        }
    }

    switch (field->kind)
    {
    case EX_DEC:
        return exGetDec(ss, 0xffffffff, (uint32_t *)field->value);

    case EX_HEX64:
        return exGetBig(ss, 8, (uint64_t *)field->value);

    case EX_KEY:
    case EX_OPT_KEY:
        return exGetHex(ss, (uint8_t *)field->value, ZB_STACK_KEY_OCTETS);

    default:
        return exGetNarrow(ss, field);
    }
}

/* The name the line starts with, `name` whole and followed by a value. */
static int exNameIs(const U_SStream *ss, const char *name)
{
    uint32_t len = Zb_strlen(name, EX_CONFIG_LINE_MAX);

    return U_sstream_starts_with(ss, name) && U_sstream_remaining(ss) > len && U_sstream_str(ss)[len] == ' ';
}

/* What reading the lines so far has gathered: the config, which scalars came, and whether `version` did. */
typedef struct ExReader
{
    Ex_Config cfg;
    ExScalar scalars[EX_SCALARS_MAX];
    uint32_t scalarCount;
    uint32_t seen;
    int versionSeen;
} ExReader;

static int exReadValues(U_SStream *ss, const ExField *fields, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if (!exGetField(ss, &fields[i]))
            return 0;
    }

    return U_sstream_at_end(ss);
}

static int exReadLine(ExReader *reader, char *line, uint32_t len)
{
    ExField fields[EX_FIELDS_MAX];
    uint32_t version;
    uint32_t *count;
    U_SStream ss;
    uint32_t i;

    if (len == 0 || line[0] == '#')
        return 1;

    U_sstream_init(&ss, line, (unsigned)len);

    if (exNameIs(&ss, "version"))
    {
        U_sstream_seek(&ss, Zb_strlen("version", EX_CONFIG_LINE_MAX));
        fields[0] = exField(EX_DEC, &version, 0);

        if (reader->versionSeen || !exReadValues(&ss, fields, 1) || version != EX_CONFIG_VERSION)
            return 0;

        reader->versionSeen = 1;
        return 1;
    }

    for (i = 0; i < reader->scalarCount; i++)
    {
        if (!exNameIs(&ss, reader->scalars[i].name))
            continue;

        if ((reader->seen & ((uint32_t)1 << i)) != 0)
            return 0;

        reader->seen |= (uint32_t)1 << i;
        U_sstream_seek(&ss, Zb_strlen(reader->scalars[i].name, EX_CONFIG_LINE_MAX));

        return exReadValues(&ss, &reader->scalars[i].field, 1);
    }

    for (i = 0; i < EX_TABLE_COUNT; i++)
    {
        if (!exNameIs(&ss, s_tables[i].name))
            continue;

        count = s_tables[i].count(&reader->cfg);

        if (*count >= s_tables[i].max)
            return 0;

        U_sstream_seek(&ss, Zb_strlen(s_tables[i].name, EX_CONFIG_LINE_MAX));

        if (!exReadValues(&ss, fields, s_tables[i].fields(&reader->cfg, *count, fields)))
            return 0;

        (*count)++;
        return 1;
    }

    return 0;
}

/* The file a chunk at a time, cut into lines; a last line needs no newline. */
static int exReadAll(PortFile *file, ExReader *reader)
{
    uint8_t chunk[EX_READ_CHUNK];
    char line[EX_CONFIG_LINE_MAX];
    uint32_t lineLen = 0;
    uint32_t got;
    uint32_t i;

    while (Port_FileRead(file, chunk, (uint32_t)sizeof chunk, &got))
    {
        if (got == 0)
            return lineLen == 0 || exReadLine(reader, line, lineLen);

        for (i = 0; i < got; i++)
        {
            if (chunk[i] == '\n')
            {
                if (!exReadLine(reader, line, lineLen))
                    return 0;

                lineLen = 0;
            }
            else if (lineLen < sizeof line)
            {
                line[lineLen++] = (char)chunk[i];
            }
            else
            {
                return 0;
            }
        }
    }

    return 0;
}

int Ex_ConfigLoad(Ex_Config *out, const char *path)
{
    static ExReader reader;
    PortFile file;
    uint32_t all;
    int ok;

    if (out == 0 || path == 0 || !Port_FileOpen(&file, path, PORT_FILE_READ))
        return 0;

    Zb_memset(&reader, 0, (uint32_t)sizeof reader);
    reader.scalarCount = exScalars(&reader.cfg, reader.scalars);
    all = ((uint32_t)1 << reader.scalarCount) - 1;

    ok = exReadAll(&file, &reader);
    Port_FileClose(&file);

    if (!ok || !reader.versionSeen || reader.seen != all || reader.cfg.state.version < ZB_STATE_VERSION_OLDEST
        || reader.cfg.state.version > ZB_STATE_VERSION || reader.cfg.channel < 11 || reader.cfg.channel > 26)
        return 0;

    *out = reader.cfg;

    return 1;
}

void Ex_ConfigToStack(const Ex_Config *in, Zb_StackConfig *cfg)
{
    if (in == 0 || cfg == 0)
        return;

    cfg->channel = in->channel;
    Zb_memcpy(cfg->linkKeySeed, in->linkKeySeed, ZB_STACK_KEY_OCTETS);
    cfg->state = &in->state;
}
