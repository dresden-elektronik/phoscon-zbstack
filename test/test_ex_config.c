/* The `ex_config` suite: an example's saved network written and read back through the port's files, each kind of file
   the module did not write refused with the caller's config untouched, and the samples in examples/config/ read. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "ex_config.h"
#include "port_file.h"
#include "test_harness.h"

#define SCRATCH_CONFIG ZB_SCRATCH_DIR "/ex_config_scratch.txt"
#define SCRATCH_MISSING ZB_SCRATCH_DIR "/ex_config_missing.txt"
/* Every line a full config can hold, each at most EX_CONFIG_LINE_MAX: the scalars and one line per pool entry. */
#define SCRATCH_TEXT_MAX ((32 + SECURITY_KEY_SET_MAX + SECURITY_INCOMING_MAX + SECURITY_KEYPAIR_MAX + NWK_NEIGHBOR_MAX) \
                          * EX_CONFIG_LINE_MAX)

static Ex_Config s_full;
static Ex_Config s_read;
static Ex_Config s_untouched;
static char s_text[SCRATCH_TEXT_MAX];

/* Every field set and every pool full, a key and a short address absent where an entry may hold none. */
static void exFull(Ex_Config *cfg)
{
    Zb_State *s = &cfg->state;
    uint32_t i;

    memset(cfg, 0, sizeof *cfg);
    cfg->channel = 25;

    for (i = 0; i < ZB_STACK_KEY_OCTETS; i++)
        cfg->linkKeySeed[i] = (uint8_t)(0xf0 - i);

    s->version = ZB_STATE_VERSION;
    s->ownIeee = 0x00212effff00a001;
    s->deviceType = 2;
    s->trustCenterIeee = 0xffffffffffffffff;
    s->panId = 0xbeef;
    s->extendedPanId = 0x8877665544332211;
    s->networkAddress = 0xfffe;
    s->nwkUpdateId = 7;
    s->parentInformation = 3;
    s->parentShort = 0x1234;
    s->parentIeee = 0x00212effff00b002;
    s->stackProfile = 2;
    s->nwkSecurityLevel = 5;
    s->nwkActiveKeySeqNumber = 0xff;
    s->authenticated = 1;
    s->nwkAllFresh = 1;
    s->nwkSequenceNumber = 255;
    s->nwkRoutingSequenceNumber = 0xffff;
    s->macDsn = 254;
    s->apsCounter = 1;

    s->keyCount = SECURITY_KEY_SET_MAX;

    for (i = 0; i < s->keyCount; i++)
    {
        s->keys[i].keySeqNumber = (uint8_t)(0xfe + i);
        s->keys[i].outgoingFrameCounter = 0xffffffff - i;
        s->keys[i].keyPresent = i == 0;

        if (i == 0)
            memset(s->keys[i].key, 0xa5, sizeof s->keys[i].key);
    }

    s->windowCount = SECURITY_INCOMING_MAX;

    for (i = 0; i < s->windowCount; i++)
    {
        s->windows[i].senderIeee = 0x1000000000000000 + i;
        s->windows[i].keySeqNumber = (uint8_t)i;
        s->windows[i].frameCounter = 1000 * i;
    }

    s->pairCount = SECURITY_KEYPAIR_MAX;

    for (i = 0; i < s->pairCount; i++)
    {
        s->pairs[i].deviceIeee = i == 0 ? 0 : 0x2000000000000000 + i;
        s->pairs[i].shortKnown = i != 0;
        s->pairs[i].shortAddress = i != 0 ? (uint16_t)(0x0100 + i) : 0;
        s->pairs[i].keyAttributes = 2;
        s->pairs[i].linkKeyType = i == 0 ? 1 : 0;
        s->pairs[i].outgoingFrameCounter = 17 * i;
        s->pairs[i].featuresCapabilities = (uint8_t)(i & 1);
        s->pairs[i].keyPresent = i != 1;

        if (i != 1)
            memset(s->pairs[i].linkKey, (int)(0x10 + i), sizeof s->pairs[i].linkKey);
    }

    s->childCount = NWK_NEIGHBOR_MAX;

    for (i = 0; i < s->childCount; i++)
    {
        s->children[i].extendedAddress = 0x3000000000000000 + i;
        s->children[i].networkAddress = (uint16_t)(0x4000 + i);
        s->children[i].endDeviceConfiguration = i & 1;
        s->children[i].deviceTimeout = 10 + i;
    }
}

static void exWriteText(const char *path, const char *text)
{
    PortFile file;
    uint32_t written;

    Test_Expect(Port_FileOpen(&file, path, PORT_FILE_WRITE) == 1
                && Port_FileWrite(&file, (const uint8_t *)text, (uint32_t)strlen(text), &written) == 1,
                "the file under test is written");
    Port_FileClose(&file);
}

/* The saved file's text, to make a damaged copy of. */
static void exReadText(const char *path)
{
    PortFile file;
    uint32_t got = 0;

    memset(s_text, 0, sizeof s_text);
    Test_Expect(Port_FileOpen(&file, path, PORT_FILE_READ) == 1
                && Port_FileRead(&file, (uint8_t *)s_text, (uint32_t)sizeof s_text - 1, &got) == 1 && got != 0,
                "the saved file reads back as text");
    Port_FileClose(&file);
}

/* The saved text with one line replaced, or a line added at the end when `from` is 0. */
static void exDamaged(const char *from, const char *to, const char *what)
{
    static char damaged[SCRATCH_TEXT_MAX];
    const char *at = from != 0 ? strstr(s_text, from) : 0;

    if (from != 0 && at == 0)
    {
        Test_Expect(0, "the line a damage case replaces is in the saved file");
        return;
    }

    if (from == 0)
        snprintf(damaged, sizeof damaged, "%s%s", s_text, to);
    else
        snprintf(damaged, sizeof damaged, "%.*s%s%s", (int)(at - s_text), s_text, to, at + strlen(from));

    exWriteText(SCRATCH_CONFIG, damaged);
    memcpy(&s_read, &s_untouched, sizeof s_read);
    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_CONFIG) == 0, what);
    Test_Expect(memcmp(&s_read, &s_untouched, sizeof s_read) == 0, "and the caller's config is untouched");
}

static void caseRoundTrip(void)
{
    Test_Case("caseRoundTrip");

    exFull(&s_full);
    memset(&s_read, 0, sizeof s_read);

    Test_Expect(Ex_ConfigSave(&s_full, SCRATCH_CONFIG) == 1, "a config with every pool full is saved");
    Test_Expect(Port_FileExists(SCRATCH_CONFIG ".tmp") == 0, "and the name it was written under is gone");
    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_CONFIG) == 1, "and loaded");
    Test_Expect(memcmp(&s_read, &s_full, sizeof s_read) == 0,
                "every field as it was saved, a key and a short address absent where they were absent");
}

static void caseMissingFile(void)
{
    Test_Case("caseMissingFile");

    (void)Port_FileDelete(SCRATCH_MISSING);
    memset(&s_untouched, 0x5a, sizeof s_untouched);
    memcpy(&s_read, &s_untouched, sizeof s_read);

    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_MISSING) == 0, "a missing file does not load");
    Test_Expect(memcmp(&s_read, &s_untouched, sizeof s_read) == 0, "and leaves the caller's config as it was");
}

static void caseRefusals(void)
{
    Test_Case("caseRefusals");

    exFull(&s_full);
    Test_Expect(Ex_ConfigSave(&s_full, SCRATCH_CONFIG) == 1, "a config is saved to damage");
    exReadText(SCRATCH_CONFIG);
    memset(&s_untouched, 0x5a, sizeof s_untouched);

    exDamaged("version 1\n", "version 2\n", "a file of another version is refused");
    exDamaged("state-version 2\n", "state-version 3\n", "and one whose state is of another schema");
    exDamaged("channel 25\n", "", "a file missing a field is refused");
    exDamaged(0, "channel 25\n", "and one holding a field twice");
    exDamaged(0, "colour blue\n", "a line this module does not write is refused");
    exDamaged("channel 25\n", "channel 27\n", "a channel above 26 is refused");
    exDamaged("active-key 255\n", "active-key 256\n", "an octet's value above 255");
    exDamaged("authenticated 1\n", "authenticated 2\n", "a flag other than 0 or 1");
    exDamaged("pan BEEF\n", "pan BEE\n", "a short hex value");
    exDamaged("pan BEEF\n", "pan BEEG\n", "a digit that is not hex");
    exDamaged("pan BEEF\n", "pan BEEF 1\n", "a value past the ones the field has");
    exDamaged("pan BEEF\n", "pan\n", "a field with no value");
    exDamaged(0, "key 1 1 -\n", "an entry past the pool it fills");
    exDamaged(0, "# a comment longer than any line this module writes, which is one hundred and twenty-eight "
                 "characters at most, so this one is refused\n", "a line longer than EX_CONFIG_LINE_MAX");
}

static void caseLayout(void)
{
    size_t len;

    Test_Case("caseLayout");

    exFull(&s_full);
    Test_Expect(Ex_ConfigSave(&s_full, SCRATCH_CONFIG) == 1, "a config is saved");
    exReadText(SCRATCH_CONFIG);

    len = strlen(s_text);
    s_text[len - 1] = 0;
    exWriteText(SCRATCH_CONFIG, s_text);
    memset(&s_read, 0, sizeof s_read);
    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_CONFIG) == 1 && memcmp(&s_read, &s_full, sizeof s_read) == 0,
                "a last line without its newline is read");

    s_text[len - 1] = '\n';
    memmove(s_text + 2, s_text, len + 1);
    s_text[0] = '#';
    s_text[1] = '\n';
    strncat(s_text, "\n# the end\n", sizeof s_text - strlen(s_text) - 1);
    exWriteText(SCRATCH_CONFIG, s_text);
    memset(&s_read, 0, sizeof s_read);
    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_CONFIG) == 1 && memcmp(&s_read, &s_full, sizeof s_read) == 0,
                "and a comment line and a blank one are skipped");
}

/* A save that cannot write leaves the file it would have replaced. */
static void caseFailedSaveKeepsTheFile(void)
{
    static char longPath[EX_CONFIG_PATH_MAX + 1];

    Test_Case("caseFailedSaveKeepsTheFile");

    exFull(&s_full);
    Test_Expect(Ex_ConfigSave(&s_full, SCRATCH_CONFIG) == 1, "a config is saved");

    (void)remove(SCRATCH_CONFIG ".tmp");
    Test_Expect(mkdir(SCRATCH_CONFIG ".tmp", 0700) == 0, "a directory stands where the save writes first");

    s_full.channel = 11;
    Test_Expect(Ex_ConfigSave(&s_full, SCRATCH_CONFIG) == 0, "so the next save fails");
    Test_Expect(Ex_ConfigLoad(&s_read, SCRATCH_CONFIG) == 1 && s_read.channel == 25,
                "and the file holds the config saved before it");
    (void)remove(SCRATCH_CONFIG ".tmp");

    memset(longPath, 'a', EX_CONFIG_PATH_MAX);
    Test_Expect(Ex_ConfigSave(&s_full, longPath) == 0, "a path with no room for its .tmp is refused");
}

static void caseSamples(void)
{
    static const char *const samples[] = { "coordinator.txt", "router.txt", "end_device.txt" };
    char path[EX_CONFIG_PATH_MAX];
    uint32_t i;

    Test_Case("caseSamples");

    for (i = 0; i < sizeof samples / sizeof samples[0]; i++)
    {
        snprintf(path, sizeof path, "%s/%s", EX_CONFIG_SAMPLES, samples[i]);
        memset(&s_read, 0, sizeof s_read);
        Test_Expect(Ex_ConfigLoad(&s_read, path) == 1, "a sample in examples/config/ is a file the module reads");
        Test_ExpectCount(s_read.state.deviceType, i, "and names the role its file name does");
    }

    Test_Expect(s_read.state.parentInformation != 0 && s_read.state.childCount == 0 && s_read.state.parentIeee != 0,
                "the end device's keeps its parent by both addresses and its parent information, and holds no child");
}

static void caseToStack(void)
{
    Zb_StackConfig cfg;

    Test_Case("caseToStack");

    exFull(&s_full);
    Zb_StackCoordinatorDefaults(&cfg);
    Ex_ConfigToStack(&s_full, &cfg);

    Test_Expect(cfg.channel == 25 && memcmp(cfg.linkKeySeed, s_full.linkKeySeed, ZB_STACK_KEY_OCTETS) == 0,
                "a coordinator's config takes the saved channel and seed");
    Test_Expect(cfg.state == &s_full.state, "and points at the saved state, which the stack reads at bring-up");

    Zb_StackEndDeviceDefaults(&cfg);
    Ex_ConfigToStack(&s_full, &cfg);

    Test_Expect(cfg.channel == 25 && cfg.state == &s_full.state,
                "an end device's takes the channel too, which a joiner restored from its state runs on");
}

int main(void)
{
    Test_Begin("ex_config");

    caseRoundTrip();
    caseMissingFile();
    caseRefusals();
    caseLayout();
    caseFailedSaveKeepsTheFile();
    caseSamples();
    caseToStack();

    (void)Port_FileDelete(SCRATCH_CONFIG);

    return Test_Report();
}
