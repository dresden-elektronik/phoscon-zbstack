/* Suite for the log substrate: the record is twelve bytes (a 16-bit component, a 16-bit
   line, a 16-bit reason, a 32-bit argument) from the call site to the sink; the pool keeps
   its order through a wrap, its full policy is to refuse and count, and the host-side name
   table names every code the core knows and nothing else. A string is built nowhere in this
   suite: a verdict is a line the shared assertion family prints. */

#include "log.h"
#include "log_names.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The memory sink: the host-side half of logging, done in a few lines, which is what the
   interface is for. It records what it is handed, in the order it is handed it. */
#define SINK_MAX 4096

static Log_Record s_sink[SINK_MAX];
static uint32_t s_sinkCount;

static void memSinkWrite(void *context, const Log_Record *record)
{
    (void)context;

    if (s_sinkCount < SINK_MAX)
        s_sink[s_sinkCount] = *record;

    s_sinkCount++;
}

static void memSinkReset(void)
{
    s_sinkCount = 0;
}

static void caseInit(void)
{
    Log_Log log;

    Test_ExpectStatus(Log_Init(&log), ZB_OK, "a pool initialises");
    Test_Expect(Log_Count(&log) == 0, "empty after the reset");
    Test_Expect(Log_Refused(&log) == 0, "with nothing refused");
    Test_Expect(Log_Drained(&log) == 0, "and nothing handed over");
    Test_Expect(Log_Count(0) == 0 && Log_Refused(0) == 0 && Log_Drained(0) == 0,
           "and the readers say so for a 0 pool rather than faulting");
}

static void caseReportAndDrain(void)
{
    Log_Log log;
    Log_Sink sink;

    Log_Init(&log);
    memSinkReset();
    sink.context = 0;
    sink.write = memSinkWrite;

    Test_ExpectStatus(Log_Report(&log, LOG_COMP_PORT_CORE, 101, LOG_REASON_ERROR, 12), ZB_OK, "a report is taken");
    Test_ExpectStatus(Log_Report(&log, LOG_COMP_SPINEL_SESSION, 202, LOG_REASON_TIMEOUT, 1500), ZB_OK, "and so is the next");
    Test_ExpectStatus(Log_Report(&log, LOG_COMP_MAC, 303, LOG_REASON_DROPPED, 2), ZB_OK, "and so is the third");
    Test_Expect(Log_Count(&log) == 3, "all three are waiting");

    Test_Expect(Log_Drain(&log, &sink) == 3, "the drain hands over all three");
    Test_Expect(Log_Count(&log) == 0, "and the pool is empty again");
    Test_Expect(Log_Drained(&log) == 3, "and the count of what was handed over is kept");

    Test_Expect(s_sinkCount == 3, "the sink saw three records");

    if (s_sinkCount == 3)
    {
        /* FIFO order, oldest first: the sink may rely on the order the faults happened in. */
        Test_Expect(s_sink[0].component == LOG_COMP_PORT_CORE && s_sink[0].line == 101
               && s_sink[0].reason == LOG_REASON_ERROR && s_sink[0].argument == 12,
               "the first record is the first report, integer for integer");
        Test_Expect(s_sink[1].component == LOG_COMP_SPINEL_SESSION && s_sink[1].line == 202
               && s_sink[1].reason == LOG_REASON_TIMEOUT && s_sink[1].argument == 1500,
               "the second is the second");
        Test_Expect(s_sink[2].component == LOG_COMP_MAC && s_sink[2].line == 303
               && s_sink[2].reason == LOG_REASON_DROPPED && s_sink[2].argument == 2,
               "the third is the third");
    }

    Test_Expect(Log_Drain(&log, &sink) == 0, "and a drain with nothing waiting hands over nothing");
    Test_Expect(Log_Drained(&log) == 3, "without moving the count of what was handed over");
}

static void caseWrap(void)
{
    Log_Log log;
    Log_Sink sink;
    uint32_t i;
    uint32_t mismatches;
    ZbStatus status;

    Log_Init(&log);
    memSinkReset();
    sink.context = 0;
    sink.write = memSinkWrite;

    /* More reports than the pool holds, drained in turns: the pool wraps, and the order the
       records were reported in is the order the sink gets them in, wrap or no wrap. */
    status = ZB_OK;

    for (i = 0; i < 3 * LOG_RING_MAX; i++)
    {
        if (i % 17 == 0)
            Log_Drain(&log, &sink);

        status = Log_Report(&log, (uint16_t)(0x0100 + (i % 7)), 4000 + i, (i % 5) + 1, i);

        if (status != ZB_OK)
            break;
    }

    Test_Expect(Log_Drain(&log, &sink) <= 16, "and the last drain finds only the reports since the previous one");
    Test_Expect(Log_Count(&log) == 0, "and after it the pool is empty");

    mismatches = 0;

    for (i = 0; i < s_sinkCount && i < SINK_MAX; i++)
    {
        if (s_sink[i].component != (uint16_t)(0x0100 + (i % 7)) || (s_sink[i].component >> 8) != 0x01
            || s_sink[i].reason != (i % 5) + 1
            || s_sink[i].argument != i)
            mismatches++;
    }

    Test_Expect(status == ZB_OK && i == 3 * LOG_RING_MAX,
           "every one of the 192 reports was taken and drained");
    Test_Expect(s_sinkCount == 3 * LOG_RING_MAX, "the sink saw every one of them");
    Test_Expect(mismatches == 0, "in the order they were reported, field for field");
    Test_Expect(Log_Refused(&log) == 0,
           "and the wrap refused nothing: a drain between reports is the caller's job, and it did it");
}

static void caseFullPolicy(void)
{
    Log_Log log;
    Log_Sink sink;
    uint32_t i;

    Log_Init(&log);
    memSinkReset();
    sink.context = 0;
    sink.write = memSinkWrite;

    for (i = 0; i < LOG_RING_MAX; i++)
        Log_Report(&log, LOG_COMP_RCP_RADIO, 500 + i, LOG_REASON_STATE, i);

    Test_Expect(Log_Count(&log) == LOG_RING_MAX, "the pool is full");

    Test_ExpectStatus(Log_Report(&log, LOG_COMP_RCP_RADIO, 500 + LOG_RING_MAX, LOG_REASON_ERROR, 99),
                 ZB_ERR_NO_SPACE,
                 "and the next report is refused, not folded over what is already kept");
    Test_Expect(Log_Refused(&log) == 1, "and the refusal is counted");
    Test_Expect(Log_Count(&log) == LOG_RING_MAX, "and the pool is still full, holding what it was given");

    Test_Expect(Log_Drain(&log, &sink) == LOG_RING_MAX, "and the full pool still drains");

    for (i = 0; i < LOG_RING_MAX && i < SINK_MAX; i++)
    {
        if (s_sink[i].argument != i)
            break;
    }

    Test_Expect(i == LOG_RING_MAX,
           "holding exactly the reports it took, in order, the refused one among them nowhere");
    Test_ExpectStatus(Log_Report(&log, LOG_COMP_RCP_RADIO, 900, LOG_REASON_ERROR, 99), ZB_OK,
                 "and a report after the drain is taken again");
}

static void caseArgumentErrors(void)
{
    Log_Log log;
    Log_Sink sink;

    Log_Init(&log);
    sink.context = 0;
    sink.write = 0;

    Test_ExpectStatus(Log_Report(0, LOG_COMP_PORT_CORE, 1, LOG_REASON_ERROR, 0), ZB_ERR_BAD_ARGUMENT,
                 "a report to a 0 pool is an argument error, not a write");
    Test_Expect(Log_Drain(0, &sink) == 0, "and a drain of a 0 pool hands over nothing");

    Log_Report(&log, LOG_COMP_PORT_CORE, 1, LOG_REASON_ERROR, 1);

    Test_Expect(Log_Drain(&log, &sink) == 0, "a sink with no write function hands over nothing");
    Test_Expect(Log_Count(&log) == 1, "and changes nothing: the record is still waiting");

    Test_Expect(Log_Drain(&log, 0) == 0, "and a 0 sink is the same refusal");

    Test_ExpectStatus(Log_Init(0), ZB_ERR_BAD_ARGUMENT, "and an init of a 0 pool is named");
}

/* One row per component constant, in the order the table declares them: the 23 named, plus
   the none. caseRecordShape walks it for shape, caseNameTable for the rows the name table
   should have. */
typedef struct CompPair
{
    uint16_t section;
    uint16_t component;
} CompPair;

static const CompPair s_compPairs[24] = {
    { LOG_SECTION_NONE, LOG_COMP_NONE },
    { LOG_SECTION_PORT, LOG_COMP_PORT_CORE },
    { LOG_SECTION_PORT, LOG_COMP_PORT_POSIX },
    { LOG_SECTION_PORT, LOG_COMP_PORT_NULL },
    { LOG_SECTION_PORT, LOG_COMP_PORT_WIN32 },
    { LOG_SECTION_PORT, LOG_COMP_PORT_LOG },
    { LOG_SECTION_HDLC, LOG_COMP_HDLC },
    { LOG_SECTION_SPINEL, LOG_COMP_SPINEL_CODEC },
    { LOG_SECTION_SPINEL, LOG_COMP_SPINEL_SESSION },
    { LOG_SECTION_RCP, LOG_COMP_RCP_RADIO },
    { LOG_SECTION_RCP, LOG_COMP_RCP_PROPS },
    { LOG_SECTION_LOOPBACK, LOG_COMP_LOOPBACK },
    { LOG_SECTION_MAC, LOG_COMP_MAC_FRAME },
    { LOG_SECTION_MAC, LOG_COMP_MAC },
    { LOG_SECTION_NWK, LOG_COMP_NWK },
    { LOG_SECTION_APS, LOG_COMP_APS },
    { LOG_SECTION_ZDO, LOG_COMP_ZDO },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY_PROTECT_REFUSED },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY_UNPROTECT_FAILED },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY_KEY_ADOPTED },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY_INCOMING_FULL },
    { LOG_SECTION_SECURITY, LOG_COMP_SECURITY_FRAME_TOO_LONG },
    { LOG_SECTION_APP, LOG_COMP_APP }
};

static const uint16_t s_sections[12] = {
    LOG_SECTION_NONE,
    LOG_SECTION_PORT,
    LOG_SECTION_HDLC,
    LOG_SECTION_SPINEL,
    LOG_SECTION_RCP,
    LOG_SECTION_LOOPBACK,
    LOG_SECTION_MAC,
    LOG_SECTION_NWK,
    LOG_SECTION_APS,
    LOG_SECTION_ZDO,
    LOG_SECTION_SECURITY,
    LOG_SECTION_APP
};

static void caseRecordShape(void)
{
    uint32_t i;
    uint32_t j;

    Test_Expect(sizeof(Log_Record) == 12, "the record is 12 bytes: three 16-bit fields and a 32-bit argument");

    for (i = 0; i < 24; i++)
    {
        if (s_compPairs[i].component == LOG_COMP_NONE)
            continue;

        Test_Expect(s_compPairs[i].component >> 8 == s_compPairs[i].section,
               "the section of every named component is its top byte");
        Test_Expect((s_compPairs[i].component & 0xFF) != 0,
               "and its topic is not 0x00: that low byte is left unattributed");
    }

    for (i = 0; i < 24; i++)
    {
        for (j = i + 1; j < 24; j++)
        {
            Test_Expect(s_compPairs[i].component != s_compPairs[j].component,
                   "no two component constants share the same (section, topic) pair");
        }
    }

    for (i = 0; i < 12; i++)
    {
        Test_Expect(s_sections[i] <= 0x0B, "every section value is one of the twelve named sections");

        for (j = i + 1; j < 12; j++)
            Test_Expect(s_sections[i] != s_sections[j], "and no two sections share a value");
    }
}

/* The suite's own word compare: the names are short static words, so a length check and a
   byte check over that length are the whole of it. */
static int nameEq(const char *a, const char *b)
{
    uint32_t la = Zb_strlen(a, 64);

    if (la != Zb_strlen(b, 64))
        return 0;

    return Zb_memcmp(a, b, la) == 0;
}

static void caseNameTable(void)
{
    const char *name;
    uint32_t i;

    for (i = 0; i < 12; i++)
    {
        name = LogNames_SectionName(s_sections[i]);

        Test_Expect(Zb_strlen(name, 64) != 0, "every declared section has a name");
        Test_Expect(!nameEq(name, "unknown"), "and it is not the unknown word");
    }

    for (i = 0; i < 24; i++)
    {
        if (s_compPairs[i].component == LOG_COMP_NONE)
            continue;

        name = LogNames_TopicName(s_compPairs[i].component);

        Test_Expect(Zb_strlen(name, 64) != 0, "every named component has a topic name");
        Test_Expect(!nameEq(name, "unknown"), "and it is not the unknown word");
    }

    Test_Expect(nameEq(LogNames_SectionName(0x0C), "unknown"),
           "and a section the table has no row for answers unknown");
    Test_Expect(nameEq(LogNames_TopicName(0x017F), "unknown"),
           "and a topic the table has no row for answers the same word");
    Test_Expect(Zb_strlen(LogNames_ReasonName(LOG_REASON_NONE), 64) != 0, "every named reason has a name");
    Test_Expect(Zb_strlen(LogNames_ReasonName(LOG_REASON_TIMEOUT), 64) != 0, "the timeout is named");
    Test_Expect(LogNames_ReasonName(0x7fffff) == LogNames_ReasonName(9999),
           "and a reason code with no row does the same, the same word every time");
    Test_Expect(LogNames_ReasonName(LOG_REASON_ASSERT) != LogNames_ReasonName(9999),
           "the assert reason is named");
}

int main(void)
{
    Test_Begin("log");

    caseInit();
    caseReportAndDrain();
    caseWrap();
    caseFullPolicy();
    caseArgumentErrors();
    caseRecordShape();
    caseNameTable();

    return Test_Report();
}
