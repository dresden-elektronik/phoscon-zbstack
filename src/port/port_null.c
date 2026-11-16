#include "port_null.h"
#include "zb_utils.h"


#define SCRIPT_NO_INJECTION 0xffffffff

static ZbStatus nullOpen(Port *port, const char *path, const PortConfig *config)
{
    PortNullScript *script = (PortNullScript *)port->implData;

    (void)path;
    (void)config;

    if (!script)
        return ZB_ERR_BAD_ARGUMENT;

    port->fault = PORT_FAULT_NONE;
    port->platformErrno = 0;
    script->seenBaud = config->baud;
    script->seenRxRing = config->rxRingSize;
    script->seenTxRing = config->txRingSize;
    script->seenExclusive = config->exclusive;

    if (script->failOpen)
    {
        port->fault = PORT_FAULT_DEVICE_GONE;
        port->platformErrno = script->platformErrno;
        return ZB_ERR_NO_DEVICE;
    }

    port->device = 1;
    return ZB_OK;
}

static void nullClose(Port *port)
{
    port->device = 0;
}

static int nullPump(Port *port)
{
    PortNullScript *script = (PortNullScript *)port->implData;
    uint32_t remaining;
    uint32_t deliver;
    uint32_t freeSpace;

    if (!script)
        return -1;

    script->pumpCalls++;

    if (script->pumpCalls > script->failPumpAfter)
    {
        port->fault = PORT_FAULT_READ;
        port->platformErrno = script->platformErrno;
        return -1;
    }

    if (!script->rxBytes)
        return 0;

    remaining = script->rxLen - script->rxPos;

    if (script->rxLimit != 0 && remaining > script->rxLimit)
        remaining = script->rxLimit;

    if (remaining == 0)
        return 0;

    deliver = remaining;

    if (script->rxChunk != 0 && deliver > script->rxChunk)
        deliver = script->rxChunk;

    freeSpace = Port_RxRingSize(port) - Port_RxPending(port);

    if (deliver > freeSpace)
        deliver = freeSpace;

    if (deliver == 0)
        return 0;

    script->rxPos += deliver;
    return (int)Port_PushRx(port, &script->rxBytes[script->rxPos - deliver], deliver);
}

static ZbStatus nullDrain(Port *port)
{
    PortNullScript *script = (PortNullScript *)port->implData;
    const uint8_t *bytes;
    uint32_t run;

    if (!script)
        return ZB_ERR_BAD_ARGUMENT;

    script->drainCalls++;

    if (script->drainCalls > script->failDrainAfter)
    {
        port->fault = PORT_FAULT_WRITE;
        port->platformErrno = script->platformErrno;
        return ZB_ERR_DEVICE_LOST;
    }

    for (;;)
    {
        bytes = Port_TxHead(port, &run);

        if (!bytes)
            return ZB_OK;

        if (script->txRateLimit != 0 && run > script->txRateLimit)
            run = script->txRateLimit;

        if (script->txCapture && script->txCount + run <= script->txCapacity)
        {
            Zb_memcpy(&script->txCapture[script->txCount], bytes, run);
            script->txCount += run;
        }
        else
        {
            script->txOverflow += run;
        }

        Port_ConsumeTx(port, run);

        if (script->txRateLimit != 0)
            return ZB_OK;
    }
}

static ZbStatus nullLastFault(const Port *port)
{
    (void)port;
    return ZB_ERR_DEVICE_LOST;
}

/*
 * Scripted entropy, in the same idiom as the rx transcript: the bytes are the test's, they are handed
 * over in order, and a request past what the script holds is refused with ZB_ERR_NO_SPACE and counted,
 * the house refusal-and-count for a pool that has run out (docs/internals/coding-rules.md §4.3), with the caller's
 * buffer left exactly as it was. The script lives in the caller's `PortNullScript`, which this module
 * reaches through `implData` and never copies.
 */
static ZbStatus nullEntropy(Port *port, uint8_t *out, uint32_t len)
{
    PortNullScript *script = (PortNullScript *)port->implData;

    if (!script)
        return ZB_ERR_BAD_ARGUMENT;

    if (!script->entropyBytes || script->entropyLen - script->entropyPos < len)
    {
        script->entropyRefused++;
        return ZB_ERR_NO_SPACE;
    }

    Zb_memcpy(out, &script->entropyBytes[script->entropyPos], len);
    script->entropyPos += len;
    return ZB_OK;
}

static const PortDeviceOps s_ops = {
    "null",
    nullOpen,
    nullClose,
    nullPump,
    nullDrain,
    nullLastFault,
    nullEntropy,
    0
};

const PortDeviceOps *PortNullOps(void)
{
    return &s_ops;
}

void PortNull_Attach(Port *port, PortNullScript *script)
{
    if (!port)
        return;

    port->implData = script;
}

void PortNull_Reset(PortNullScript *script)
{
    if (!script)
        return;

    script->rxPos = 0;
    script->entropyPos = 0;
    script->entropyRefused = 0;
    script->txCount = 0;
    script->txOverflow = 0;
    script->pumpCalls = 0;
    script->drainCalls = 0;
    script->failPumpAfter = SCRIPT_NO_INJECTION;
    script->failDrainAfter = SCRIPT_NO_INJECTION;
    script->platformErrno = 0;
}

uint32_t PortNull_Captured(const Port *port)
{
    PortNullScript *script;

    if (!port)
        return 0;

    script = (PortNullScript *)port->implData;
    return !script ? 0 : script->txCount;
}

uint32_t PortNull_Overflow(const Port *port)
{
    PortNullScript *script;

    if (!port)
        return 0;

    script = (PortNullScript *)port->implData;
    return !script ? 0 : script->txOverflow;
}
