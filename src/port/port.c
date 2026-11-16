#include "port.h"
#include "zb_utils.h"


enum
{
    PORT_RX_RING_CAPACITY = sizeof(((Port *)0)->rxRing),
    PORT_TX_RING_CAPACITY = sizeof(((Port *)0)->txRing)
};

/* The rings are fixed arrays: a configured size may shrink them, never exceed them
   (docs/internals/coding-rules.md §7). */
typedef char PortRingCapacityBound[(PORT_RX_RING_CAPACITY == PORT_RX_RING_DEFAULT &&
                                    PORT_TX_RING_CAPACITY == PORT_TX_RING_DEFAULT) ? 1 : -1];

static int isPowerOfTwo(uint32_t v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

static uint32_t ringOccupancy(uint32_t write, uint32_t read)
{
    return write - read;
}

static uint32_t ringFree(Port *port, int isRx)
{
    uint32_t size = isRx ? port->rxRingSize : port->txRingSize;
    uint32_t used = isRx ? ringOccupancy(port->rxWrite, port->rxRead)
                         : ringOccupancy(port->txWrite, port->txRead);
    return size - used;
}

ZbStatus Port_Init(Port *port, const PortDeviceOps *ops)
{
    if (!port || !ops)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(port, 0, (uint32_t)sizeof *port);
    port->ops = ops;
    port->rxRingSize = PORT_RX_RING_DEFAULT;
    port->txRingSize = PORT_TX_RING_DEFAULT;
    port->state = PORT_STATE_CLOSED;
    return ZB_OK;
}

ZbStatus Port_Open(Port *port, const char *path, const PortConfig *config)
{
    PortConfig settings;
    uint32_t rxSize;
    uint32_t txSize;
    ZbStatus status;

    if (!port || !port->ops)
        return ZB_ERR_BAD_ARGUMENT;

    if (!port->ops->open)
        return ZB_ERR_UNSUPPORTED;

    if (!path || path[0] == '\0')
        return ZB_ERR_BAD_ARGUMENT;

    if (Zb_strlen(path, PORT_PATH_MAX) >= PORT_PATH_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    settings.baud = PORT_BAUD_LINK;
    settings.rxRingSize = PORT_RX_RING_DEFAULT;
    settings.txRingSize = PORT_TX_RING_DEFAULT;
    settings.exclusive = 1;

    if (config)
    {
        if (config->baud != 0)
            settings.baud = config->baud;

        if (config->rxRingSize != 0)
            settings.rxRingSize = config->rxRingSize;

        if (config->txRingSize != 0)
            settings.txRingSize = config->txRingSize;

        settings.exclusive = config->exclusive;
    }

    rxSize = settings.rxRingSize;
    txSize = settings.txRingSize;

    if (!isPowerOfTwo(rxSize) || rxSize > PORT_RX_RING_CAPACITY)
        return ZB_ERR_BAD_ARGUMENT;

    if (!isPowerOfTwo(txSize) || txSize > PORT_TX_RING_CAPACITY)
        return ZB_ERR_BAD_ARGUMENT;

    if (port->state != PORT_STATE_CLOSED)
        Port_Close(port);

    port->rxRingSize = rxSize;
    port->txRingSize = txSize;

    if (path != port->path)
        Zb_memcpy(port->path, path, Zb_strlen(path, PORT_PATH_MAX) + 1);

    status = port->ops->open(port, path, &settings);

    if (status != ZB_OK)
    {
        port->state = PORT_STATE_FAULT;

        if (port->fault == PORT_FAULT_NONE)
            port->fault = PORT_FAULT_OPEN;

        return status;
    }

    port->state = PORT_STATE_READY;
    port->fault = PORT_FAULT_NONE;
    return ZB_OK;
}

void Port_Close(Port *port)
{
    if (!port || !port->ops)
        return;

    if (port->ops->close)
        port->ops->close(port);

    port->rxWrite = 0;
    port->rxRead = 0;
    port->txWrite = 0;
    port->txRead = 0;
    port->drops = 0;
    port->refusals = 0;
    port->platformErrno = 0;
    port->device = 0;
    port->fault = PORT_FAULT_NONE;
    port->state = PORT_STATE_CLOSED;
}

ZbStatus Port_Write(Port *port, const uint8_t *bytes, uint32_t len, uint32_t *written)
{
    uint32_t mask;
    uint32_t index;
    uint32_t tail;

    if (!written)
        return ZB_ERR_BAD_ARGUMENT;

    *written = 0;

    if (!port || !port->ops || !bytes)
        return ZB_ERR_BAD_ARGUMENT;

    if (len == 0 || len > port->txRingSize)
        return ZB_ERR_BAD_ARGUMENT;

    if (port->state == PORT_STATE_FAULT)
        return ZB_ERR_DEVICE_LOST;

    if (port->state != PORT_STATE_READY)
        return ZB_ERR_NOT_OPEN;


    if (ringFree(port, 0) < len)
    {
        port->refusals++;
        return ZB_ERR_BUSY;
    }

    mask = port->txRingSize - 1;
    index = port->txWrite & mask;
    tail = port->txRingSize - index;

    if (tail > len)
        tail = len;

    Zb_memcpy(&port->txRing[index], bytes, tail);

    if (len > tail)
        Zb_memcpy(&port->txRing[0], &bytes[tail], len - tail);

    port->txWrite += len;
    *written = len;

    if (port->ops->drain)
    {
        ZbStatus status = port->ops->drain(port);

        if (status != ZB_OK)
        {
            port->state = PORT_STATE_FAULT;
            return status;
        }
    }

    return ZB_OK;
}

ZbStatus Port_Read(Port *port, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    uint32_t mask;
    uint32_t index;
    uint32_t take;
    uint32_t tail;

    if (!got)
        return ZB_ERR_BAD_ARGUMENT;

    *got = 0;

    if (!port || !port->ops || !buf)
        return ZB_ERR_BAD_ARGUMENT;

    if (port->state == PORT_STATE_CLOSED)
        return ZB_ERR_NOT_OPEN;

    if (port->state == PORT_STATE_READY && port->ops->pump)
    {
        if (port->ops->pump(port) < 0)
        {
            port->state = PORT_STATE_FAULT;

            if (port->fault == PORT_FAULT_NONE)
                port->fault = PORT_FAULT_READ;
        }
    }

    if (cap > 0)
    {
        mask = port->rxRingSize - 1;

        while (cap > 0 && port->rxRead != port->rxWrite)
        {
            index = port->rxRead & mask;
            take = cap;

            if (take > ringOccupancy(port->rxWrite, port->rxRead))
                take = ringOccupancy(port->rxWrite, port->rxRead);

            tail = port->rxRingSize - index;

            if (take > tail)
                take = tail;

            Zb_memcpy(buf, &port->rxRing[index], take);
            buf += take;
            cap -= take;
            *got += take;
            port->rxRead += take;
        }
    }


    if (*got == 0 && port->state == PORT_STATE_FAULT)
    {
        if (port->ops->lastFault)
            return port->ops->lastFault(port);

        return ZB_ERR_DEVICE_LOST;
    }

    return ZB_OK;
}

uint32_t Port_PushRx(Port *port, const uint8_t *bytes, uint32_t len)
{
    uint32_t mask;
    uint32_t index;
    uint32_t accept;
    uint32_t tail;

    if (!port || !bytes)
        return 0;

    accept = len;

    if (accept > ringFree(port, 1))
        accept = ringFree(port, 1);

    if (accept == 0)
    {
        port->drops += len;
        return 0;
    }

    if (accept < len)
        port->drops += len - accept;

    mask = port->rxRingSize - 1;
    index = port->rxWrite & mask;
    tail = port->rxRingSize - index;

    if (tail > accept)
        tail = accept;

    Zb_memcpy(&port->rxRing[index], bytes, tail);

    if (accept > tail)
        Zb_memcpy(&port->rxRing[0], &bytes[tail], accept - tail);

    port->rxWrite += accept;
    return accept;
}

uint32_t Port_RxPending(const Port *port)
{
    if (!port)
        return 0;

    return ringOccupancy(port->rxWrite, port->rxRead);
}

const uint8_t *Port_TxHead(const Port *port, uint32_t *contiguous)
{
    uint32_t pending;
    uint32_t index;
    uint32_t run;

    if (!contiguous)
        return 0;

    *contiguous = 0;

    if (!port)
        return 0;

    pending = ringOccupancy(port->txWrite, port->txRead);

    if (pending == 0)
        return 0;

    index = port->txRead & (port->txRingSize - 1);
    run = port->txRingSize - index;

    if (run > pending)
        run = pending;

    *contiguous = run;
    return &port->txRing[index];
}

void Port_ConsumeTx(Port *port, uint32_t len)
{
    uint32_t pending;

    if (!port || len == 0)
        return;

    pending = ringOccupancy(port->txWrite, port->txRead);

    if (len > pending)
        len = pending;

    port->txRead += len;
}

uint32_t Port_TxPending(const Port *port)
{
    if (!port)
        return 0;

    return ringOccupancy(port->txWrite, port->txRead);
}

ZbStatus Port_Entropy(Port *port, uint8_t *out, uint32_t len)
{
    if (!port || !port->ops || !out)
        return ZB_ERR_BAD_ARGUMENT;

    if (len == 0)
        return ZB_OK;

    if (len > PORT_ENTROPY_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!port->ops->entropy)
        return ZB_ERR_UNSUPPORTED;

    return port->ops->entropy(port, out, len);
}

ZbStatus Port_Wait(Port *port, uint32_t maxMs)
{
    ZbStatus status;

    if (!port || !port->ops)
        return ZB_ERR_BAD_ARGUMENT;

    if (port->state != PORT_STATE_READY)
        return ZB_ERR_NOT_OPEN;

    if (Port_TxPending(port) != 0)
        (void)port->ops->drain(port);

    if (Port_RxPending(port) != 0)
        return ZB_OK;

    if (!port->ops->wait)
        return ZB_ERR_UNSUPPORTED;

    status = port->ops->wait(port, maxMs);

    if (port->fault != PORT_FAULT_NONE)
        port->state = PORT_STATE_FAULT;

    return status;
}

void Port_TestPrimeRing(Port *port, uint32_t rxWrite, uint32_t rxRead)
{
    if (!port)
        return;

    port->rxWrite = rxWrite;
    port->rxRead = rxRead;
}

uint32_t Port_Drops(const Port *port)
{
    return !port ? 0 : port->drops;
}

uint32_t Port_Refusals(const Port *port)
{
    return !port ? 0 : port->refusals;
}

uint32_t Port_RxRingSize(const Port *port)
{
    return !port ? 0 : port->rxRingSize;
}

uint32_t Port_TxRingSize(const Port *port)
{
    return !port ? 0 : port->txRingSize;
}

PortState Port_State(const Port *port)
{
    return !port ? PORT_STATE_CLOSED : port->state;
}

int Port_IsOpen(const Port *port)
{
    return (port && port->state == PORT_STATE_READY) ? 1 : 0;
}

const char *Port_Path(const Port *port)
{
    return !port ? "" : port->path;
}

const char *Port_Device(const Port *port)
{
    if (!port)
        return "";

    return port->located[0] != 0 ? port->located : port->path;
}

const char *Port_TargetName(const Port *port)
{
    if (!port || !port->ops || !port->ops->name)
        return "";

    return port->ops->name;
}

PortFault Port_Fault(const Port *port)
{
    return !port ? PORT_FAULT_NONE : port->fault;
}

uint32_t Port_PlatformErrno(const Port *port)
{
    return !port ? 0 : port->platformErrno;
}
