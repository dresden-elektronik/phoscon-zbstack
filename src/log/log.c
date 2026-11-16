#include "log.h"

ZbStatus Log_Init(Log_Log *self)
{
    if (!self)
        return ZB_ERR_BAD_ARGUMENT;

    self->head = 0;
    self->count = 0;
    self->refused = 0;
    self->drained = 0;
    return ZB_OK;
}

ZbStatus Log_Report(Log_Log *self, uint16_t component, uint16_t line, uint16_t reason, uint32_t argument)
{
    Log_Record *slot;
    uint32_t tail;

    if (!self)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->count == LOG_RING_MAX)
    {
        self->refused++;
        return ZB_ERR_NO_SPACE;
    }

    tail = (self->head + self->count) % LOG_RING_MAX;
    slot = &self->ring[tail];

    slot->component = component;
    slot->line = line;
    slot->reason = reason;
    slot->argument = argument;
    self->count++;
    return ZB_OK;
}

uint32_t Log_Drain(Log_Log *self, const Log_Sink *sink)
{
    uint32_t handed = 0;

    if (!self || !sink || !sink->write)
        return 0;

    while (self->count != 0)
    {
        sink->write(sink->context, &self->ring[self->head]);
        self->head = (self->head + 1) % LOG_RING_MAX;
        self->count--;
        self->drained++;
        handed++;
    }

    return handed;
}

uint32_t Log_Count(const Log_Log *self)
{
    if (!self)
        return 0;

    return self->count;
}

uint32_t Log_Refused(const Log_Log *self)
{
    if (!self)
        return 0;

    return self->refused;
}

uint32_t Log_Drained(const Log_Log *self)
{
    if (!self)
        return 0;

    return self->drained;
}
