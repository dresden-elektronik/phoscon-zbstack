#ifndef PORT_NULL_H
#define PORT_NULL_H

#include "port.h"

/* Scripted port for suites: the transcript is the test data, the splits are the
   test's choice, and nothing here touches a device. Entropy is scripted too (`entropyBytes` is
   consumed in call order and a request past the end of it is refused with ZB_ERR_NO_SPACE), which is
   what lets a suite hold a caller-supplied byte source in its own hands instead of asking a host for
   octets it cannot name afterwards. */
typedef struct PortNullScript
{
    const uint8_t *rxBytes;
    uint32_t rxLen;
    uint32_t rxChunk;      /* 0 delivers everything remaining that the ring accepts */
    uint32_t rxLimit;      /* 0 delivers the whole script */

    uint8_t *txCapture;
    uint32_t txCapacity;
    uint32_t txRateLimit;   /* bytes one drain may consume; 0 = unlimited (a busy device) */

    const uint8_t *entropyBytes;   /* the scripted entropy, caller-owned, consumed in call order; 0 scripts none */
    uint32_t entropyLen;

    int failOpen;          /* 0/1 */
    uint32_t failPumpAfter;  /* 0xffffffff disables */
    uint32_t failDrainAfter; /* 0xffffffff disables */
    uint32_t platformErrno;

    uint32_t rxPos;
    uint32_t entropyPos;      /* how much of the entropy script has been handed over */
    uint32_t seenBaud;      /* what the port module actually passed down */
    uint32_t seenRxRing;
    uint32_t seenTxRing;
    int seenExclusive;      /* 0/1 */
    uint32_t txCount;
    uint32_t txOverflow;
    uint32_t pumpCalls;
    uint32_t drainCalls;
    uint32_t entropyRefused;   /* requests past the end of the script, counted and refused (docs/internals/coding-rules.md §4.3) */
} PortNullScript;

const PortDeviceOps *PortNullOps(void);

void     PortNull_Attach(Port *port, PortNullScript *script);
void     PortNull_Reset(PortNullScript *script);
uint32_t PortNull_Captured(const Port *port);
uint32_t PortNull_Overflow(const Port *port);

#endif /* PORT_NULL_H */
