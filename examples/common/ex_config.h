#ifndef EX_CONFIG_H
#define EX_CONFIG_H

/* An example's saved network: a text file of one field per line, built and read through U_SStream and stored through
   the port's files (examples/README.md). This module is the only writer, so a line it cannot read refuses the file;
   a `#` line and a blank one are skipped, for the samples in examples/config/. */

#include <stdint.h>

#include "zb_stack.h"

#define EX_CONFIG_VERSION 1           /* the file's own schema; the state inside it carries ZB_STATE_VERSION */
#define EX_CONFIG_LINE_MAX 128        /* the longest line, a key pair's with its link key, is about 100 */
#define EX_CONFIG_PATH_MAX 256        /* a path and the ".tmp" a save writes beside it */

typedef struct Ex_Config
{
    uint32_t channel;                 /* not in Zb_State: the network's channel, 11 to 26 */
    uint8_t linkKeySeed[ZB_STACK_KEY_OCTETS];         /* the seed joiners' link keys come from (Zb_StackConfig's) */
    Zb_State state;                   /* what Zb_StackCapture returned */
} Ex_Config;

/* Reads the file at `path`: 1 with `*out` filled, 0 with `*out` untouched for a file that is missing, unreadable,
   of another version, or holds a line this module does not write. */
int Ex_ConfigLoad(Ex_Config *out, const char *path);

/* Writes `in` to `<path>.tmp` and renames it over `path`, so a failed save leaves the previous file as it was. */
int Ex_ConfigSave(const Ex_Config *in, const char *path);

/* Points a config of the state's role at the saved network: its channel, the seed, and the state. `in` is read when
   the RCP comes up, so it outlives ZB_EVENT_NETWORK_UP. */
void Ex_ConfigToStack(const Ex_Config *in, Zb_StackConfig *cfg);

#endif /* EX_CONFIG_H */
