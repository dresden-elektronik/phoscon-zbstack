/* Links the stack over the application's own streams: one call that reaches every layer. */

#include "zb_stack.h"

static Zb_StackConfig s_config;

int main(void)
{
    Zb_StackCoordinatorDefaults(&s_config);
    return s_config.role == ZB_STACK_COORDINATOR ? 0 : 1;
}
