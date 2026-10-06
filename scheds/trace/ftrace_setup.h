// reread with events.h so ftrace's header passes use the same setup
#undef TRACE_SYSTEM
#define TRACE_SYSTEM scxtp

#include <linux/tracepoint.h>

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE events
