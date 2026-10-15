// fixed-size scx scheduler ftrace tracepoints
// timestamps and cpu ids come from ftrace
#include "ftrace_setup.h"

#if !defined(TRACE_EVENTS__EVENTS_H) || defined(TRACE_HEADER_MULTI_READ)
#define TRACE_EVENTS__EVENTS_H

#include "event_types.h"
#include "helpers.h"

#define SCXTP_FIELDS_init(FIELD, ARRAY, STRING) \
  FIELD(__u64, cgrp_id)

SCXTP_DEFINE_EVENT(init, SCXTP_FIELDS_init,
  "cgrp_id=%llu",
  (unsigned long long)__entry->cgrp_id
);

#define SCXTP_FIELDS_exit(FIELD, ARRAY, STRING) \
  FIELD(__u64, cgrp_id)

SCXTP_DEFINE_EVENT(exit, SCXTP_FIELDS_exit,
  "cgrp_id=%llu",
  (unsigned long long)__entry->cgrp_id
);

#define SCXTP_FIELDS_cgroup_init_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, cgrp_id) \
  FIELD(__u64, weight)

SCXTP_DEFINE_EVENT(cgroup_init_args, SCXTP_FIELDS_cgroup_init_args,
  "cgrp_id=%llu weight=%llu",
  (unsigned long long)__entry->cgrp_id,
  (unsigned long long)__entry->weight
);

#define SCXTP_FIELDS_set_weight_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, cgrp_id) \
  FIELD(__u64, weight)

SCXTP_DEFINE_EVENT(set_weight_args, SCXTP_FIELDS_set_weight_args,
  "cgrp_id=%llu weight=%llu",
  (unsigned long long)__entry->cgrp_id,
  (unsigned long long)__entry->weight
);

#define SCXTP_FIELDS_sub_params_update(FIELD, ARRAY, STRING) \
  FIELD(__s32, idx) \
  FIELD(__u64, cgrp_id) \
  FIELD(__u64, weight)

SCXTP_DEFINE_EVENT(sub_params_update, SCXTP_FIELDS_sub_params_update,
  "idx=%d cgrp_id=%llu weight=%llu",
  __entry->idx,
  (unsigned long long)__entry->cgrp_id,
  (unsigned long long)__entry->weight
);

#define SCXTP_FIELDS_set_task_weight(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__u64, weight)

SCXTP_DEFINE_EVENT(set_task_weight, SCXTP_FIELDS_set_task_weight,
  "tid=%llu weight=%llu",
  (unsigned long long)__entry->tid,
  (unsigned long long)__entry->weight
);

#define SCXTP_FIELDS_set_cmask(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__u64, cmask)

SCXTP_DEFINE_EVENT(set_cmask, SCXTP_FIELDS_set_cmask,
  "tid=%llu cmask=%016llx",
  (unsigned long long)__entry->tid,
  (unsigned long long)__entry->cmask
);

#define SCXTP_FIELDS_init_task_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__u8, fork)

SCXTP_DEFINE_EVENT(init_task_args, SCXTP_FIELDS_init_task_args,
  "tid=%llu fork=%u",
  (unsigned long long)__entry->tid,
  __entry->fork
);

#define SCXTP_FIELDS_exit_task_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid)

SCXTP_DEFINE_EVENT(exit_task_args, SCXTP_FIELDS_exit_task_args,
  "tid=%llu",
  (unsigned long long)__entry->tid
);

#define SCXTP_FIELDS_cid_topo(FIELD, ARRAY, STRING) \
  FIELD(__s32, cid) \
  FIELD(__s32, cpu) \
  FIELD(__s32, core) \
  FIELD(__s32, shard) \
  FIELD(__s32, llc) \
  FIELD(__s32, node)

SCXTP_DEFINE_EVENT(cid_topo, SCXTP_FIELDS_cid_topo,
  "cid=%d cpu=%d core=%d shard=%d llc=%d node=%d",
  __entry->cid,
  __entry->cpu,
  __entry->core,
  __entry->shard,
  __entry->llc,
  __entry->node
);

#define SCXTP_FIELDS_enqueue_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__s32, prev_cid) \
  FIELD(__u64, enq_flags)

SCXTP_DEFINE_EVENT(enqueue_args, SCXTP_FIELDS_enqueue_args,
  "tid=%llu prev_cid=%d enq_flags=0x%llx",
  (unsigned long long)__entry->tid,
  __entry->prev_cid,
  (unsigned long long)__entry->enq_flags
);

#define SCXTP_FIELDS_select_cid_args(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__s32, prev_cid) \
  FIELD(__u64, wake_flags)

SCXTP_DEFINE_EVENT(select_cid_args, SCXTP_FIELDS_select_cid_args,
  "tid=%llu prev_cid=%d wake_flags=0x%llx",
  (unsigned long long)__entry->tid,
  __entry->prev_cid,
  (unsigned long long)__entry->wake_flags
);

#define SCXTP_FIELDS_running(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__u64, weight)

SCXTP_DEFINE_EVENT(running, SCXTP_FIELDS_running,
  "tid=%llu weight=%llu",
  (unsigned long long)__entry->tid,
  (unsigned long long)__entry->weight
);

#define SCXTP_FIELDS_stopping(FIELD, ARRAY, STRING) \
  FIELD(__u64, tid) \
  FIELD(__u8, runnable)

SCXTP_DEFINE_EVENT(stopping, SCXTP_FIELDS_stopping,
  "tid=%llu runnable=%u",
  (unsigned long long)__entry->tid,
  __entry->runnable
);

#endif

// define_trace.h rereads the event definitions outside the include guard
#include <trace/define_trace.h>
