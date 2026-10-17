// fixed-size trace events shared between all schedulers and userspace

#ifndef TRACE_EVENTS__EVENT_TYPES_H
#define TRACE_EVENTS__EVENT_TYPES_H

#ifndef __BPF__
#include <linux/types.h>
#endif

struct scxtp_event_init {
  __u64 cgrp_id;
};

struct scxtp_event_exit {
  __u64 cgrp_id;
};

struct scxtp_event_cgroup_init_args {
  __u64 cgrp_id;
  __u64 weight;
};

struct scxtp_event_set_weight_args {
  __u64 cgrp_id;
  __u64 weight;
};

struct scxtp_event_sub_params_update {
  __s32 idx;
  __u64 cgrp_id;
  __u64 weight;
};

struct scxtp_event_set_task_weight {
  __u64 tid;
  __u64 weight;
};

struct scxtp_event_set_cmask {
  __u64 tid;
  __u64 cmask;
};

struct scxtp_event_init_task_args {
  __u64 tid;
  __u8 fork;
};

struct scxtp_event_exit_task_args {
  __u64 tid;
};

struct scxtp_event_cid_topo {
  __s32 cid;
  __s32 cpu;
  __s32 core;
  __s32 shard;
  __s32 llc;
  __s32 node;
};

struct scxtp_event_enqueue_args {
  __u64 tid;
  __s32 prev_cid;
  __u64 enq_flags;
};

struct scxtp_event_select_cid_args {
  __u64 tid;
  __s32 prev_cid;
  __u64 wake_flags;
};

struct scxtp_event_running {
  __u64 tid;
  __u64 weight;
};

struct scxtp_event_stopping {
  __u64 tid;
  __u8 runnable;
};

// append new ids to preserve existing trace meanings
enum scxtp_op {
  SCXTP_OP_INIT = 1,
  SCXTP_OP_EXIT,
  SCXTP_OP_SELECT_CID,
  SCXTP_OP_ENQUEUE,
  SCXTP_OP_DISPATCH,
  SCXTP_OP_RUNNING,
  SCXTP_OP_STOPPING,
  SCXTP_OP_UPDATE_IDLE,
  SCXTP_OP_INIT_TASK,
  SCXTP_OP_EXIT_TASK,
  SCXTP_OP_SET_CMASK,
  SCXTP_OP_CPUCTL_SET_WEIGHT,
  SCXTP_OP_SUB_ATTACH,
  SCXTP_OP_SUB_DETACH,
  SCXTP_OP_TICK,
  SCXTP_OP_YIELD,
};

struct scxtp_event_op_entry {
  __u32 op;
};

struct scxtp_event_op_exit {
  __u32 op;
};

// shared by the BPF declarations and kernel kfunc registration
#define SCXTP_EVENT_LIST(EVENT) \
  EVENT(init) \
  EVENT(exit) \
  EVENT(cgroup_init_args) \
  EVENT(set_weight_args) \
  EVENT(sub_params_update) \
  EVENT(set_task_weight) \
  EVENT(set_cmask) \
  EVENT(init_task_args) \
  EVENT(exit_task_args) \
  EVENT(cid_topo) \
  EVENT(enqueue_args) \
  EVENT(select_cid_args) \
  EVENT(running) \
  EVENT(stopping) \
  EVENT(op_entry) \
  EVENT(op_exit)
#endif
