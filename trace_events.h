#ifndef __TRACE_EVENTS_H
#define __TRACE_EVENTS_H

#define TRACING 1

enum sched_trace_event_type {
  SCHED_TRACE_FUNC_START,
  SCHED_TRACE_FUNC_END,
  SCHED_TRACE_TIMER_START,
  SCHED_TRACE_TIMER_CANCEL,
  SCHED_TRACE_CGROUP_INIT_ARGS,
  SCHED_TRACE_SET_WEIGHT_ARGS,
  SCHED_TRACE_ENQUEUE_TASK,
  SCHED_TRACE_DEQUEUE_TASK,
  SCHED_TRACE_SUB_ATTACH_ARGS,
  SCHED_TRACE_SUB_DETACH_ARGS,
  SCHED_TRACE_RUN_TASK,
  SCHED_TRACE_STOP_TASK,
  SCHED_TRACE_KICK_CPU,
  SCHED_TRACE_TRY_SUB_DISPATCH,
  SCHED_TRACE_SUB_PARAMS_UPDATE,
};

// note: each scheduler gets its own ring buffer, so don't need to give scheduler identification
struct sched_trace_event_header {
  enum sched_trace_event_type type; // should be at offset 0
  uint64_t timestamp;
  int core;
};

struct sched_trace_event_func_start {
  struct sched_trace_event_header header;
  char func_name[32]; // dispatch, init, timer_cb, etc
};

struct sched_trace_event_func_end {
  struct sched_trace_event_header header;
  char func_name[32];
  char reason[32];
};

struct sched_trace_event_timer_start {
  struct sched_trace_event_header header;
  uint64_t timer_addr;
  uint64_t duration;
};

struct sched_trace_event_timer_cancel {
  struct sched_trace_event_header header;
  uint64_t timer_addr;
};

struct sched_trace_event_cgroup_init_args {
  struct sched_trace_event_header header;
  uint64_t cgrp_id;
  uint64_t weight;
};

struct sched_trace_event_set_weight_args {
  struct sched_trace_event_header header;
  uint64_t cgrp_id;
  uint64_t weight;
};

struct sched_trace_event_enqueue_task {
  struct sched_trace_event_header header;
  uint64_t pid;
  uint64_t enq_flags;
};

struct sched_trace_event_dequeue_task {
  struct sched_trace_event_header header;
  uint64_t pid;
  uint64_t deq_flags;
};

struct sched_trace_event_sub_attach_args {
  struct sched_trace_event_header header;
  uint64_t cgrp_id;
};

struct sched_trace_event_sub_detach_args {
  struct sched_trace_event_header header;
  uint64_t cgrp_id;
};

struct sched_trace_event_run_task {
  struct sched_trace_event_header header;
  uint64_t pid;
};

struct sched_trace_event_stop_task {
  struct sched_trace_event_header header;
  uint64_t pid;
};

struct sched_trace_event_kick_cpu {
  struct sched_trace_event_header header;
  s32 cpu;
};

struct sched_trace_try_sub_dispatch {
  struct sched_trace_event_header header;
  int idx;
  bool success;
};

struct sched_trace_sub_params_update {
  struct sched_trace_event_header header;
  int idx;
  u64 cgrp_id;
  u64 weight;
};

#if TRACING

#define TRACE_EVENT(STRUCT_TYPE, EVENT_TYPE, ...) \
do { \
  u64 timestamp = bpf_ktime_get_ns(); \
  STRUCT_TYPE *e; \
  e = bpf_ringbuf_reserve(&trace_buff, sizeof(*e), 0); \
  if (!e) bpf_printk("ERROR: trace ring buffer full\n"); \
  else { \
    e->header.timestamp = timestamp; \
    e->header.type = EVENT_TYPE; \
    e->header.core = bpf_get_smp_processor_id(); \
    __VA_ARGS__ \
    bpf_ringbuf_submit(e, 0); \
  } \
} while (0)

#define CREATE_TRACE_BUFF() \
struct { \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, 256 * 1024); \
} trace_buff SEC(".maps");

#else

#define TRACE_EVENT(STRUCT_TYPE, EVENT_TYPE, ...)
#define CREATE_TRACE_BUFF() \
struct { \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, 1); \
} trace_buff SEC(".maps");

#endif

#define TRACE_FUNC_START(NAME) \
TRACE_EVENT(struct sched_trace_event_func_start, SCHED_TRACE_FUNC_START, \
  bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
);

#define TRACE_FUNC_END(NAME, REASON) \
TRACE_EVENT(struct sched_trace_event_func_end, SCHED_TRACE_FUNC_END, \
  bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
  bpf_probe_read_kernel_str(e->reason, 32, REASON); \
);

// HACK FOR RESOLVING LINKER ISSUES (some macros missing)

#if SCX_KICK_IDLE == 0
#undef SCX_KICK_IDLE
#define SCX_KICK_IDLE 0b01
#endif

#if SCX_KICK_PREEMPT == 0
#undef SCX_KICK_PREEMPT
#define SCX_KICK_PREEMPT 0b10
#endif

#if SCX_SLICE_INF == 0
#undef SCX_SLICE_INF
#define SCX_SLICE_INF ~0ULL
#endif

#if SCX_DSQ_LOCAL == 0
#undef SCX_DSQ_LOCAL
#define SCX_DSQ_LOCAL 9223372036854775810ULL
#endif

#if SCX_DSQ_LOCAL_ON == 0
#undef SCX_DSQ_LOCAL_ON
#define SCX_DSQ_LOCAL_ON 13835058055282163712ULL
#endif

#endif