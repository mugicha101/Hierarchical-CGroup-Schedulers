// trace events + latency stats

// only captures low-frequency events (i.e. not every enqueue/dispatch)
// rest can be captured through switch events, latency stats, tracebox, and scx_tracer (if can get working)
// omitted from latency stats wherever possible unless denotes update that is immediately useable by other cpus

// TODO: fix and cleanup SCX_TRACER

// TODO: replace func events with stack emit events
// func events trigger too often and are either all on or off
// instead, track a stack and let the scheduler emit the entire stack where needed for debugging

#ifndef __TRACE_EVENTS_H
  #define __TRACE_EVENTS_H

  #define TRACING 1
  #define SCX_TRACER 0
  #define TRACE_FUNCS 0

  enum sched_trace_event_type {
    SCHED_TRACE_FUNC_START,
    SCHED_TRACE_FUNC_END,
    SCHED_TRACE_INIT,
    SCHED_TRACE_EXIT,
    SCHED_TRACE_CGROUP_INIT_ARGS,
    SCHED_TRACE_SET_WEIGHT_ARGS,
    SCHED_TRACE_SUB_ATTACH_ARGS,
    SCHED_TRACE_SUB_DETACH_ARGS,
    SCHED_TRACE_SUB_PARAMS_UPDATE,
    SCHED_TRACE_SET_TASK_WEIGHT,
    SCHED_TRACE_SET_CMASK,
    SCHED_TRACE_INIT_TASK_ARGS,
    SCHED_TRACE_EXIT_TASK_ARGS,
    SCHED_TRACE_CID_TOPO
  };

  // note: each scheduler gets its own ring buffer, so don't need to give scheduler identification
  struct sched_trace_event_header {
    enum sched_trace_event_type type; // should be at offset 0
    uint64_t timestamp;
    int cid;
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

  struct sched_trace_event_init {
    struct sched_trace_event_header header;
    uint64_t cgrp_id;
  };

  struct sched_trace_event_exit {
    struct sched_trace_event_header header;
    uint64_t cgrp_id;
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

  struct sched_trace_event_sub_attach_args {
    struct sched_trace_event_header header;
    uint64_t cgrp_id;
  };

  struct sched_trace_event_sub_detach_args {
    struct sched_trace_event_header header;
    uint64_t cgrp_id;
  };

  struct sched_trace_sub_params_update {
    struct sched_trace_event_header header;
    int idx;
    u64 cgrp_id;
    u64 weight;
  };

  struct sched_trace_event_set_task_weight {
    struct sched_trace_event_header header;
    uint64_t tid;
    uint64_t weight;
  };

  struct sched_trace_event_set_cmask {
    struct sched_trace_event_header header;
    uint64_t tid;
    uint64_t cmask;
  };

  struct sched_trace_event_init_task_args {
    struct sched_trace_event_header header;
    uint64_t tid;
    bool fork;
  };

  struct sched_trace_event_exit_task_args {
    struct sched_trace_event_header header;
    uint64_t tid;
  };

  struct sched_trace_event_cid_topo {
    struct sched_trace_event_header header;
    int cid;
    int cpu;
    int core;
    int shard;
    int llc;
    int node;
  };

  #if TRACING

    #define TRACE_EVENT(STRUCT_TYPE, EVENT_TYPE, ...) \
    do { \
      if (trace_enabled) { \
        u64 timestamp = bpf_ktime_get_ns(); \
        STRUCT_TYPE *e; \
        e = bpf_ringbuf_reserve(&trace_buff, sizeof(*e), 0); \
        if (!e) bpf_printk("ERROR: trace ring buffer full\n"); \
        else { \
          e->header.timestamp = timestamp; \
          e->header.type = EVENT_TYPE; \
          e->header.cid = bpf_get_smp_processor_id(); \
          __VA_ARGS__ \
          bpf_ringbuf_submit(e, 0); \
        } \
      } \
    } while (0)

    // create buffer + define https://github.com/wagler/scx-tracer.git tracepoints

    #if SCX_TRACER

      #define CREATE_TRACE_BUFF() \
      const volatile bool trace_enabled = false; \
      extern void scx_custom_trace_event_begin(const char *name__str) __ksym; \
      extern void scx_custom_trace_event_end(void) __ksym; \
      extern void scx_custom_trace_event_instant(const char *name__str) __ksym; \
      struct { \
          __uint(type, BPF_MAP_TYPE_RINGBUF); \
          __uint(max_entries, 256 * 1024); \
      } trace_buff SEC(".maps");

    #else

      #define CREATE_TRACE_BUFF() \
      const volatile bool trace_enabled = false; \
      struct { \
          __uint(type, BPF_MAP_TYPE_RINGBUF); \
          __uint(max_entries, 256 * 1024); \
      } trace_buff SEC(".maps");

    #endif

  #else

    #define TRACE_EVENT(STRUCT_TYPE, EVENT_TYPE, ...)
    #define CREATE_TRACE_BUFF() \
    const volatile bool trace_enabled = false; \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, 1); \
    } trace_buff SEC(".maps");

  #endif

  #if SCX_TRACER && TRACE_FUNCS

    #define TRACE_FUNC_START(NAME) \
    scx_custom_trace_event_begin(NAME); \
    TRACE_EVENT(struct sched_trace_event_func_start, SCHED_TRACE_FUNC_START, \
      bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
    );

    #define TRACE_FUNC_END(NAME, REASON) \
    scx_custom_trace_event_end(); \
    TRACE_EVENT(struct sched_trace_event_func_end, SCHED_TRACE_FUNC_END, \
      bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
      bpf_probe_read_kernel_str(e->reason, 32, REASON); \
    );

  #elif TRACE_FUNCS

    #define TRACE_FUNC_START(NAME) \
    TRACE_EVENT(struct sched_trace_event_func_start, SCHED_TRACE_FUNC_START, \
      bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
    );

    #define TRACE_FUNC_END(NAME, REASON) \
    TRACE_EVENT(struct sched_trace_event_func_end, SCHED_TRACE_FUNC_END, \
      bpf_probe_read_kernel_str(e->func_name, 32, NAME); \
      bpf_probe_read_kernel_str(e->reason, 32, REASON); \
    );

  #else

    #define TRACE_FUNC_START(NAME)
    #define TRACE_FUNC_END(NAME, REASON)

  #endif

  #ifndef __BPF__

    // handle tracing events from userspace
    struct callback_ctx {
      char sched_name[32];
    };
    static FILE *trace_fd = NULL;
    static u64 start_time = 0;
    int handle_event(void *ctx, void *data, size_t data_sz) {
      if (!trace_fd) return 0;

      struct callback_ctx *cb_ctx = ctx;
      struct sched_trace_event_header *header = data;
      if (start_time == 0) {
        start_time = header->timestamp;
        fprintf(trace_fd, "start time: %lu\n", start_time);
      }
      fprintf(trace_fd, "[%s] [t=%lu:cid=%d] ", cb_ctx->sched_name, header->timestamp - start_time, header->cid);
      switch (header->type) {
        case SCHED_TRACE_FUNC_START: {
          struct sched_trace_event_func_start *event = data;
          fprintf(trace_fd, "FUNC_START: %s\n", event->func_name);
        } break;
        case SCHED_TRACE_FUNC_END: {
          struct sched_trace_event_func_end *event = data;
          fprintf(trace_fd, "FUNC_END: %s %s\n", event->func_name, event->reason);
        } break;
        case SCHED_TRACE_INIT: {
          struct sched_trace_event_init *event = data;
          fprintf(trace_fd, "INIT: cgrp_id=%lu\n", event->cgrp_id);
        } break;
        case SCHED_TRACE_EXIT: {
          struct sched_trace_event_exit *event = data;
          fprintf(trace_fd, "EXIT: cgrp_id=%lu\n", event->cgrp_id);
        } break;
        case SCHED_TRACE_CGROUP_INIT_ARGS: {
          struct sched_trace_event_cgroup_init_args *event = data;
          fprintf(trace_fd, "CGROUP_INIT_ARGS: cgrp_id=%lu weight=%lu\n", event->cgrp_id, event->weight);
        } break;
        case SCHED_TRACE_SET_WEIGHT_ARGS: {
          struct sched_trace_event_set_weight_args *event = data;
          fprintf(trace_fd, "SET_WEIGHT_ARGS: cgrp_id=%lu weight=%lu\n", event->cgrp_id, event->weight);
        } break;
        case SCHED_TRACE_SUB_ATTACH_ARGS: {
          struct sched_trace_event_sub_attach_args *event = data;
          fprintf(trace_fd, "SUB_ATTACH_ARGS: cgrp_id=%lu\n", event->cgrp_id);
        } break;
        case SCHED_TRACE_SUB_DETACH_ARGS: {
          struct sched_trace_event_sub_detach_args *event = data;
          fprintf(trace_fd, "SUB_DETACH_ARGS: cgrp_id=%lu\n", event->cgrp_id);
        } break;
        case SCHED_TRACE_SUB_PARAMS_UPDATE: {
          struct sched_trace_sub_params_update *event = data;
          fprintf(trace_fd, "SUB_PARAMS_UPDATE: idx=%d cgrp_id=%lu weight=%lu\n", event->idx, event->cgrp_id, event->weight);
        } break;
        case SCHED_TRACE_SET_TASK_WEIGHT: {
          struct sched_trace_event_set_task_weight *event = data;
          fprintf(trace_fd, "SET_TASK_WEIGHT: tid=%lu weight=%lu\n", event->tid, event->weight);
        } break;
        case SCHED_TRACE_SET_CMASK: {
          struct sched_trace_event_set_cmask *event = data;
          fprintf(trace_fd, "SET_CMASK: tid=%lu cmask=%016lx\n", event->tid, event->cmask);
        } break;
        case SCHED_TRACE_INIT_TASK_ARGS: {
          struct sched_trace_event_init_task_args *event = data;
          fprintf(trace_fd, "INIT_TASK_ARGS: tid=%lu fork=%d\n", event->tid, event->fork);
        } break;
        case SCHED_TRACE_EXIT_TASK_ARGS: {
          struct sched_trace_event_exit_task_args *event = data;
          fprintf(trace_fd, "EXIT_TASK_ARGS: tid=%lu\n", event->tid);
        } break;
        case SCHED_TRACE_CID_TOPO: {
          struct sched_trace_event_cid_topo *event = data;
          fprintf(trace_fd, "CID_TOPO: cid=%d cpu=%d core=%d shard=%d llc=%d node=%d\n", event->cid, event->cpu, event->core, event->shard, event->llc, event->node);
        } break;
        default:
          fprintf(trace_fd, "UNKNOWN_EVENT_TYPE\n");
      }
      
      return 0;
    }

  #endif

  // LATENCY STATS
  // measures the latency of a code section
  // note: assumes non-preemptable so in sleepable ops may have issues
  // - increments to n and sum, as well as max updates, are not atomic 
  // TODO: add variant for sleepable ops

  struct latency_stat {
    u64 n; // number of samples
    unsigned __int128 sum; // sum of samples
    u64 max; // worst-case execution time
  };

  #ifdef __BPF__

    struct latency_ctx {
      u64 start_time; // start time + pause duration
      u64 pause_start_time; // start time of the current pause
    };
    static __always_inline void lstat_start(struct latency_ctx *lctx) {
      lctx->start_time = bpf_ktime_get_ns();
    }
    static __always_inline void lstat_record(struct latency_ctx *lctx, struct latency_stat __arena *lstat) {
      u64 lat = bpf_ktime_get_ns() - lctx->start_time;
      ++lstat->n;
      lstat->sum += lat;
      if (unlikely(lat > lstat->max)) {
        lstat->max = lat;
      }
    }
    static __always_inline void lstat_pause(struct latency_ctx *lctx) {
      lctx->pause_start_time = bpf_ktime_get_ns();
    }
    static __always_inline void lstat_resume(struct latency_ctx *lctx) {
      lctx->start_time += bpf_ktime_get_ns() - lctx->pause_start_time;
    }
    
  #endif

  // HACK FOR RESOLVING LINKER ISSUES (some macros missing)

  #ifdef __BPF__

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

    #if SCX_ENQ_WAKEUP == 0
    #undef SCX_ENQ_WAKEUP
    #define SCX_ENQ_WAKEUP 1ULL
    #endif

    #if SCX_ENQ_LAST == 0
    #undef SCX_ENQ_LAST
    #define SCX_ENQ_LAST 2199023255552ULL
    #endif

  #endif

#endif