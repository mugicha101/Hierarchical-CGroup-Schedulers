// macros to make adding new tracepoints easier
// uses fixed-size ftrace events, which are lightweight and emitted to per-cpu buffers
// ensure using TSC and not HPET timestamps, since TSC only takes ~40ns while HPET takes a lot longer
// note: tracepoints get CPU not CID, CID --> CPU mapping emitted in root init

#ifndef TRACE_EVENTS__HELPERS_H
#define TRACE_EVENTS__HELPERS_H

#ifdef __BPF__

#include <bpf/bpf_helpers.h>

#ifndef SCXTP_TRACING
#define SCXTP_TRACING 1
#endif
#ifndef SCXTP_HOTPATH_TRACING
#define SCXTP_HOTPATH_TRACING 0
#endif
#ifndef SCXTP_BACKTRACE
#define SCXTP_BACKTRACE 0
#endif

#define SCXTP_DECLARE_KFUNC(NAME) \
  extern void scxtp_emit_##NAME(__u64 sched_cgrp_id, \
                                const struct scxtp_event_##NAME *event) __ksym __weak;

#if SCXTP_TRACING

// skip payload preparation when the optional module was absent at load time
// initialize the full payload, including padding, before calling the kfunc
#define SCXTP_EMIT(NAME, SCHED_CGRP_ID, ...) \
do { \
  if (bpf_ksym_exists(scxtp_emit_##NAME)) { \
    struct scxtp_event_##NAME scxtp_event = {}; \
    struct scxtp_event_##NAME *e = &scxtp_event; \
    __VA_ARGS__ \
    scxtp_emit_##NAME((SCHED_CGRP_ID), e); \
  } \
} while (0)

#else
#define SCXTP_EMIT(NAME, SCHED_CGRP_ID, ...) do {} while (0)
#endif

#if SCXTP_HOTPATH_TRACING
#define SCXTP_EMIT_HOTPATH(NAME, SCHED_CGRP_ID, ...) \
  SCXTP_EMIT(NAME, SCHED_CGRP_ID, __VA_ARGS__)
#else
#define SCXTP_EMIT_HOTPATH(NAME, SCHED_CGRP_ID, ...) do {} while (0)
#endif

#if SCXTP_BACKTRACE

#ifndef SCXTP_BACKTRACE_MAX_DEPTH
#define SCXTP_BACKTRACE_MAX_DEPTH 16
#endif
#ifndef SCXTP_BACKTRACE_FRAME_SIZE
#define SCXTP_BACKTRACE_FRAME_SIZE 128
#endif

_Static_assert(SCXTP_BACKTRACE_MAX_DEPTH > 0, "backtrace depth must be positive");
_Static_assert(SCXTP_BACKTRACE_FRAME_SIZE >= 16, "backtrace frames must hold error text");

struct scxtp_backtrace_frame {
  char text[SCXTP_BACKTRACE_FRAME_SIZE];
  __u8 truncated;
};

struct scxtp_backtrace_state {
  __u32 depth;
  __u32 overflow;
  __u32 underflows;
  struct scxtp_backtrace_frame frames[SCXTP_BACKTRACE_MAX_DEPTH];
};

// one stack per cpu; reset at the start of each non-sleeping, non-reentrant op
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scxtp_backtrace_state);
} scxtp_backtrace SEC(".maps");

static __always_inline struct scxtp_backtrace_state *scxtp_backtrace_get(void)
{
  const __u32 key = 0;
  return bpf_map_lookup_elem(&scxtp_backtrace, &key);
}

#define SCXTP_BACKTRACE_RESET() \
do { \
  struct scxtp_backtrace_state *scxtp_bt = scxtp_backtrace_get(); \
  if (scxtp_bt) { \
    scxtp_bt->depth = 0; \
    scxtp_bt->overflow = 0; \
    scxtp_bt->underflows = 0; \
  } \
} while (0)

// format arguments on entry so later mutations do not change saved frames
#define SCXTP_FUNC_ENTRY(FMT, ...) \
do { \
  struct scxtp_backtrace_state *scxtp_bt = scxtp_backtrace_get(); \
  if (scxtp_bt) { \
    if (scxtp_bt->overflow || scxtp_bt->depth >= SCXTP_BACKTRACE_MAX_DEPTH) { \
      scxtp_bt->overflow++; \
    } else { \
      __u32 scxtp_idx = scxtp_bt->depth; \
      struct scxtp_backtrace_frame *scxtp_frame = &scxtp_bt->frames[scxtp_idx]; \
      scxtp_frame->text[0] = '\0'; \
      long scxtp_len = BPF_SNPRINTF(scxtp_frame->text, sizeof(scxtp_frame->text), \
                                   "%s(" FMT ")", __func__, ##__VA_ARGS__); \
      if (scxtp_len < 0) \
        __builtin_memcpy(scxtp_frame->text, "<format error>", sizeof("<format error>")); \
      scxtp_frame->text[sizeof(scxtp_frame->text) - 1] = '\0'; \
      scxtp_frame->truncated = scxtp_len > (long)sizeof(scxtp_frame->text); \
      scxtp_bt->depth = scxtp_idx + 1; \
    } \
  } \
} while (0)

#define SCXTP_FUNC_EXIT() \
do { \
  struct scxtp_backtrace_state *scxtp_bt = scxtp_backtrace_get(); \
  if (scxtp_bt) { \
    if (scxtp_bt->overflow) \
      scxtp_bt->overflow--; \
    else if (scxtp_bt->depth) \
      scxtp_bt->depth--; \
    else \
      scxtp_bt->underflows++; \
  } \
} while (0)

static __always_inline void scxtp_backtrace_dump(void)
{
  struct scxtp_backtrace_state *scxtp_bt = scxtp_backtrace_get();
  if (!scxtp_bt) {
    bpf_printk("scxtp backtrace unavailable");
    return;
  }

  __u32 depth = scxtp_bt->depth;
  if (depth > SCXTP_BACKTRACE_MAX_DEPTH)
    depth = SCXTP_BACKTRACE_MAX_DEPTH;
  bpf_printk("scxtp cpu=%u depth=%u omitted=%u unmatched_exits=%u",
             bpf_get_smp_processor_id(), depth, scxtp_bt->overflow, scxtp_bt->underflows);

  // bounded iteration keeps the buffer size independent of the BPF stack limit
  for (__u32 i = 0; i < SCXTP_BACKTRACE_MAX_DEPTH; i++) {
    if (i >= depth)
      break;
    __u32 idx = depth - 1 - i;
    if (idx >= SCXTP_BACKTRACE_MAX_DEPTH)
      break;
    struct scxtp_backtrace_frame *frame = &scxtp_bt->frames[idx];
    bpf_printk("scxtp #%u %s%s", i + scxtp_bt->overflow, frame->text,
               frame->truncated ? " [truncated]" : "");
  }
}

// dump the instrumented call chain without depending on structured tracepoints
#define SCXTP_BACKTRACE_DUMP(FMT, ...) \
do { \
  bpf_printk("scxtp backtrace at %s: " FMT, __func__, ##__VA_ARGS__); \
  scxtp_backtrace_dump(); \
} while (0)

#define SCXTP_BACKTRACE_DUMP_IF(COND, ...) \
do { \
  if (COND) \
    SCXTP_BACKTRACE_DUMP(__VA_ARGS__); \
} while (0)

#else
#define SCXTP_BACKTRACE_RESET() do {} while (0)
#define SCXTP_FUNC_ENTRY(FMT, ...) do {} while (0)
#define SCXTP_FUNC_EXIT() do {} while (0)
#define SCXTP_BACKTRACE_DUMP(FMT, ...) do {} while (0)
#define SCXTP_BACKTRACE_DUMP_IF(COND, ...) do {} while (0)
#endif

#else

#define SCXTP_FIELD(TYPE, NAME) __field(TYPE, NAME)
#define SCXTP_ARRAY(TYPE, NAME, LENGTH) __array(TYPE, NAME, LENGTH)
#define SCXTP_STRING(NAME, LENGTH) __array(char, NAME, LENGTH)

#define SCXTP_COPY_FIELD(TYPE, NAME) \
  _Static_assert(sizeof(__entry->NAME) == sizeof(event->NAME), "trace field size mismatch"); \
  __entry->NAME = event->NAME;
#define SCXTP_COPY_ARRAY(TYPE, NAME, LENGTH) \
  _Static_assert(sizeof(__entry->NAME) == sizeof(event->NAME), "trace array size mismatch"); \
  memcpy(__entry->NAME, event->NAME, sizeof(__entry->NAME));
#define SCXTP_COPY_STRING(NAME, LENGTH) \
  SCXTP_COPY_ARRAY(char, NAME, LENGTH) \
  __entry->NAME[sizeof(__entry->NAME) - 1] = '\0';

// FIELDS supplies FIELD, ARRAY, and STRING callbacks for declaration and copy
#define SCXTP_DEFINE_EVENT(NAME, FIELDS, FORMAT, ...) \
  TRACE_EVENT(scxtp_##NAME, \
    TP_PROTO(__u64 sched_cgrp_id, const struct scxtp_event_##NAME *event), \
    TP_ARGS(sched_cgrp_id, event), \
    TP_STRUCT__entry( \
      __field(__u64, sched_cgrp_id) \
      FIELDS(SCXTP_FIELD, SCXTP_ARRAY, SCXTP_STRING) \
    ), \
    TP_fast_assign( \
      __entry->sched_cgrp_id = sched_cgrp_id; \
      FIELDS(SCXTP_COPY_FIELD, SCXTP_COPY_ARRAY, SCXTP_COPY_STRING) \
    ), \
    TP_printk("sched_cgrp_id=%llu " FORMAT, \
      (unsigned long long)__entry->sched_cgrp_id, __VA_ARGS__) \
  )

#define SCXTP_DEFINE_KFUNC(NAME) \
  __bpf_kfunc void scxtp_emit_##NAME(__u64 sched_cgrp_id, \
                                    const struct scxtp_event_##NAME *event) \
  { \
    trace_scxtp_##NAME(sched_cgrp_id, event); \
  }
#define SCXTP_KFUNC_ID(NAME) BTF_ID_FLAGS(func, scxtp_emit_##NAME)

#endif

#endif
