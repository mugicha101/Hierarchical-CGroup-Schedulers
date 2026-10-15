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

// expose the BPF build settings to the userspace loader
const bool scxtp_lowfreq_compiled = SCXTP_TRACING;
const bool scxtp_hotpath_compiled = SCXTP_HOTPATH_TRACING;

// set per scheduler before BPF load (disabled by default)
const volatile bool scxtp_enabled = false;

#define SCXTP_DECLARE_KFUNC(NAME) \
  extern void scxtp_emit_##NAME(__u64 sched_cgrp_id, \
                                const struct scxtp_event_##NAME *event) __ksym __weak;

#if SCXTP_TRACING

// skip payload preparation when disabled or the optional module was absent at load time
// initialize the full payload, including padding, before calling the kfunc
#define SCXTP_EMIT(NAME, SCHED_CGRP_ID, ...) \
do { \
  if (scxtp_enabled && bpf_ksym_exists(scxtp_emit_##NAME)) { \
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
