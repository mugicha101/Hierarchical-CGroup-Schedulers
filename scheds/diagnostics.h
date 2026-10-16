// hook for diagnostics
#ifndef __DIAGNOSTICS_H
#define __DIAGNOSTICS_H

// TRACING
// include tracing dependencies in scheds/trace
#ifdef __BPF__
#include "trace/events.bpf.h"
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

  #ifndef SCX_LATENCY_STATS
  #define SCX_LATENCY_STATS 1
  #endif

  struct latency_ctx {
    u64 start_time; // start time + pause duration
    u64 pause_start_time; // start time of the current pause
  };
  static __always_inline void lstat_start(struct latency_ctx *lctx) {
    #if SCX_LATENCY_STATS
    lctx->start_time = bpf_ktime_get_ns();
    #endif
  }
  static __always_inline void lstat_record(struct latency_ctx *lctx, struct latency_stat __arena *lstat) {
    #if SCX_LATENCY_STATS
    u64 lat = bpf_ktime_get_ns() - lctx->start_time;
    ++lstat->n;
    lstat->sum += lat;
    if (unlikely(lat > lstat->max)) {
      lstat->max = lat;
    }
    #endif
  }
  static __always_inline void lstat_pause(struct latency_ctx *lctx) {
    #if SCX_LATENCY_STATS
    lctx->pause_start_time = bpf_ktime_get_ns();
    #endif
  }
  static __always_inline void lstat_resume(struct latency_ctx *lctx) {
    #if SCX_LATENCY_STATS
    lctx->start_time += bpf_ktime_get_ns() - lctx->pause_start_time;
    #endif
  }

#endif

#endif
