#ifndef __SCX_GEDF_BPF_H
#define __SCX_GEDF_BPF_H

#ifndef __BPF__
#error "This file must be compiled for BPF"
#endif

#ifndef __SCX_GEDF_H
#error "This file must be included from scx_gedf.h"
#endif

// returns new weight of task based on dl
// note: weight = U64_MAX - abs_dl
static __always_inline u64 update_task_dl(struct task_struct *p, u64 now_ts) {
  const struct task_rtp *lookup_rtp = bpf_task_storage_get(&task_rtp_map, p, 0, 0);
  if (!lookup_rtp) return 1; // non-realtime tasks have minimal weight

  // TODO: small race possible due to non-atomic updates to rtp
  // avoided by user setting rtps before moving task to scx

  struct task_rtp rtp = *lookup_rtp;

  u64 weight = ~0ULL; // new task dl set to time 0
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, &weight, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (unlikely(!lookup_weight)) return 1; // for verifier, should not happen

  weight = *lookup_weight;
  u64 abs_dl = ~0ULL - weight;
  if (likely(now_ts < abs_dl)) return weight; // dl not reached, no dl update needed
  
  if (abs_dl == 0) {
    // new tasks abs dl set to now + rel_dl
    abs_dl = now_ts + rtp.rel_dl;
  } else if (rtp.is_periodic) {
    // periodic tasks increment their abs dl by period until abs dl in the future
    // can do this in const time by using ceil division
    u64 incr_periods = 1ULL + (now_ts - abs_dl) / rtp.period;
    abs_dl += incr_periods * rtp.period;
  } else {
    // sporadic task abs dls set to max(now, period end) + rel dl
    u64 period_end = abs_dl + rtp.period - rtp.rel_dl;
    abs_dl = (now_ts > period_end ? now_ts : period_end) + rtp.rel_dl;
  }
  
  return *lookup_weight = weight = ~0ULL - abs_dl;
}

// calculate slice based on task_weight
static __always_inline u64 get_slice(struct gedf_arena __arena *a, u64 task_weight, u64 now_ts) {
  if (task_weight <= 1) return a->jlfp.slice; // non-realtime 

  u64 abs_dl = ~0ULL - task_weight;
  bpf_assert(abs_dl > now_ts);
  u64 dt = abs_dl - now_ts;
  return dt > a->jlfp.slice ? a->jlfp.slice : dt;
}

#endif
