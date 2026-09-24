#ifndef __SCX_GEDF_BPF_H
#define __SCX_GEDF_BPF_H

#ifndef __BPF__
#error "This file must be compiled for BPF"
#endif

#ifndef __SCX_GEDF_H
#error "This file must be included from scx_gedf.h"
#endif

// configured task weights, shared through the pinned map across JLFP instances
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_weights SEC(".maps");

// global realtime params map
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_rtp);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_rtp_map SEC(".maps");

// global memmappable job completion flag array
// size: 2^22 * 1 byte = ~4MB
// due to BPF entries requiring minimum 8 bytes, we store 8 1 byte flags per entry
// the userspace program can treat the array as a u8 array and simply index with its tid
// no need for atomic operations since each flag gets a byte
// task sets flag to 1 when job completes, scheduler clears flag to 0 when period advanced
// if flag still 1 after task sets and sleeps, then something went wrong and the task's deadline was not advanced
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, (TID_MAX + 8) / 8);
  __type(key, u32);
  __type(value, u64);
  __uint(map_flags, BPF_F_MMAPABLE);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} job_completion_flags SEC(".maps");

// get and clear job completion flag for task
// we assume the task is not running at this point (should happen in enqueue), so no need for atomic operations
// advances deadline if set
static __always_inline bool check_completion(struct task_struct *p) {
  u32 tid = p->pid;
  u32 idx = tid >> 3;
  u32 off = tid & 0b111;
  u64 *flag_entry = bpf_map_lookup_elem(&job_completion_flags, &idx);
  if (unlikely(!flag_entry)) {
    scx_bpf_error("[GEDF] [CHECK_COMPLETION] Failed to lookup job completion flag for task %d", p->pid);
    return false;
  }

  u8 *flag_byte = (u8 *)flag_entry + off;
  if (*flag_byte == 0) {
    return false;
  }

  // advance deadline
  struct task_rtp *rtp = bpf_task_storage_get(&task_rtp_map, p, 0, 0);
  if (unlikely(!rtp)) {
    // user program probably forgot to set the task_rtp for this task, ignore completion flag
    bpf_printk("[GEDF] [CHECK_COMPLETION] Warning: Failed to lookup realtime params for task %d with job completion flag set", p->pid);
    return false;
  }

  // check curr abs dl
  u64 init_weight = ~0ULL; // abs_dl of 0
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, &init_weight, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (unlikely(!lookup_weight)) { // should only happen if OOM
    scx_bpf_error("[GEDF] [CHECK_COMPLETION] Failed to lookup weight for task %d", p->pid);
    return false;
  }
  u64 abs_dl = ~0ULL - *lookup_weight;
  if (abs_dl == 0) {
    // no prior dl, so this is the first job completion, set dl to now + rel_dl
    u64 now = bpf_ktime_get_ns();
    abs_dl = now + rtp->rel_dl;
  } else if (rtp->is_periodic) {
    // periodic task
    abs_dl += rtp->period;
  } else {
    // sporadic task
    u64 now = bpf_ktime_get_ns();
    u64 period_end = abs_dl + rtp->period - rtp->rel_dl;
    abs_dl = (now < period_end ? period_end : now) + rtp->rel_dl;
  }

  *lookup_weight = ~0ULL - abs_dl;
  *flag_byte = 0;
  return true;
}

// configured weight for selection, enqueue, and reconsidering runnable prev
// from JLFP (TODO: refactor to avoid duplication)
static __always_inline u64 get_task_weight(struct task_struct *p) {
  u64 weight = DEFAULT_TASK_WEIGHT;
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, 0, 0);
  if (lookup_weight) {
    weight = *lookup_weight;
  }
  if (unlikely(weight == 0)) {
    bpf_printk("[WARN] [JLFP] [GET_WEIGHT] Task %d has weight 0, using weight 1 instead", p->pid);
    weight = 1;
  }
  return weight;
}

#endif
