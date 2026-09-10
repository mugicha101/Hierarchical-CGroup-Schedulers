#ifndef __SCX_JLFP_H
#define __SCX_JLFP_H

#ifdef __BPF__
#include <scx/bpf_arena_common.bpf.h>
#else
#include <linux/types.h>
#include <scx/bpf_arena_common.h>
#endif

#include "trace_events.h"
#include "scx_base.h"

// weight tuple consists of 2 64 bit halves
// upper: misc data [127..80], cgrp_weight [79..64]
// lower: is_nmig [63], task_weight [62..0]
// inverse of lower is used as vtime in global dsq
typedef u128 weight_tuple_t;
#define WT_IS_NMIG_SHIFT 63
#define WT_CGRP_WEIGHT_SHIFT 64
#define WT_MISC_SHIFT 80
const u128 U128_MAX = (((u128)(~0ULL)) << 64) | (u128)(~0ULL);

#define WT_TASK_WEIGHT_MASK 0x7fffffffffffffffull
#define WT_IS_NMIG_MASK 1
#define WT_CGRP_WEIGHT_MASK 0xffffull
#define WT_MISC_MASK 0xffffffffffffull

// extraction macros
#define WT_TASK_WEIGHT(wt) ((u64)wt & WT_TASK_WEIGHT_MASK)
#define WT_IS_NMIG(wt) ((bool)((wt >> WT_IS_NMIG_SHIFT) & WT_IS_NMIG_MASK))
#define WT_CGRP_WEIGHT(wt) (u64)((wt >> WT_CGRP_WEIGHT_SHIFT) & WT_CGRP_WEIGHT_MASK)
#define WT_MISC(wt) ((u64)((wt >> WT_MISC_SHIFT) & WT_MISC_MASK))
#define WT_UPPER(wt) ((u64)((wt) >> 64))
#define WT_LOWER(wt) ((u64)(wt))
#define WT_STRIP_MISC(wt) ((wt) & ~(U128_MAX << WT_MISC_SHIFT))

// construction macros
#define WT_LOWER_FROM_FIELDS(task_weight, is_nmig) ((((u64)is_nmig & WT_IS_NMIG_MASK) << WT_IS_NMIG_SHIFT) | ((u64)task_weight & WT_TASK_WEIGHT_MASK))
#define WT_UPPER_FROM_FIELDS(cgrp_weight, misc) ((((u64)misc & WT_MISC_MASK) << (WT_MISC_SHIFT-64)) | ((u64)cgrp_weight & WT_CGRP_WEIGHT_MASK))
#define WT_FROM_HALVES(lower, upper) ((weight_tuple_t)(lower) | ((weight_tuple_t)(upper) << 64))
#define WT_FROM_FIELDS(task_weight, is_nmig, cgrp_weight, misc) (((weight_tuple_t)((u64)task_weight & WT_TASK_WEIGHT_MASK) | ((weight_tuple_t)((u64)is_nmig & WT_IS_NMIG_MASK) << WT_IS_NMIG_SHIFT) | ((weight_tuple_t)((u64)cgrp_weight & WT_CGRP_WEIGHT_MASK) << WT_CGRP_WEIGHT_SHIFT) | ((weight_tuple_t)((u64)misc & WT_MISC_MASK) << WT_MISC_SHIFT)))

// conversion macros
#define WT_VTIME_FROM_LOWER(lower) (~0ULL - (u64)(lower))
#define WT_LOWER_FROM_VTIME(vtime) (~0ULL - (u64)(vtime))

#define DEFAULT_TASK_WEIGHT (~0ULL)

// seqlock implementation
// single writer multiple reader lock-free structure
// allows global data to sync with local data
// can be nested inside another seqlock s.t. syncs only occur if all in the chain are consistent
// parent seqlocks only need to update when update not contained in a single nested seqlock
// need to call sync on nested synclocks, cannot call sync on just parent synclock for data to be protected
struct seqlock_global {
	u64 gen_fin; // incremented when update ends (generation of the last finished update)
	u64 gen_beg; // incremented when update begins (generation of the last started update)
};

struct seqlock_local {
	u64 gen;
};

#ifdef __BPF__

#ifndef smp_rmb
# if defined(__TARGET_ARCH_x86)
#  define smp_rmb() barrier()
# else
#  define smp_rmb() __sync_synchronize()
# endif
#endif

#ifndef smp_wmb
# if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#  define smp_wmb() barrier()
# else
#  define smp_wmb() __sync_synchronize()
# endif
#endif

static __always_inline void seqlock_update_start(struct seqlock_global __arena *g) {
	WRITE_ONCE(g->gen_beg, g->gen_beg + 1);
	smp_wmb();
}

static __always_inline void seqlock_update_end(struct seqlock_global __arena *g) {
	smp_wmb();
	WRITE_ONCE(g->gen_fin, g->gen_fin + 1);
}

#endif

// stats stored per-cid to avoid race conditions
struct stats_data {
  struct latency_stat no_op;
  struct latency_stat pick_cid_prev;
  struct latency_stat pick_cid_idle;
  struct latency_stat pick_cid_search;
  struct latency_stat task_dispatch;
  struct latency_stat sub_dispatch;
  struct latency_stat dispatch;
  struct latency_stat sync_porder_update;
  struct latency_stat sync_porder_fail;
  struct latency_stat sync_porder_cached;
  struct latency_stat init_task;
  struct latency_stat exit_task;
  struct latency_stat select_cid;
  struct latency_stat enqueue;
  struct latency_stat sub_attach;
  struct latency_stat sub_detach;
  struct latency_stat cpuctl_weight_update;
  struct latency_stat set_cmask;
  struct latency_stat running;
  struct latency_stat stopping;
};

struct cid_data {
  // scheduling state
  u32 curr_idx; // index of currently running subscheduler
  int can_run[BASE_MAX_CPUS]; // whether current enqueued task can run on each CPU

  u32 porder[MAX_SUB_SCHEDS]; // cached indices of global porder
  u32 porder_sync_buff[MAX_SUB_SCHEDS]; // buffer for syncing porder
  struct seqlock_local porder_lock;

  // scratch memory
  struct base_cmask_wrapper tmp_cmask;
};

// per scheduler instance arena memory
struct jlfp_arena {
  struct base_arena base;

  // userspace opts
  bool global_search; // search all fully-overlapped shards (fallback on prev shard if no fully-overlapped shards)

  // global task dsq
  u64 dsq_id;

  // SCHEDULING STATE
  
  // per-cid data
  struct cid_data cid_data[BASE_MAX_CPUS];

  u32 porder[MAX_SUB_SCHEDS]; // sub indices in decreasing priority order
  struct seqlock_global porder_lock;

  // latency stats
  struct stats_data stats[BASE_MAX_CPUS];
};

#ifdef __BPF__
#include "scx_jlfp.bpf.h"
#endif

#endif
