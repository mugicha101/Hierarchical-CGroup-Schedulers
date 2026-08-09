// shared definitions between scx_qmap.bpf.c and scx_qmap.c
// defines arena memory layout and shared data structures
// locks should be stored in a separate bpf map, arena memory has no locking primitives
// shared data should be stored in pinned maps for now (TODO: split arena into shared and private sections)

#ifndef __SCX_FFP_H
#define __SCX_FFP_H

#ifdef __BPF__
#include <scx/bpf_arena_common.bpf.h>
#else
#include <linux/types.h>
#include <scx/bpf_arena_common.h>
#endif

#define u128 unsigned __int128

// weight tuple consists of 2 64 bit halves
// upper: misc data (48 bits), cgrp_weight (16 bits)
// lower: is_nmig(1 bit), task_weight (63 bits)
// inverse of lower is used as vtime in global dsq
typedef u128 weight_tuple_t;
#define WT_IS_NMIG_SHIFT 63
#define WT_CGRP_WEIGHT_SHIFT 64
#define WT_MISC_SHIFT 112
const u128 U128_MAX = (((u128)(~0ULL)) << 64) | (u128)(~0ULL);

// extraction macros
#define WT_TASK_WEIGHT(wt) ((u64)wt & 0x7fffffffffffffffull)
#define WT_IS_NMIG(wt) ((bool)((wt) >> WT_IS_NMIG_SHIFT & 1))
#define WT_CGRP_WEIGHT(wt) ((u64)((wt) >> WT_CGRP_WEIGHT_SHIFT) & 0xffffull)
#define WT_MISC(wt) ((u64)((wt) >> WT_MISC_SHIFT))
#define WT_UPPER(wt) ((u64)((wt) >> 64))
#define WT_LOWER(wt) ((u64)(wt))
#define WT_STRIP_MISC(wt) ((wt) & ~(U128_MAX << WT_MISC_SHIFT))

// construction macros
#define WT_LOWER_FROM_FIELDS(task_weight, is_nmig) (((u64)(is_nmig) << WT_IS_NMIG_SHIFT) | (u64)task_weight)
#define WT_UPPER_FROM_FIELDS(cgrp_weight, misc) ((u64)(misc << (WT_MISC_SHIFT-64)) | (u64)cgrp_weight)
#define WT_FROM_HALVES(lower, upper) ((weight_tuple_t)(lower) | ((weight_tuple_t)(upper) << 64))
#define WT_FROM_FIELDS(task_weight, is_nmig, cgrp_weight, misc) (((weight_tuple_t)(task_weight) | ((weight_tuple_t)(is_nmig) << WT_IS_NMIG_SHIFT) | ((weight_tuple_t)(cgrp_weight) << WT_CGRP_WEIGHT_SHIFT) | ((weight_tuple_t)(misc) << WT_MISC_SHIFT)))

// conversion macros
#define WT_VTIME_FROM_LOWER(lower) (~0ULL - (u64)(lower))
#define WT_LOWER_FROM_VTIME(vtime) (~0ULL - (u64)(vtime))

#define SCX_FFP_MAX_CPUS 1024 // >= NR_CPUS
#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_CGROUP_WEIGHT 100 // should match default weight in kernel
#define DEFAULT_TASK_WEIGHT (~0ULL)
#define NTRIALS 10000 // enough trials to be functionally infinite for rare race-conditioned events

// from qmap
#define FFP_CMASK_WORDS	(((SCX_FFP_MAX_CPUS) + 63) / 64 + 1)
struct ffp_cmask {
#ifdef __BPF__
	union {
		struct scx_cmask mask;
		u64 words[FFP_CMASK_WORDS + 2];
	};
#else
	u64 words[FFP_CMASK_WORDS + 2];
#endif
};

// topology data
struct cid_topo_data {
  u32 cpu;

  s32 shard_idx;
  s32 core_idx;
  s32 llc_idx;
  s32 node_idx;
};
struct core_topo_data {
  u32 base_cid;
  u32 nr_cids;
  
  s32 shard_idx;
  s32 llc_idx;
  s32 node_idx;
};
struct shard_topo_data {
  u32 base_cid;
  u32 nr_cids;

  s32 llc_idx;
  s32 node_idx;

  // shard indices ordered by distance from this shard (index 0 is this shard)
  // sorted by same node then same ll3 then shard index
  u32 shard_dist_order[SCX_FFP_MAX_CPUS];
};
struct llc_topo_data {
  u32 base_cid;
  u32 nr_cids;

  u32 base_shard;
  u32 nr_shards;

  s32 node_idx;
};
struct node_topo_data {
  u32 base_cid;
  u32 nr_cids;
  
  u32 base_shard;
  u32 nr_shards;
};
struct topo_data {
  u32 nr_cids;
  u32 nr_shards;
  u32 nr_cores;
  u32 nr_llcs;
  u32 nr_nodes;

  struct cid_topo_data cids[SCX_FFP_MAX_CPUS];
  struct shard_topo_data shards[SCX_FFP_MAX_CPUS];
  struct core_topo_data cores[SCX_FFP_MAX_CPUS];
  struct llc_topo_data llcs[SCX_FFP_MAX_CPUS];
  struct node_topo_data nodes[SCX_FFP_MAX_CPUS];
};

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

struct latency_stat {
  u64 n; // number of samples
  u128 sum; // sum of samples
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

// from qmap
// per task state for the scheduler
// copy of weight stored as well to reduce map lookups (copied from task_weights during enqueue)
// opaque to userspace
// stored on arena memory, allocated via slab allocator
#ifdef __BPF__

struct task_ctx {
	struct task_ctx __arena	*next_free;	/* only valid on free list */
  struct scx_cmask cpus_allowed;	/* per-task affinity in cid space */
  u64 tid;
  weight_tuple_t weight; // weight tuple of task at enqueue time
};
/*
 * Slab stride for task_ctx. cpus_allowed's flex array bits[] overlaps the
 * tail bytes appended per entry; struct_size() gives the actual per-entry
 * footprint.
 */
#define TASK_CTX_STRIDE							\
	struct_size_t(struct task_ctx, cpus_allowed.bits,		\
		      CMASK_NR_WORDS(SCX_FFP_MAX_CPUS))

#else

struct task_ctx;

#endif

typedef struct task_ctx __arena task_ctx_t;

// from qmap
// per subscheduler state
struct sub_sched_ctx {
  u64 cgroup_id;
  u32 weight;

  // TODO: if cid partitioning needed, can use these
  // struct ffp_cmask granted_cids; // cids granted excl to this child
  // struct ffp_cmask prev_granted; // last grant, for delta calculation
};

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
  int can_run[SCX_FFP_MAX_CPUS]; // whether current enqueued task can run on each CPU

  u32 porder[MAX_SUB_SCHEDS]; // cached indices of global porder
  u32 porder_sync_buff[MAX_SUB_SCHEDS]; // buffer for syncing porder
  struct seqlock_local porder_lock;

  // scratch memory
  struct ffp_cmask tmp_cmask;
};

// per scheduler instance arena memory
struct ffp_arena {
  // SCHEDULING STATE
  
  // per-cid data
  struct cid_data cid_data[SCX_FFP_MAX_CPUS];

  // subscheduler state
  struct sub_sched_ctx sub_scheds[MAX_SUB_SCHEDS];
  u64 nr_sub_scheds;

  u32 porder[MAX_SUB_SCHEDS]; // sub indices in decreasing priority order
  struct seqlock_global porder_lock;

  // copy of topology
  struct topo_data topo;

  // CMASK MANAGEMENT
  
  // from qmap
	/* task_ctx slab; allocated and threaded by qmap_init() */
	task_ctx_t *task_ctxs;
	task_ctx_t *task_free_head;

  // from qmap
  /* bpf-internal cmasks (embedded, see struct ffp_cmask) */
	struct ffp_cmask self_cids;	/* cids this node runs its own tasks on */
	struct ffp_cmask idle_cids;	/* idle state of all cids regardless of delegation */

  // per-shard cmasks
  struct ffp_cmask shard_cids[SCX_FFP_MAX_CPUS];

  // latency stats
  struct stats_data stats[SCX_FFP_MAX_CPUS];
};

#endif
