#ifndef __SCX_ROOT_H
#define __SCX_ROOT_H

#define SCX_MAX_CPUS 1024  // >= NR_CPUS
#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_CGROUP_WEIGHT 100 // should match default weight in kernel
#define NTRIALS 10000 // enough trials to be functionally infinite for rare race-conditioned events
#define SCX_POLICY_TASK_CTX_SIZE 1024 // >= largest policy's task context
#define u128 unsigned __int128
#define bpf_assert(cond) if (!(cond)) scx_bpf_error(#cond);

// taken from qmap for getting arena memory through verifier
#define SCX_TOUCH_ARENA() do { asm volatile("" :: "r"(&arena)); } while (0)

// from qmap
#define SCX_CMASK_WORDS	(((SCX_MAX_CPUS) + 63) / 64 + 1)
struct scx_cmask_wrapper {
#ifdef __BPF__
	union {
		struct scx_cmask mask;
		u64 words[SCX_CMASK_WORDS + 2];
	};
#else
	u64 words[SCX_CMASK_WORDS + 2];
#endif
};

// from qmap
// per subscheduler state
struct sub_sched_ctx {
  u64 cgroup_id;
  u32 weight;

  // TODO: if cid partitioning needed, can use these
  // struct scx_cmask_wrapper granted_cids; // cids granted excl to this child
  // struct scx_cmask_wrapper prev_granted; // last grant, for delta calculation
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
  u32 shard_dist_order[SCX_MAX_CPUS];
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

  struct cid_topo_data cids[SCX_MAX_CPUS];
  struct shard_topo_data shards[SCX_MAX_CPUS];
  struct core_topo_data cores[SCX_MAX_CPUS];
  struct llc_topo_data llcs[SCX_MAX_CPUS];
  struct node_topo_data nodes[SCX_MAX_CPUS];
};

struct task_ctx;
typedef struct task_ctx __arena task_ctx_t;

// per scheduler instance arena memory
struct scx_arena {
  u64 cgroup_id;
  u64 self_cgroup_weight;

  // subscheduler state
  struct sub_sched_ctx sub_scheds[MAX_SUB_SCHEDS];
  u64 nr_sub_scheds;

  // local copy of topology
  struct topo_data topo;

  // CMASK MANAGEMENT
	
  // initialized in scx_init()
  // pushed/popped in scx_init_task() and scx_task_exit_task()
  // protected by scx_arena_task_ctx_slab_lock
  u64 max_tasks;
	task_ctx_t *task_ctxs;
	task_ctx_t *task_free_head;

  /* bpf-internal cmasks (embedded, see struct scx_cmask_wrapper) */
	struct scx_cmask_wrapper self_cids;	/* cids this node runs its own tasks on */
	struct scx_cmask_wrapper idle_cids;	/* idle state of all cids regardless of delegation */

  // per-shard cmasks
  struct scx_cmask_wrapper shard_cids[SCX_MAX_CPUS];
};

#ifdef __BPF__
#include "scx_root.bpf.h"
#endif

#endif
