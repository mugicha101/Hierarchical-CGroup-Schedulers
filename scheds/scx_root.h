// header file for generic root setup
// this header can be shared with userspace
// includes scx_root.bpf.h if targeting BPF

#ifndef __SCX_ROOT_H
#define __SCX_ROOT_H

#define SCX_MAX_CPUS 1024  // >= NR_CPUS
#define MAX_SUB_SCHEDS 64 // must be power of 2
#define NTRIALS 10000 // enough trials to be functionally infinite for rare race-conditioned events

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

// ensure that SCX_MAX_CPUS >= NR_CPUS
// ensure that BPF and userspace are seeing the same size for qmap_cmask
#define SCX_ROOT_ASSERTIONS \
_Static_assert(SCX_MAX_CPUS >= NR_CPUS, "SCX_MAX_CPUS must be >= NR_CPUS"); \
_Static_assert(SCX_CMASK_WORDS == CMASK_NR_WORDS(NR_CPUS), "SCX_CMASK_WORDS must equal CMASK_NR_WORDS(NR_CPUS)"); \
_Static_assert(sizeof(struct scx_cmask_wrapper) ==s truct_size_t(struct scx_cmask, bits, SCX_CMASK_WORDS), "scx_full_cmask must be exactly sized to back a full scx_cmask");


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

#ifdef __BPF__
#include "scx_root.bpf.h"
#endif

#endif
