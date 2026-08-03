#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "trace_events.h"
#include "scx_ffp.h"

CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// fast lockless version of job-level fixed priority scheduler
// ignores certain race conditions in favor of performance
// prioritized by weight (higher weight = higher priority)
// weights can be modified at runtime via the cgroup fs interface (/sys/fs/bpf/task_weights) but tasks must be reenqueued for their weight to update

// if tasks assigned to scheduler, they are prioritized over sub cgroup schedulers for now

// cgroup scheduling:
// assumes no cgroups have same weight
// task weight only matters when cgroup weights match
// works same as scx_fp

// task scheduling:
// assumes all tasks share same cpu set
// for now, ignores race conditions in favor of less locks and cpuset changes with non-migrateable tasks
// uses global vtime dsq for tasks that are not high enough priority to run
// during select_cid/enqueue, if task can preempt lower priority task / idle cpu, will kick it
// during dispatch, finds highest priority task in global dsq to run
// during running/stopping, associates the cgroup weight + task weight to the current cpu for future select_cid/enqueue decisions (ignores race conditions caused by gap between dsq pop and setting)
//    assumes this is done by all subschedulers during running, since using bpf helper functions to pull cgroup info is slow (requires RCU lock)
//    can also be done during enqueue into local dsq to reduce desync time and thus race conditions, but not necessary
//    to resolve race conditions between various entities moving to local dsq, should always update it in running/stopping regardless
// cpu search order:
//     last cpu if idle
//     nearest idle cpu
//     min cpu to preempt based on weight with tie breaks: last cpu > cpu in same numa node > any cpu
// this search is done in either select_cid or enqueue
// if cpu found, enqueues to local dsq directly rather than going through dispatch

// TODO: update kernel and use SCX_ENQ_IMMED to resolve race condition where both dispatch and enqueue move to local dsq, causing multiple tasks in local dsq

const volatile u64 cgroup_id;
const volatile u32 max_tasks;
u64 self_cgroup_weight;
u64 slice = 1000000ULL; // 1ms

#define DEBUG 1

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif

#ifndef SCHED_RR
#define SCHED_RR 2
#endif

#define bpf_assert(cond) if (!(cond)) scx_bpf_error(#cond);

// taken from qmap for getting arena memory through verifier
// so far doesn't seem to be needed yet though
#define FFP_TOUCH_ARENA() do { asm volatile("" :: "r"(&arena)); } while (0)

// from qmap
// max number of times to try idle claim
#define IDLE_PICK_RETRIES	16

UEI_DEFINE(uei);

// data only accessed by its own CPU, no locking needed
// local to this scheduler
// struct cpu_sched_state {
//   __u64 local_gen; // for checking if global_gen updated
//   u32 curr_idx; // index of currently running subscheduler
//   u64 priority[MAX_SUB_SCHEDS]; // cached priorities of subs
//   int porder[MAX_SUB_SCHEDS]; // cached indices of subs in decreasing priority order
//   int can_run[NR_CPUS]; // whether current enqueued task can run on each CPU
// };

// data shared between all cores
// local to scheduler
// struct global_data {
//   // concurrency: single writer, multiple readers
//   struct bpf_spin_lock global_subs_write_lock;
//   struct global_sub_params global_subs[MAX_SUB_SCHEDS];
//   __u64 global_gen; // incremented after new data written to
// };
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __uint(max_entries, 1);
//   __type(key, u32);
//   __type(value, struct global_data);
// } global SEC(".maps");

// data tracking weight of task running on each cid
// shared between all cores and schedulers
// updated in dispatch+running/stopping (can be desynced but should sync eventually)
// TODO: replace with per-shard
// struct global_running_data {
//   weight_tuple_t cid_running_weight[NR_CPUS];
// };
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __uint(max_entries, 1);
//   __type(key, u32);
//   __type(value, struct global_running_data);
//   __uint(pinning, LIBBPF_PIN_BY_NAME);
// } global_running SEC(".maps");

// inline struct global_running_data *fetch_running() {
//   const u32 idx = 0;
//   return bpf_map_lookup_elem(&global_running, &idx);
// }

// from qmap
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 16);		/* upper bound in pages */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__ulong(map_extra, 0x1ull << 32);	/* user/BPF mmap base */
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

struct ffp_arena __arena_global aa;

/* ensure that BPF and userspace are seeing the same size for qmap_cmask */
_Static_assert(FFP_CMASK_WORDS == CMASK_NR_WORDS(SCX_FFP_MAX_CPUS),
	       "FFP_CMASK_WORDS must equal CMASK_NR_WORDS(SCX_FFP_MAX_CPUS)");
_Static_assert(sizeof(struct ffp_cmask) ==
	       struct_size_t(struct scx_cmask, bits, FFP_CMASK_WORDS),
	       "ffp_cmask must be exactly sized to back a full scx_cmask");

// id of global vtime-based task dsq (non-migrateable per-cpu dsqs stored at dsq_id + 1 + cpu)
// updated to cgroup_id in init
u64 dsq_id = 0;

// global weight of each task (should not change after enqueue due to fixed priority, re-enqueue if does change)
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_weights SEC(".maps");

// points to task_ctx on arena memory for each task
struct task_ctx_ptr {
  task_ctx_t *tctx;
};
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_ctx_ptr);
} task_ctx_ptr_map SEC(".maps");

// from qmap
/* Protects the task_ctx slab free list. */
__hidden struct bpf_res_spin_lock aa_task_lock SEC(".data.aa_task_lock");

static __always_inline task_ctx_t *get_task_ctx(struct task_struct *p) {

	FFP_TOUCH_ARENA();

  struct task_ctx_ptr *ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, 0, 0);
  return ptr ? ptr->tctx : NULL;
}

// topology data shared by all schedulers
// initialized by root init
// copied by all schedulers on init for quicker access
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct topo_data);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} topo SEC(".maps");

static __always_inline struct topo_data *fetch_global_topo() {
  const u32 idx = 0;
  return bpf_map_lookup_elem(&topo, &idx);
}

// per-shard context
// used during search to find min-weight task
// also stores running weights per-cid
// protected by lock
// shared by all priority schedulers
struct shard_ctx {
  weight_tuple_t cid_running_weight[SCX_CID_SHARD_MAX_CPUS];
  weight_tuple_t max_running_weight; // atomically updated but may be stale if reading without lock
  struct bpf_res_spin_lock lock;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, SCX_FFP_MAX_CPUS);
  __type(key, u32);
  __type(value, struct shard_ctx);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ffp_shard_ctx_map SEC(".maps");

static __always_inline weight_tuple_t get_running_weight(u32 cid) {
  u32 shard_idx = aa.topo.cids[cid & (SCX_FFP_MAX_CPUS - 1)].shard_idx;
  struct shard_ctx *sctx = bpf_map_lookup_elem(&ffp_shard_ctx_map, &shard_idx);
  u32 shard_offset = cid - aa.topo.shards[shard_idx].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return 0; // for verifier, should not happen

  return sctx->cid_running_weight[shard_offset];
}

static __always_inline void set_running_weight(u32 cid, weight_tuple_t wt) {
  u32 shard_idx = aa.topo.cids[cid & (SCX_FFP_MAX_CPUS - 1)].shard_idx;
  struct shard_ctx *sctx = bpf_map_lookup_elem(&ffp_shard_ctx_map, &shard_idx);
  u32 shard_offset = cid - aa.topo.shards[shard_idx].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  if (unlikely(bpf_res_spin_lock(&sctx->lock))) {
    scx_bpf_error("failed to acquire shard lock");
    return;
  }
  sctx->cid_running_weight[shard_offset] = wt;
  bpf_res_spin_unlock(&sctx->lock);
}

// dump helper
static __always_inline u64 cmask_to_int(struct scx_cmask __arena *cmask) {
  u64 out = 0;
  u32 i;
  bpf_for(i, cmask->base, cmask->nr_cids + cmask->base) {
    if (cmask_test(i, cmask)) {
      out |= (1ULL << i);
    }
  }
  return out;
}

// init global structures
// TODO: move to base root scheduler for all hierarchical schedulers to pull from
static __always_inline void root_init() {
  u32 nr_cids = scx_bpf_nr_cids() & (SCX_FFP_MAX_CPUS-1);
  bpf_printk("[INFO] [FP] [INIT] nr_cids=%u", nr_cids);
  
  // init topology
  // note: cannot assume zero initialized due to pinning
  struct topo_data *topo = fetch_global_topo();
  if (unlikely(!topo)) return; // for verifier, should not happen
  
  topo->nr_cids = nr_cids;
  topo->nr_cores = 0;
  topo->nr_shards = 0;
  topo->nr_llcs = 0;
  topo->nr_nodes = 0;
  u32 cid;
  u32 no_topo_core = SCX_FFP_MAX_CPUS;
  u32 no_topo_llc = SCX_FFP_MAX_CPUS;
  u32 no_topo_node = SCX_FFP_MAX_CPUS;
  bpf_for(cid, 0, nr_cids) {
    struct scx_cid_topo t = {};
    scx_bpf_cid_topo(cid, &t);
    bpf_printk("[INFO] [FP] [INIT] core_cid=%u core_idx=%d llc_cid=%d llc_idx=%d node_cid=%d node_idx=%d shard_cid=%d shard_idx=%d",
      t.core_cid,
      t.core_idx,
      t.llc_cid,
      t.llc_idx,
      t.node_cid,
      t.node_idx,
      t.shard_cid,
      t.shard_idx
    );

    // since cids with core/llc/node unknown (-1) are at back
    // we can allocate a core/llc/node for them at the back upon seeing first
    if (t.core_idx == -1) {
      if (no_topo_core == SCX_FFP_MAX_CPUS) {
        no_topo_core = topo->nr_cores;
        no_topo_llc = topo->nr_llcs;
        no_topo_node = topo->nr_nodes;
      }
      t.core_idx = no_topo_core;
      t.llc_idx = no_topo_llc;
      t.node_idx = no_topo_node;
    }

    struct cid_topo_data *cid_td = &topo->cids[cid];
    struct core_topo_data *core_td = &topo->cores[t.core_idx & (SCX_FFP_MAX_CPUS-1)];
    struct shard_topo_data *shard_td = &topo->shards[t.shard_idx & (SCX_FFP_MAX_CPUS-1)];
    struct llc_topo_data *llc_td = &topo->llcs[t.llc_idx & (SCX_FFP_MAX_CPUS-1)];
    struct node_topo_data *node_td = &topo->nodes[t.node_idx & (SCX_FFP_MAX_CPUS-1)];

    core_td->nr_cids++;
    shard_td->nr_cids++;
    llc_td->nr_cids++;
    node_td->nr_cids++;

    cid_td->cpu = scx_bpf_cid_to_cpu(cid);
    cid_td->shard_idx = t.shard_idx;
    cid_td->core_idx = t.core_idx;
    cid_td->llc_idx = t.llc_idx;
    cid_td->node_idx = t.node_idx;

    if (t.core_idx < topo->nr_cores) {
      bpf_assert(core_td->base_cid == t.core_cid);
      continue;
    }
    bpf_assert(t.core_idx == topo->nr_cores);
    topo->nr_cores++;
    core_td->base_cid = t.core_cid;
    core_td->nr_cids = 1;
    bpf_printk("[INFO] [FP] [INIT] new core: %lld", t.core_idx);

    if (t.shard_idx < topo->nr_shards) {
      bpf_assert(shard_td->base_cid == t.shard_cid);
      continue;
    }
    bpf_assert(t.shard_idx == topo->nr_shards);
    llc_td->nr_shards++;
    node_td->nr_shards++;
    topo->nr_shards++;
    shard_td->base_cid = t.shard_cid;
    shard_td->nr_cids = 1;
    bpf_printk("[INFO] [FP] [INIT] new shard: %lld", t.shard_idx);

    if (t.llc_idx < topo->nr_llcs) {
      bpf_assert(llc_td->base_cid == t.llc_cid);
      continue;
    }
    bpf_assert(t.llc_idx == topo->nr_llcs);
    topo->nr_llcs++;
    llc_td->base_cid = t.llc_cid;
    llc_td->base_shard = t.shard_idx;
    llc_td->nr_cids = 1;
    llc_td->nr_shards = 1;
    bpf_printk("[INFO] [FP] [INIT] new llc: %lld", t.llc_idx);

    if (t.node_idx < topo->nr_nodes) {
      bpf_assert(node_td->base_cid == t.node_cid);
      continue;
    }
    bpf_assert(t.node_idx == topo->nr_nodes);
    topo->nr_nodes++;
    node_td->base_cid = t.node_cid;
    node_td->base_shard = t.shard_idx;
    node_td->nr_cids = 1;
    node_td->nr_shards = 1;
    bpf_printk("[INFO] [FP] [INIT] new node: %lld", t.node_idx);
  }
  bpf_printk("[INFO] [FP] [INIT] topo nr_cids=%u nr_cores=%u nr_shards=%u nr_llcs=%u nr_nodes=%u",
    topo->nr_cids,
    topo->nr_cores,
    topo->nr_shards,
    topo->nr_llcs,
    topo->nr_nodes
  );

  // calc shard_dist_order for each shard
  u32 i;
  u32 nr_shards = topo->nr_shards;
  bpf_for(i, 0, nr_shards) {
    struct shard_topo_data *shard_td = &topo->shards[i & (SCX_FFP_MAX_CPUS-1)];
    struct llc_topo_data *llc_td = &topo->llcs[shard_td->llc_idx & (SCX_FFP_MAX_CPUS-1)];
    struct node_topo_data *node_td = &topo->nodes[shard_td->node_idx & (SCX_FFP_MAX_CPUS-1)];

    
    shard_td->shard_dist_order[0] = i;
    
    // same llc: [1, llc->nr_shards-1]
    u32 j;
    u32 off = i - llc_td->base_shard;
    u32 end = llc_td->nr_shards - 1;
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(1 + j) & (SCX_FFP_MAX_CPUS-1)] = llc_td->base_shard + j + (j < off ? (u32)0 : (u32)1);
    }

    // same node: [llc->nr_shards, node->nr_shards - llc->nr_shards]
    off = llc_td->base_shard - node_td->base_shard;
    end = node_td->nr_shards - llc_td->nr_shards;
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(llc_td->nr_shards + j) & (SCX_FFP_MAX_CPUS-1)] = node_td->base_shard + j + (j < off ? (u32)0 : llc_td->nr_shards);
    }

    // other nodes: [node->nr_shards, topo->nr_shards - node->nr_shards]
    off = node_td->base_shard;
    end = nr_shards - node_td->nr_shards;
    if (unlikely(end >= SCX_FFP_MAX_CPUS-off)) return; // for verifier, should not happen
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(node_td->nr_shards + j) & (SCX_FFP_MAX_CPUS-1)] = j + (j < off ? (u32)0 : node_td->nr_shards);
    }
    
    bpf_printk("[INFO] [FP] [INIT] shard[%u] shard_dist_order: %u %u %u", i, shard_td->shard_dist_order[0], shard_td->shard_dist_order[1], shard_td->shard_dist_order[2]);
  }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ffp_init)
{
  TRACE_FUNC_START("init");
  bpf_printk("[INFO] [FP] [INIT] cgroup=%d", cgroup_id);
  bpf_printk("SCX_CAP_ENQ_IMMED: %llu", SCX_CAP_ENQ_IMMED);
  TRACE_EVENT(struct sched_trace_event_self, SCHED_TRACE_SELF,
    e->cgrp_id = cgroup_id;
    e->weight = DEFAULT_CGROUP_WEIGHT;
  );

  if (cgroup_id == 0) {
    root_init();
  }
  
  // init cgroup data structs
  self_cgroup_weight = DEFAULT_CGROUP_WEIGHT;
  s32 err = 0;
  u32 cid;
  u32 i;
  u32 nr_cids = scx_bpf_nr_cids();
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    aa.porder[i] = i;
  }
  bpf_for(cid, 0, NR_CPUS) {
    bpf_for(i, 0, MAX_SUB_SCHEDS) {
      aa.cid_data[cid].porder[i] = i;
    }
  }

  // init static cmasks
	cmask_init(&aa.self_cids.mask, 0, nr_cids);
  cmask_init(&aa.idle_cids.mask, 0, nr_cids);
  if (cgroup_id == 0) {
    bpf_for(cid, 0, nr_cids) {
      cmask_set(cid, &aa.self_cids.mask);
    }
  }

  // from qmap
  // init dynamic task cmasks
	if (!max_tasks) {
		scx_bpf_error("max_tasks must be > 0");
		return -EINVAL;
	}
  u32 nr_pages = (max_tasks * TASK_CTX_STRIDE + PAGE_SIZE - 1) / PAGE_SIZE;
	u8 __arena *slab = bpf_arena_alloc_pages(&arena, NULL, nr_pages, NUMA_NO_NODE, 0);
	if (!slab) {
		scx_bpf_error("failed to allocate task_ctx slab");
		return -ENOMEM;
	}
	aa.task_ctxs = (task_ctx_t *)slab;
  
	bpf_for(i, 0, max_tasks) {
		task_ctx_t *curr = (task_ctx_t *)(slab + i * TASK_CTX_STRIDE);
		task_ctx_t *next = (i + 1 < max_tasks) ?
			(task_ctx_t *)(slab + (i + 1) * TASK_CTX_STRIDE) : NULL;
		curr->next_free = next;
	}
	aa.task_free_head = (task_ctx_t *)slab;

  // copy global topology into arena
  struct topo_data *global_topo = fetch_global_topo();
  aa.topo.nr_cids = global_topo->nr_cids;
  aa.topo.nr_shards = global_topo->nr_shards;
  aa.topo.nr_cores = global_topo->nr_cores;
  aa.topo.nr_llcs = global_topo->nr_llcs;
  aa.topo.nr_nodes = global_topo->nr_nodes;
  bpf_for(i, 0, aa.topo.nr_cids) {
    struct cid_topo_data __arena *a = &aa.topo.cids[i & (SCX_FFP_MAX_CPUS-1)];
    struct cid_topo_data *b = &global_topo->cids[i & (SCX_FFP_MAX_CPUS-1)];

    a->cpu = b->cpu;
    a->shard_idx = b->shard_idx;
    a->core_idx = b->core_idx;
    a->llc_idx = b->llc_idx;
    a->node_idx = b->node_idx;
  }
  bpf_for(i, 0, aa.topo.nr_cores) {
    struct core_topo_data __arena *a = &aa.topo.cores[i & (SCX_FFP_MAX_CPUS-1)];
    struct core_topo_data *b = &global_topo->cores[i & (SCX_FFP_MAX_CPUS-1)];

    
    a->base_cid = b->base_cid;
    a->nr_cids = b->nr_cids;
    a->shard_idx = b->shard_idx;
    a->llc_idx = b->llc_idx;
    a->node_idx = b->node_idx;
  }
  bpf_for(i, 0, aa.topo.nr_shards) {
    struct shard_topo_data __arena *a = &aa.topo.shards[i & (SCX_FFP_MAX_CPUS-1)];
    struct shard_topo_data *b = &global_topo->shards[i & (SCX_FFP_MAX_CPUS-1)];
    
    a->base_cid = b->base_cid;
    a->nr_cids = b->nr_cids;
    a->llc_idx = b->llc_idx;
    a->node_idx = b->node_idx;
    u32 j;
    bpf_for(j, 0, aa.topo.nr_shards) {
      if (unlikely(j >= SCX_FFP_MAX_CPUS)) break;
      a->shard_dist_order[j] = b->shard_dist_order[j];
    }
  }
  bpf_for(i, 0, aa.topo.nr_llcs) {
    struct llc_topo_data __arena *a = &aa.topo.llcs[i & (SCX_FFP_MAX_CPUS-1)];
    struct llc_topo_data *b = &global_topo->llcs[i & (SCX_FFP_MAX_CPUS-1)];
    
    a->base_cid = b->base_cid;
    a->nr_cids = b->nr_cids;
    a->base_shard = b->base_shard;
    a->nr_shards = b->nr_shards;
    a->node_idx = b->node_idx;
  }
  bpf_for(i, 0, aa.topo.nr_nodes) {
    struct node_topo_data __arena *a = &aa.topo.nodes[i & (SCX_FFP_MAX_CPUS-1)];
    struct node_topo_data *b = &global_topo->nodes[i & (SCX_FFP_MAX_CPUS-1)];

    a->base_cid = b->base_cid;
    a->nr_cids = b->nr_cids;
    a->base_shard = b->base_shard;
    a->nr_shards = b->nr_shards;
  }

  // init shard cmasks
  bpf_for(i, 0, aa.topo.nr_shards) {
    struct shard_topo_data __arena *shard_td = &aa.topo.shards[i & (SCX_FFP_MAX_CPUS-1)];
    struct scx_cmask __arena *mask = &aa.shard_cids[i & (SCX_FFP_MAX_CPUS-1)].mask;
    cmask_init(mask, shard_td->base_cid, shard_td->nr_cids);
    u32 j;
    bpf_for(j, 0, shard_td->nr_cids) {
      cmask_set(shard_td->base_cid + j, mask);
    }
    bpf_printk("[INFO] [FP] [INIT] shard[%u] shard_td->nr_cids=%llu base=%llu nr_cids=%llu cmask=%06llx", i, shard_td->nr_cids, mask->base, mask->nr_cids, cmask_to_int(mask));
  }

  // init task data structs
  if (cgroup_id) {
    dsq_id = cgroup_id;
  } else {
    // root cgroup
    dsq_id = 1;
    self_cgroup_weight = ~0ULL;
  }
  scx_bpf_create_dsq(dsq_id, -1);

  TRACE_FUNC_END("init", "");
  return err;
}

void BPF_STRUCT_OPS(ffp_exit, struct scx_exit_info *ei)
{
  bpf_printk("[INFO] [FP] [EXIT] cgroup=%d\n", cgroup_id);
  UEI_RECORD(uei, ei);
}

// looks for a cgroup in sub_scheds
// if cgroup_id is 0, returns first free location
// returns NULL if not found or no free location
static __always_inline struct sub_sched_ctx __arena *sub_lookup(u64 cgroup_id) {
  for (u32 i = 0; i < MAX_SUB_SCHEDS; ++i) {
    if (aa.sub_scheds[i].cgroup_id == cgroup_id) {
      return &aa.sub_scheds[i];
    }
  }
  return NULL;
}

// NOTE: assume sub_attach, sub_detach, and cpuctl_set_weight are done sequentially

// from qmap
// gets weight of cgroup before attach
static u32 cgroup_curr_weight(u64 cgid) {
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;
	u32 weight = DEFAULT_CGROUP_WEIGHT;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return weight;

	css = BPF_CORE_READ(cgrp, subsys[cpu_cgrp_id]);
	if (css) {
		struct task_group *tg = container_of(css, struct task_group, css);
		u32 w = BPF_CORE_READ(tg, scx.weight);

		if (w)
			weight = w;
	}
	bpf_cgroup_release(cgrp);
	return weight;
}

s32 BPF_STRUCT_OPS(ffp_sub_attach, struct scx_sub_attach_args *args)
{
  TRACE_FUNC_START("sub_attach");

  u64 sub_cgroup_id = args->ops->sub_cgroup_id;
  
  // kernel should not call sub_attach on attached cgroup so no need to check for duplicates
  struct sub_sched_ctx __arena *sub = sub_lookup(0); 
  if (unlikely(!sub)) {
    TRACE_FUNC_END("sub_attach", "MAX SUBS EXCEEDED");
    return -ENOMEM;
  }
  
  sub->cgroup_id = sub_cgroup_id;
  sub->weight = cgroup_curr_weight(sub_cgroup_id);
  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - aa.sub_scheds;
    e->cgrp_id = sub->cgroup_id;
    e->weight = sub->weight;
  );

  // debug output cmask
  bpf_printk("[INFO] [FP] [SUB_ATTACH] cgroup=%llu weight=%llu cmask=%016llx", sub_cgroup_id, sub->weight, cmask_to_int(&aa.self_cids.mask));

  scx_bpf_sub_grant(sub_cgroup_id, SCX_CAP_ENQ_IMMED, (void *)(long)&aa.self_cids.mask, NULL);
  
  TRACE_FUNC_END("sub_attach", "");
  return 0;
}

void BPF_STRUCT_OPS(ffp_sub_detach, struct scx_sub_detach_args *args)
{
  TRACE_FUNC_START("sub_detach");

  u64 sub_cgroup_id = args->ops->sub_cgroup_id;
  struct sub_sched_ctx __arena *sub = sub_lookup(sub_cgroup_id);
  if (unlikely(!sub)) { // for verifier, should not happen
    TRACE_FUNC_END("sub_detach", "NOT ATTACHED");
    return;
  }

  sub->cgroup_id = 0;
  sub->weight = 0;

  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - aa.sub_scheds;
    e->cgrp_id = 0;
    e->weight = 0;
  );
  TRACE_FUNC_END("sub_detach", "");
}

void BPF_STRUCT_OPS(ffp_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
  TRACE_FUNC_START("cpuctl_set_weight");

  u64 sub_cgroup_id = cgrp->kn->id;
  TRACE_EVENT(struct sched_trace_event_set_weight_args, SCHED_TRACE_SET_WEIGHT_ARGS,
    e->cgrp_id = sub_cgroup_id;
    e->weight = weight;
  );

  if (sub_cgroup_id == cgroup_id) {
    self_cgroup_weight = weight;
    TRACE_EVENT(struct sched_trace_event_self, SCHED_TRACE_SELF,
      e->cgrp_id = cgroup_id;
      e->weight = weight;
    );
    TRACE_FUNC_END("cpuctl_set_weight", "SELF");
    return; // self not in subs
  }
  
  struct sub_sched_ctx __arena*sub = sub_lookup(sub_cgroup_id);
  if (!sub) {
    TRACE_FUNC_END("cpuctl_set_weight", "NOT ATTACHED");
    return;
  }
  
  sub->weight = weight;
  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - aa.sub_scheds;
    e->cgrp_id = sub->cgroup_id;
    e->weight = sub->weight;
  );
  TRACE_FUNC_END("cpuctl_set_weight", "");
}

// attempt to dispatch a task from global dsq to local dsq
static __always_inline bool try_task_dispatch(u32 cid) {
  TRACE_FUNC_START("try_task_dispatch")
  if (unlikely(cid >= SCX_FFP_MAX_CPUS)) return false; // for verifier, should not happen

  // u64 start = bpf_ktime_get_ns();

  // move highest weight in global dsq that can run on this cpu to local dsq
  struct task_struct *t;
  bool moved = false;
  struct cid_data __arena *cd = &aa.cid_data[cid];
  bpf_for_each(scx_dsq, t, dsq_id, 0) {
    task_ctx_t *tctx = get_task_ctx(t);
    if (unlikely(!tctx)) continue; // for verifier, should not happen
    
    // skip tasks that can't run on this cpu (either due to cmask or is non-migratable on another cpu)
    if (!cmask_test(cid, &tctx->cpus_allowed) && likely(!is_migration_disabled(t) || scx_bpf_task_cid(t) == cid)) {
      continue;
    }

    // this move only fails if another cpu's dispatch claims the task first
    if (likely(scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0))) {
      moved = true;
      break;
    }
  }
  
  // u64 delay = bpf_ktime_get_ns() - start;
  // if (unlikely(delay > stats->task_dispatch_wcet)) stats->task_dispatch_wcet = delay;

  TRACE_FUNC_END("try_task_dispatch", moved ? "MOVED" : "NOT MOVED");
  return moved;
}

static __always_inline void copy_porder(u32 __arena *src, u32 __arena *dst) {
  u32 i;
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    dst[i] = src[i];
  }
}

// syncs local porder with global porder
// local copies (gen_fin, data, gen_beg) in that order
// if gen_fin = gen_beg, then update finished by start of copy and no new update arrived by end of copy
// thus if gen_fin = gen_beg, data is consistent and of generation gen_fin = gen_beg
// so local porder updated with copied global porder
// if this is not the case, this update is ignored until the next sync
// fine since dispatches to invalid cgroups just return false and newly attached cgroups should be picked up eventually if weight updates are infrequent enough
static __always_inline bool sync_priority_order(u32 cid) {
  if (unlikely(cid >= SCX_FFP_MAX_CPUS)) return false; // for verifier, should not happen

  struct cid_data __arena *cd = &aa.cid_data[cid];
  u64 gen_fin = READ_ONCE(aa.porder_lock.gen_fin);
  if (gen_fin == cd->porder_lock.gen) return false; // already synced

  // copy data from global to local
  smp_rmb();
  copy_porder(aa.porder, cd->porder_sync_buff);
  smp_rmb();

  u64 gen_beg = READ_ONCE(aa.porder_lock.gen_beg);
  if (gen_beg != gen_fin) return false; // update failed due to write during copy

  // copied data is consistent, update local porder
  copy_porder(cd->porder_sync_buff, cd->porder);
  cd->porder_lock.gen = gen_fin;
  return true;
}

// only call in attach/detach/set_weights so that we know no other cgroups are changing weights at the same time
static __always_inline void update_priority_order(u32 cid, u32 sub_index) {
  u32 weight = aa.sub_scheds[sub_index & (MAX_SUB_SCHEDS - 1)].weight;

  // use local porder to sort subs by weight in decreasing order
  // can just copy global porder since no updates are happening at the same time
  struct cid_data __arena *cd = &aa.cid_data[cid];
  copy_porder(aa.porder, cd->porder);

  // find index of sub_index in porder
  u32 porder_idx = MAX_SUB_SCHEDS;
  u32 i;
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    if (cd->porder[i] != sub_index) continue;
    porder_idx = i;
    break;
  }
  if (unlikely(porder_idx == MAX_SUB_SCHEDS)) return; // for verifier, should not happen

  // bubble the sub in porder to sort
  // note: want higher weight at lower index
  bpf_repeat(MAX_SUB_SCHEDS) {
    if (porder_idx > 0 && aa.sub_scheds[cd->porder[porder_idx-1] & (MAX_SUB_SCHEDS - 1)].weight < weight) {
      // bubble down
      u32 t = cd->porder[porder_idx];
      cd->porder[porder_idx] = cd->porder[porder_idx-1];
      cd->porder[porder_idx-1] = t;
      porder_idx--;
    } else if (porder_idx+1 < MAX_SUB_SCHEDS && aa.sub_scheds[cd->porder[porder_idx+1] & (MAX_SUB_SCHEDS - 1)].weight > weight) {
      // bubble up
      u32 t = cd->porder[porder_idx];
      cd->porder[porder_idx] = cd->porder[porder_idx+1];
      cd->porder[porder_idx+1] = t;
      porder_idx++;
    } else {
      // in correct position, done
      break;
    }

    #if DEBUG
    bpf_for(i, 1, MAX_SUB_SCHEDS) {
      if (unlikely(aa.sub_scheds[cd->porder[i-1] & (MAX_SUB_SCHEDS - 1)].weight < aa.sub_scheds[cd->porder[i] & (MAX_SUB_SCHEDS - 1)].weight)) {
        u32 j;
        bpf_printk("[ERROR] [FP] [UPDATE_PORDER] porder not sorted after update for cid %u", cid);
        bpf_for(j, 0, MAX_SUB_SCHEDS) {
          bpf_printk("[ERROR] [FP] [UPDATE_PORDER] porder[%u]=%u weight=%u", j, cd->porder[j], aa.sub_scheds[cd->porder[j] & (MAX_SUB_SCHEDS - 1)].weight);
        }
        break;
      }
    }
    #endif
  }

  // write to global porder
  seqlock_update_start(&aa.porder_lock);
  copy_porder(cd->porder, aa.porder);
  seqlock_update_end(&aa.porder_lock);

  // update local lock to match global lock
  cd->porder_lock.gen = aa.porder_lock.gen_fin;

  return;
}

void BPF_STRUCT_OPS(ffp_dispatch, s32 cid, struct task_struct *prev)
{
  if (unlikely(cid >= SCX_FFP_MAX_CPUS)) return; // for testing limited CPUs
  
  // bpf_printk("[INFO] [FP] [DISPATCH] dispatching on cpu %u", cpu);
  TRACE_FUNC_START("dispatch");
  // u64 start = bpf_ktime_get_ns();

  cid = cid & (SCX_FFP_MAX_CPUS - 1); // for verifier

  // if (cgroup_id == 0) ++stats->n_root_dispatch_calls;

  // dispatch task
  if (try_task_dispatch(cid)) {
    // u64 delay = bpf_ktime_get_ns() - start;
    // if (unlikely(cgroup_id == 0 && delay > stats->root_dispatch_wcet)) stats->root_dispatch_wcet = delay;
    TRACE_FUNC_END("dispatch", "DISPATCHED TASK");
    return;
  }

  // dispatch cgroups if no tasks
  sync_priority_order(cid);
  struct cid_data __arena *cd = &aa.cid_data[cid];
  u32 i;
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    u32 idx = cd->porder[i] & (MAX_SUB_SCHEDS - 1);
    u32 sub_cgroup_id = aa.sub_scheds[idx].cgroup_id;

    if (sub_cgroup_id == 0) { // empty slots at lowest priority
      break;
    }

    cd->curr_idx = idx;
    if (scx_bpf_sub_dispatch(sub_cgroup_id)) {
      TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
        e->idx = idx;
        e->success = true;
      );
      // u64 delay = bpf_ktime_get_ns() - start;
      // if (unlikely(cgroup_id == 0 && delay > stats->root_dispatch_wcet)) stats->root_dispatch_wcet = delay;
      TRACE_FUNC_END("dispatch", "DISPATCHED CGROUP");
      return;
    }
    TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
      e->idx = idx;
      e->success = false;
    );
  }
  
  // u64 delay = bpf_ktime_get_ns() - start;
  // if (unlikely(cgroup_id == 0 && delay > stats->root_dispatch_wcet)) stats->root_dispatch_wcet = delay;
  TRACE_FUNC_END("dispatch", "NO READY SUBS");
  return; // no sub schedulers
}

// lookup task weight in task_weights map
// note: task_ctx gets weight in pick_cid so should use that if task is already enqueued for lower latency
u64 __always_inline get_task_weight(struct task_struct *p) {
  u64 weight = DEFAULT_TASK_WEIGHT;
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, 0, 0);
  if (lookup_weight) {
    weight = *lookup_weight;
  }
  if (unlikely(weight == 0)) {
    bpf_printk("[WARN] [FP] [GET_WEIGHT] Task %d has weight 0, using weight 1 instead", p->pid);
    weight = 1;
  }
  return weight;
}

// called from either select_cid or enqueue
// moves directly into dsq (either local cpu dsq if high enough priority or global otherwise)
// if ran in select_cid, will skip enqueue
void __always_inline pick_cid(struct task_struct *p, u32 prev_cid, u64 enq_flags) {
  // TRACE_FUNC_START("pick_cid");
  prev_cid = prev_cid & (NR_CPUS - 1); // for verifier
  // ++stats->n_pick_cid_calls;
  
  // setup
  int target_cid = prev_cid;
  bool nmig = is_migration_disabled(p);
  weight_tuple_t task_weight = WT_FROM_FIELDS(get_task_weight(p), nmig, self_cgroup_weight, 0);
  task_ctx_t *tctx = get_task_ctx(p);
  tctx->weight = task_weight;

  // IDLE SEARCH

  // prev cid
  if (likely(cmask_test(prev_cid, &tctx->cpus_allowed))) {
    if (likely(cmask_test_and_clear(prev_cid, &aa.idle_cids.mask))) {
      goto dispatch;
    }

    // EDGE CASE: https://github.com/sched-ext/scx/pull/1094/commits/7d8b8e75812ab62454c734683de4944938b3edc2
    // if per-cpu kthread woke up this task, then treat prev cpu as idle
    if (prev_cid == scx_bpf_this_cid()) {
      struct task_struct *curr = bpf_get_current_task_btf();
      if ((curr->flags & PF_KTHREAD) && curr->nr_cpus_allowed == 1) {
        goto dispatch;
      }
    }
  }

  // NON MIGRATEABLE / CPU PINNED CASE: just need to check prev cpu
  if (unlikely(nmig) || p->nr_cpus_allowed == 1) {
    if (task_weight <= get_running_weight(prev_cid)) goto dispatch_fail;
    
    goto dispatch;
  }

  // nearest idle cpu in numa topology
  u32 prev_shard = aa.topo.cids[prev_cid].shard_idx;
  u32 __arena *order = aa.topo.shards[prev_shard & (SCX_FFP_MAX_CPUS - 1)].shard_dist_order;
  u32 i;
  bpf_for(i, 0, aa.topo.nr_shards) {
    if (unlikely(i >= SCX_FFP_MAX_CPUS)) break; // for verifier, should not happen

    // from qmap
    u32 shard = order[i] & (SCX_FFP_MAX_CPUS - 1);
    u32 cid = aa.topo.shards[shard].base_cid;
    bpf_for(i, 0, IDLE_PICK_RETRIES) {
      cid = cmask_next_and2_set_wrap(&tctx->cpus_allowed,
                  &aa.idle_cids.mask,
                  &aa.self_cids.mask, cid + 1);
      barrier_var(cid);
      if (cid >= aa.topo.shards[shard].base_cid + aa.topo.shards[shard].nr_cids) break; // no idle
      if (likely(cmask_test_and_clear(cid, &aa.idle_cids.mask))) {
        target_cid = cid;
        goto dispatch;
      }
    }
  }

  // MIN WEIGHT SEARCH
  
  // tie break: prev cpu (misc 2) > cpu on prev numa node (misc 1) > any cpu (misc 0)
  // u64 search_start = bpf_ktime_get_ns();
  // target_cpu = -1;
  // weight_tuple_t target_weight = U128_MAX;
  // u32 cpu;
  // bpf_for(cpu, 0, NR_CPUS) {
  //   if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) continue;

  //   uint numa_class = cpu == prev_cpu ? 2 : scx_bpf_cpu_node(cpu) == prev_node ? 1 : 0;
  //   weight_tuple_t running_weight = grd->cid_running_weight[cpu] | ((weight_tuple_t)numa_class << WT_MISC_SHIFT);
  //   if (running_weight < target_weight) {
  //     target_cpu = cpu;
  //     target_weight = running_weight;
  //   }
  // }
  // target_weight &= ~(U128_MAX << WT_MISC_SHIFT); // remove misc data (only used for tie breaks)
  // u64 search_delay = bpf_ktime_get_ns() - search_start;
  // if (unlikely(search_delay > stats->search_wcet)) stats->search_wcet = search_delay;
  // if (task_weight <= target_weight) goto dispatch_fail;

  // DISPATCH

  dispatch:
  // SCX_ENQ_PREEMPT handles the kicking
  scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (target_cid & (SCX_FFP_MAX_CPUS - 1)), slice, SCX_ENQ_PREEMPT);
  // ++stats->n_ldsq_insertions;

  TRACE_FUNC_END("pick_cid", "");
  return;

  // NO DISPATCH
  dispatch_fail:

  // enqueue to global dsq instead
  u64 vtime = WT_VTIME_FROM_LOWER(WT_LOWER(task_weight));
  scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
  // ++stats->n_gdsq_insertions;
  TRACE_FUNC_END("pick_cid", "GLOBAL DSQ");
}

// task scheduling functions that should not be called
s32 BPF_STRUCT_OPS(ffp_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
  TRACE_FUNC_START("select_cid");
  // const u32 zero = 0;
  // struct cpu_stats *stats = bpf_map_lookup_elem(&ffp_cpu_stats, &zero);
  // if (unlikely(!stats)) return prev_cid; // for verifier, should not happen
  // ++stats->n_select_cid_calls;
  // u64 start = bpf_ktime_get_ns();
  pick_cid(p, (u32)prev_cid, SCX_ENQ_WAKEUP | wake_flags);
  // u64 delay = bpf_ktime_get_ns() - start;
  // if (unlikely(delay > stats->pick_cid_wcet)) stats->pick_cid_wcet = delay;
  TRACE_FUNC_END("select_cid", "");
  return prev_cid; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(ffp_enqueue, struct task_struct *p, u64 enq_flags) {
  TRACE_FUNC_START("enqueue");
  // const u32 zero = 0;
  // struct cpu_stats *stats = bpf_map_lookup_elem(&ffp_cpu_stats, &zero);
  // if (unlikely(!stats)) return; // for verifier, should not happen
  // ++stats->n_enqueue_calls;
  // u64 start = bpf_ktime_get_ns();
  pick_cid(p, (u32)scx_bpf_task_cid(p), enq_flags);
  // u64 delay = bpf_ktime_get_ns() - start;
  // if (unlikely(delay > stats->pick_cid_wcet)) stats->pick_cid_wcet = delay;
  TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(ffp_running, struct task_struct *p)
{
  // bpf_printk("[INFO] [FP] [RUNNING] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
  TRACE_EVENT(struct sched_trace_event_run_task, SCHED_TRACE_RUN_TASK,
    e->pid = p->pid;
  );

  u32 cid = scx_bpf_this_cid();

  // check policy of task
  // for SCHED_FIFO or SCHED_RR, set weight to MAX since sched_ext cannot kick it
  // for SCHED_EXT find their weight in task_weights map
  // for other policies, set weight to 0 since they are lower priority than SCHED_EXT
  int policy = BPF_CORE_READ(p, policy);
  weight_tuple_t wt;
  if (policy != SCHED_EXT) {
    bpf_printk("[WARN] [FP] [RUNNING] Task %d has policy %d", p->pid, policy);
    wt = (policy == SCHED_FIFO || policy == SCHED_RR) ? U128_MAX : 0;
  } else {
    wt = WT_FROM_FIELDS(get_task_weight(p), is_migration_disabled(p), self_cgroup_weight, 0);
  }

  set_running_weight(cid, wt);
}

void BPF_STRUCT_OPS(ffp_stopping, struct task_struct *p, bool runnable)
{
  // bpf_printk("[INFO] [FP] [STOPPING] cgroup=%d pid=%d comm=%s runnable=%d", cgroup_id, p->pid, p->comm, runnable);
  TRACE_EVENT(struct sched_trace_event_stop_task, SCHED_TRACE_STOP_TASK,
    e->pid = p->pid;
  );

  u32 cid = scx_bpf_this_cid();
  set_running_weight(cid, 0);
}

// void BPF_STRUCT_OPS(ffp_cgroup_move, struct task_struct *p, 
//                     struct cgroup *from, struct cgroup *to)
// {
//     u64 to_id = BPF_CORE_READ(to, kn, id);
//     bpf_printk("[INFO] [FP] [CGROUP_MOVE] Task %d MOVING from cgroup %llu to cgroup %llu\n", 
//                p->pid, BPF_CORE_READ(from, kn, id), to_id);
// }

// update weight of current running task
// since this only runs in the first attached FP scheduler (typically root), doesn't know the running weight of the tasks in lower cgroups
// thus just blindly kick
// can probably improve this by loading a new instance per FP scheduler
SEC("syscall")
int BPF_PROG(update_weight, u64 pid, u64 weight) {
  // bpf_printk("[INFO] [FP] [UPDATE_WEIGHT] Updating weight of task %d to %llu\n", pid, weight);
  // update weight in map
  struct task_struct *p = bpf_task_from_pid(pid);
  if (unlikely(!p)) {
    return 0; // for verifier, should not happen
  }

  u64 *task_weight_ptr = bpf_task_storage_get(&task_weights, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (unlikely(!task_weight_ptr)) {
    bpf_task_release(p);
    return 0; // for verifier, should not happen
  }
  u32 cid = scx_bpf_task_cid(p);
  *task_weight_ptr = weight;
  bpf_task_release(p);

  TRACE_EVENT(struct sched_trace_event_set_task_weight, SCHED_TRACE_SET_TASK_WEIGHT,
    e->pid = pid;
    e->weight = weight;
  );

  // kick cid
  scx_bpf_kick_cid(cid, (u64)SCX_KICK_PREEMPT);
  TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
    e->cpu = cid;
  );

  return 0;
}

void BPF_STRUCT_OPS(ffp_update_idle, s32 cid, bool idle)
{
	if (idle)
		cmask_set(cid, &aa.idle_cids.mask);
	else
		cmask_clear(cid, &aa.idle_cids.mask);
}

// from qmap
s32 BPF_STRUCT_OPS_SLEEPABLE(ffp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  /* pop a slab entry off the free list */
	if (unlikely(bpf_res_spin_lock(&aa_task_lock))) {
    scx_bpf_error("failed to acquire task_ctx slab lock");
		return -EBUSY;
  }
	task_ctx_t *tctx = aa.task_free_head;
	if (tctx) aa.task_free_head = tctx->next_free;
	bpf_res_spin_unlock(&aa_task_lock);

  if (!tctx) {
    scx_bpf_error("task_ctx slab exhausted (max_tasks=%u)", max_tasks);
    return -ENOMEM;
  }

  tctx->tid = p->scx.tid;
  tctx->weight = DEFAULT_TASK_WEIGHT; // will be overwritten in pick_cid anyways no reason to set here
	cmask_init(&tctx->cpus_allowed, 0, scx_bpf_nr_cids());
  
	bpf_rcu_read_lock();
	cmask_from_cpumask(&tctx->cpus_allowed, p->cpus_ptr);
	bpf_rcu_read_unlock();

  struct task_ctx_ptr *ctx_ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (unlikely(!ctx_ptr)) {
		/* push back to the free list */
		if (unlikely(bpf_res_spin_lock(&aa_task_lock))) {
      scx_bpf_error("failed to acquire task_ctx slab lock");
    } else {
			tctx->next_free = aa.task_free_head;
			aa.task_free_head = tctx;
			bpf_res_spin_unlock(&aa_task_lock);
		}
		return -ENOMEM;
	}
  
  ctx_ptr->tctx = tctx;
  return 0;
}

// from qmap
void BPF_STRUCT_OPS(ffp_exit_task, struct task_struct *p)
{
  // don't need to free task_ctx_ptr since kernel manages it
  // need to free task_ctx since it is allocated from arena memory
	struct task_ctx_ptr *ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, NULL, 0);
  if (unlikely(!ptr || !ptr->tctx)) return; // for verifier, should not happen

	task_ctx_t *tctx = ptr->tctx;
	ptr->tctx = NULL;

	if (bpf_res_spin_lock(&aa_task_lock)) {
    scx_bpf_error("failed to acquire task_ctx slab lock");
    return;
  }
	tctx->next_free = aa.task_free_head;
	aa.task_free_head = tctx;
	bpf_res_spin_unlock(&aa_task_lock);
}

// from qmap
void BPF_STRUCT_OPS(ffp_set_cmask, struct task_struct *p, const struct scx_cmask *cmask_in)
{
  task_ctx_t *tctx = get_task_ctx(p);
  if (unlikely(!tctx)) return; // for verifier, should not happen

	struct scx_cmask __arena *cmask = (struct scx_cmask __arena *)(long)cmask_in;
	cmask_copy(&tctx->cpus_allowed, cmask);
}

// ops

SCX_OPS_CID_DEFINE(ffp_ops,
  .name               = "ffp",
  .init               = (void *)ffp_init,
  .exit               = (void *)ffp_exit,
  .flags              = SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_BUILTIN_IDLE_PER_NODE | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ENQ_EXITING | SCX_OPS_TID_TO_TASK,
  .select_cid         = (void *)ffp_select_cid,
  .enqueue            = (void *)ffp_enqueue,
  .running            = (void *)ffp_running,
  .stopping           = (void *)ffp_stopping,
  .init_task          = (void *)ffp_init_task,
  .exit_task          = (void *)ffp_exit_task,
  .set_cmask          = (void *)ffp_set_cmask,
  .dispatch           = (void *)ffp_dispatch,
  .cpuctl_set_weight  = (void *)ffp_cpuctl_set_weight,
  .sub_attach         = (void *)ffp_sub_attach,
  .sub_detach         = (void *)ffp_sub_detach,
  .update_idle    = (void *)ffp_update_idle
);
