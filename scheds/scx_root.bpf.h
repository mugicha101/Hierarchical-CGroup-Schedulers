#ifndef __SCX_ROOT_BPF_H
#define __SCX_ROOT_BPF_H

#ifndef __BPF__
#error "This file must be compiled for BPF"
#endif

#ifndef __SCX_ROOT_H
#error "This file must be included from scx_root.h"
#endif

_Static_assert(SCX_MAX_CPUS >= NR_CPUS, "SCX_MAX_CPUS must be >= NR_CPUS");
_Static_assert(SCX_CMASK_WORDS == CMASK_NR_WORDS(NR_CPUS), "SCX_CMASK_WORDS must equal CMASK_NR_WORDS(NR_CPUS)");
_Static_assert(sizeof(struct scx_cmask_wrapper) == struct_size_t(struct scx_cmask, bits, SCX_CMASK_WORDS), "scx_full_cmask must be exactly sized to back a full scx_cmask");

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

// dump helper
static __always_inline u64 cmask_to_u64(struct scx_cmask __arena *cmask) {
  u64 out = 0;
  u32 i;
  bpf_for(i, cmask->base, cmask->nr_cids + cmask->base) {
    if (cmask_test(i, cmask)) {
      out |= (1ULL << i);
    }
  }
  return out;
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

// per task state for the scheduler
// stored on arena memory, allocated via slab allocator (from qmap)
// policy_task_ctx needs to be large enough to support all policies
union policy_task_ctx {
  u64 __align;
  u8 data[SCX_POLICY_TASK_CTX_SIZE];
};

struct task_ctx {
  struct task_ctx __arena	*next_free;	/* only valid on free list */

  // policy specific fields
  union policy_task_ctx ptctx;

  // affinity max needs to be after fields due to cmask size being variable
  struct scx_cmask cpus_allowed;
};

struct scx_task_ctx {
  u64 tid;
};
typedef struct scx_task_ctx __arena scx_task_ctx_t;
_Static_assert(sizeof(struct scx_task_ctx) <= SCX_POLICY_TASK_CTX_SIZE, "scx_task_ctx larger than SCX_POLICY_TASK_CTX_SIZE");
_Static_assert(_Alignof(struct scx_task_ctx) <= _Alignof(union policy_task_ctx), "scx_task_ctx requires greater alignment");

static __always_inline scx_task_ctx_t *get_scx_task_ctx(task_ctx_t *tctx) {
  return likely(tctx) ? (scx_task_ctx_t *)tctx->ptctx.data : (scx_task_ctx_t *)0;
}

/*
 * Slab stride for task_ctx. cpus_allowed's flex array bits[] overlaps the
 * tail bytes appended per entry; struct_size() gives the actual per-entry
 * footprint.
 */
#define TASK_CTX_STRIDE							\
	struct_size_t(struct task_ctx, cpus_allowed.bits,		\
		      CMASK_NR_WORDS(NR_CPUS))

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

// since task slab allocator needs a lock, and arena can't store locks, define it here
__hidden struct bpf_res_spin_lock scx_arena_task_ctx_slab_lock SEC(".data.scx_arena_task_ctx_slab_lock");


static __always_inline task_ctx_t *get_task_ctx(struct task_struct *p) {
	SCX_TOUCH_ARENA();
  struct task_ctx_ptr *ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, 0, 0);
  return ptr ? ptr->tctx : NULL;
}

// init global structures
static __always_inline void root_init() {
  u32 nr_cids = scx_bpf_nr_cids();
  if (nr_cids > SCX_MAX_CPUS)
    nr_cids = SCX_MAX_CPUS;
  bpf_printk("[INFO] [JLFP] [INIT] nr_cids=%u", nr_cids);
  
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
  u32 no_topo_core = SCX_MAX_CPUS;
  u32 no_topo_shard = SCX_MAX_CPUS;
  u32 no_topo_llc = SCX_MAX_CPUS;
  u32 no_topo_node = SCX_MAX_CPUS;
  bpf_for(cid, 0, nr_cids) {
    struct scx_cid_topo t = {};
    scx_bpf_cid_topo(cid, &t);
    bpf_printk("[INFO] [JLFP] [INIT] core_cid=%u core_idx=%d llc_cid=%d llc_idx=%d node_cid=%d node_idx=%d shard_cid=%d shard_idx=%d",
      t.core_cid,
      t.core_idx,
      t.llc_cid,
      t.llc_idx,
      t.node_cid,
      t.node_idx,
      t.shard_cid,
      t.shard_idx
    );
    TRACE_EVENT(struct sched_trace_event_cid_topo, SCHED_TRACE_CID_TOPO,
      e->cid = cid;
      e->cpu = scx_bpf_cid_to_cpu(cid);
      e->core = t.core_idx;
      e->shard = t.shard_idx;
      e->llc = t.llc_idx;
      e->node = t.node_idx;
    );

    // since cids with core/llc/node unknown (-1) are at back
    // we can allocate a core/llc/node for them at the back upon seeing first
    // TODO: fix bug in case where multiple shards have no-topo nodes
    if (t.core_idx == -1) {
      if (no_topo_core == SCX_MAX_CPUS) {
        no_topo_core = topo->nr_cores;
        no_topo_llc = topo->nr_llcs;
        no_topo_node = topo->nr_nodes;
      }
      t.core_idx = no_topo_core;
      t.llc_idx = no_topo_llc;
      t.node_idx = no_topo_node;
    }

    struct cid_topo_data *cid_td = &topo->cids[cid];
    struct core_topo_data *core_td = &topo->cores[t.core_idx & (SCX_MAX_CPUS-1)];
    struct shard_topo_data *shard_td = &topo->shards[t.shard_idx & (SCX_MAX_CPUS-1)];
    struct llc_topo_data *llc_td = &topo->llcs[t.llc_idx & (SCX_MAX_CPUS-1)];
    struct node_topo_data *node_td = &topo->nodes[t.node_idx & (SCX_MAX_CPUS-1)];

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
    core_td->shard_idx = t.shard_idx;
    core_td->llc_idx = t.llc_idx;
    core_td->node_idx = t.node_idx;
    bpf_printk("[INFO] [JLFP] [INIT] new core: %lld", t.core_idx);

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
    shard_td->llc_idx = t.llc_idx;
    shard_td->node_idx = t.node_idx;
    bpf_printk("[INFO] [JLFP] [INIT] new shard: %lld", t.shard_idx);

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
    llc_td->node_idx = t.node_idx;
    bpf_printk("[INFO] [JLFP] [INIT] new llc: %lld", t.llc_idx);

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
    bpf_printk("[INFO] [JLFP] [INIT] new node: %lld", t.node_idx);
  }
  bpf_printk("[INFO] [JLFP] [INIT] topo nr_cids=%u nr_cores=%u nr_shards=%u nr_llcs=%u nr_nodes=%u",
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
    struct shard_topo_data *shard_td = &topo->shards[i & (SCX_MAX_CPUS-1)];
    struct llc_topo_data *llc_td = &topo->llcs[shard_td->llc_idx & (SCX_MAX_CPUS-1)];
    struct node_topo_data *node_td = &topo->nodes[shard_td->node_idx & (SCX_MAX_CPUS-1)];
    
    shard_td->shard_dist_order[0] = i;
    
    // same llc: [1, llc->nr_shards-1]
    u32 j;
    u32 off = i - llc_td->base_shard;
    u32 end = llc_td->nr_shards - 1;
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(1 + j) & (SCX_MAX_CPUS-1)] = llc_td->base_shard + j + (j < off ? (u32)0 : (u32)1);
    }

    // same node: [llc->nr_shards, node->nr_shards - llc->nr_shards]
    off = llc_td->base_shard - node_td->base_shard;
    end = node_td->nr_shards - llc_td->nr_shards;
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(llc_td->nr_shards + j) & (SCX_MAX_CPUS-1)] = node_td->base_shard + j + (j < off ? (u32)0 : llc_td->nr_shards);
    }

    // other nodes: [node->nr_shards, topo->nr_shards - node->nr_shards]
    off = node_td->base_shard;
    end = nr_shards - node_td->nr_shards;
    if (unlikely(end >= SCX_MAX_CPUS-off)) return; // for verifier, should not happen
    bpf_for(j, 0, end) {
      shard_td->shard_dist_order[(node_td->nr_shards + j) & (SCX_MAX_CPUS-1)] = j + (j < off ? (u32)0 : node_td->nr_shards);
    }
    
    bpf_printk("[INFO] [JLFP] [INIT] shard[%u] shard_dist_order: %u %u %u", i, shard_td->shard_dist_order[0], shard_td->shard_dist_order[1], shard_td->shard_dist_order[2]);
  }
}

// init scx_arena
static __always_inline s32 scx_init(struct scx_arena __arena *a, u64 cgroup_id, u32 max_tasks) {
  a->cgroup_id = cgroup_id;
  a->max_tasks = max_tasks;
  if (cgroup_id == 0) {
    root_init();
  }

  // copy global topology into arena
  struct topo_data *global_topo = fetch_global_topo();
  a->topo.nr_cids = global_topo->nr_cids;
  a->topo.nr_shards = global_topo->nr_shards;
  a->topo.nr_cores = global_topo->nr_cores;
  a->topo.nr_llcs = global_topo->nr_llcs;
  a->topo.nr_nodes = global_topo->nr_nodes;
  u32 i;
  bpf_for(i, 0, a->topo.nr_cids) {
    struct cid_topo_data __arena *dst = &a->topo.cids[i & (NR_CPUS-1)];
    struct cid_topo_data *src = &global_topo->cids[i & (NR_CPUS-1)];

    dst->cpu = src->cpu;
    dst->shard_idx = src->shard_idx;
    dst->core_idx = src->core_idx;
    dst->llc_idx = src->llc_idx;
    dst->node_idx = src->node_idx;
  }
  bpf_for(i, 0, a->topo.nr_cores) {
    struct core_topo_data __arena *dst = &a->topo.cores[i & (NR_CPUS-1)];
    struct core_topo_data *src = &global_topo->cores[i & (NR_CPUS-1)];

    
    dst->base_cid = src->base_cid;
    dst->nr_cids = src->nr_cids;
    dst->shard_idx = src->shard_idx;
    dst->llc_idx = src->llc_idx;
    dst->node_idx = src->node_idx;
  }
  bpf_for(i, 0, a->topo.nr_shards) {
    struct shard_topo_data __arena *dst = &a->topo.shards[i & (NR_CPUS-1)];
    struct shard_topo_data *src = &global_topo->shards[i & (NR_CPUS-1)];
    
    dst->base_cid = src->base_cid;
    dst->nr_cids = src->nr_cids;
    dst->llc_idx = src->llc_idx;
    dst->node_idx = src->node_idx;
    u32 j;
    bpf_for(j, 0, a->topo.nr_shards) {
      if (unlikely(j >= NR_CPUS)) break;
      dst->shard_dist_order[j] = src->shard_dist_order[j];
    }
  }
  bpf_for(i, 0, a->topo.nr_llcs) {
    struct llc_topo_data __arena *dst = &a->topo.llcs[i & (NR_CPUS-1)];
    struct llc_topo_data *src = &global_topo->llcs[i & (NR_CPUS-1)];
    
    dst->base_cid = src->base_cid;
    dst->nr_cids = src->nr_cids;
    dst->base_shard = src->base_shard;
    dst->nr_shards = src->nr_shards;
    dst->node_idx = src->node_idx;
  }
  bpf_for(i, 0, a->topo.nr_nodes) {
    struct node_topo_data __arena *dst = &a->topo.nodes[i & (NR_CPUS-1)];
    struct node_topo_data *src = &global_topo->nodes[i & (NR_CPUS-1)];

    dst->base_cid = src->base_cid;
    dst->nr_cids = src->nr_cids;
    dst->base_shard = src->base_shard;
    dst->nr_shards = src->nr_shards;
  }

  // init task_ctx slab
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
	a->task_ctxs = (task_ctx_t *)slab;
  
	bpf_for(i, 0, max_tasks) {
		task_ctx_t *curr = (task_ctx_t *)(slab + i * TASK_CTX_STRIDE);
		task_ctx_t *next = (i + 1 < max_tasks) ?
			(task_ctx_t *)(slab + (i + 1) * TASK_CTX_STRIDE) : NULL;
		curr->next_free = next;
	}
	a->task_free_head = (task_ctx_t *)slab;
  
  // init static cmasks
	cmask_init(&a->self_cids.mask, 0, a->topo.nr_cids);
  cmask_init(&a->idle_cids.mask, 0, a->topo.nr_cids);

  // init shard cmasks
  bpf_for(i, 0, a->topo.nr_shards) {
    struct shard_topo_data __arena *shard_td = &a->topo.shards[i & (NR_CPUS-1)];
    struct scx_cmask __arena *mask = &a->shard_cids[i & (NR_CPUS-1)].mask;
    cmask_init(mask, shard_td->base_cid, shard_td->nr_cids);
    u32 j;
    bpf_for(j, 0, shard_td->nr_cids) {
      cmask_set(shard_td->base_cid + j, mask);
    }
    bpf_printk("[INFO] [JLFP] [INIT] shard[%u] shard_td->nr_cids=%llu base=%llu nr_cids=%llu cmask=%06llx", i, shard_td->nr_cids, mask->base, mask->nr_cids, cmask_to_u64(mask));
  }

  // TODO: handle subschedulers in capabilities ops
  // currently just assuming subscheduler has access to all CPUs
  bpf_for(i, 0, a->topo.nr_cids) {
    cmask_set(i, &a->self_cids.mask);
  }

  return 0;
}

static __always_inline task_ctx_t *scx_init_task(struct scx_arena __arena *a, struct task_struct *p, struct scx_init_task_args *args) {
  // allocate new task_ctx_t (from qmap)
  /* pop a slab entry off the free list */
	if (unlikely(bpf_res_spin_lock(&scx_arena_task_ctx_slab_lock))) {
    scx_bpf_error("failed to acquire task_ctx slab lock");
		return (task_ctx_t *)0;
  }
	task_ctx_t *tctx = a->task_free_head;
	if (tctx) a->task_free_head = tctx->next_free;
	bpf_res_spin_unlock(&scx_arena_task_ctx_slab_lock);

  if (!tctx) {
    scx_bpf_error("task_ctx slab exhausted (max_tasks=%llu)", a->max_tasks);
    return tctx;
  }

  struct task_ctx_ptr *ctx_ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (unlikely(!ctx_ptr)) {
		/* push back to the free list */
		if (unlikely(bpf_res_spin_lock(&scx_arena_task_ctx_slab_lock))) {
      scx_bpf_error("failed to acquire task_ctx slab lock");
    } else {
			tctx->next_free = a->task_free_head;
			a->task_free_head = tctx;
			bpf_res_spin_unlock(&scx_arena_task_ctx_slab_lock);
		}
		return (task_ctx_t *)0;
	}
  
  ctx_ptr->tctx = tctx;

  // init cpus allowed
	cmask_init(&tctx->cpus_allowed, 0, a->topo.nr_cids);
	bpf_rcu_read_lock();
	cmask_from_cpumask(&tctx->cpus_allowed, p->cpus_ptr);
	bpf_rcu_read_unlock();

  // init scx_task_ctx fields
  scx_task_ctx_t *scx_tctx = get_scx_task_ctx(tctx);
  scx_tctx->tid = p->scx.tid;

  return tctx;
}

// returns true if successful
static __always_inline bool scx_exit_task(struct scx_arena __arena *a, struct task_struct *p) {
  // don't need to free task_ctx_ptr since kernel manages it
  // need to free task_ctx since it is allocated from arena memory
	struct task_ctx_ptr *ptr = bpf_task_storage_get(&task_ctx_ptr_map, p, NULL, 0);
  if (unlikely(!ptr || !ptr->tctx)) return false; // for verifier, should not happen

	task_ctx_t *tctx = ptr->tctx;
	ptr->tctx = NULL;

	if (bpf_res_spin_lock(&scx_arena_task_ctx_slab_lock)) {
    scx_bpf_error("failed to acquire task_ctx slab lock");
    return false;
  }
	tctx->next_free = a->task_free_head;
	a->task_free_head = tctx;
	bpf_res_spin_unlock(&scx_arena_task_ctx_slab_lock);
  return true;
}

static __always_inline task_ctx_t *scx_set_cmask(struct task_struct *p, const struct scx_cmask *cmask_in) {
  task_ctx_t *tctx = get_task_ctx(p);
  if (unlikely(!tctx)) return NULL;

  struct scx_cmask __arena *cmask = (struct scx_cmask __arena *)(long)cmask_in;
  cmask_copy(&tctx->cpus_allowed, cmask);
  return tctx;
}

static __always_inline void scx_update_idle(struct scx_arena __arena *a, s32 cid, bool idle) {
  if (idle)
    cmask_set(cid, &a->idle_cids.mask);
  else
    cmask_clear(cid, &a->idle_cids.mask);
}

#endif