// header file for generic root setup
// sets up topology

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

// BPF ONLY CODE

#ifdef __BPF__

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

#endif

#endif
