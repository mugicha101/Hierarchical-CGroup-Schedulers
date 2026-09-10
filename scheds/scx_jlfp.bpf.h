#ifndef __SCX_JLFP_BPF_H
#define __SCX_JLFP_BPF_H

#ifndef __BPF__
#error "This file must be compiled for BPF"
#endif

#ifndef __SCX_JLFP_H
#error "This file must be included from scx_jlfp.h"
#endif

struct jlfp_task_ctx {
  struct scx_task_ctx scx;

  // cached tuple from selection/enqueue or dispatch reconsidering runnable prev
  weight_tuple_t weight;
  // outstanding preemption reservation, NR_CPUS if none
  u32 pending_cid;
};
typedef struct jlfp_task_ctx __arena jlfp_task_ctx_t;
_Static_assert(sizeof(struct jlfp_task_ctx) <= SCX_POLICY_TASK_CTX_SIZE, "jlfp_task_ctx larger than SCX_POLICY_TASK_CTX_SIZE");
_Static_assert(offsetof(struct jlfp_task_ctx, scx) == 0, "scx_task_ctx must be prefix");
static __always_inline jlfp_task_ctx_t *get_jlfp_task_ctx(task_ctx_t *tctx) {
  return likely(tctx) ? (jlfp_task_ctx_t *)tctx->ptctx.data : (jlfp_task_ctx_t *)0;
}

static __always_inline bool init_jlfp_task_ctx(struct scx_arena __arena *a, struct task_struct *p, struct scx_init_task_args *args) {
  jlfp_task_ctx_t *tctx = get_jlfp_task_ctx(scx_init_task(a, p, args));
  if (unlikely(!tctx)) return false;

  // placeholder until jlfp_pick_cid constructs the full priority tuple
  tctx->weight = DEFAULT_TASK_WEIGHT;
  tctx->pending_cid = NR_CPUS;
  return true;
}

// cpu selection
// first try prev cid as idle, including the per-cpu kthread wakeup shortcut
// migration-disabled and single-cpu tasks then compare against prev cid's effective weight
// other tasks search nearby idle cids allowed by both task affinity and self_cids
// preemption searches fully allowed shards when global_search is enabled, with prev shard as fallback
// the selected cid must allow the task and have a lower effective weight; otherwise use the global dsq
// partial shards are skipped by global preemption search; prev-shard fallback still checks affinity
// global dsq dispatch compares eligible queued tasks against runnable prev, favoring prev on equal weight

// TODO: ensure search checks capabilities consistently (currently only checks in idle search)
// TODO: replace all verifier sat checks with explicit errors

// pending vs running
// effective_weight[cid] = max(running_weight[cid], pending_weight[cid])
// pending reservations keep stopping of the old task from erasing a new preemptor's priority
// runtime updates to shard weights, pending owners, and minima hold the shard lock
// unlocked search reads are hints; the selected shard is checked again under its lock

// jlfp_pick_cid(A):
//     clear A's old pending reservation on re-enqueue if A still owns it
//     on the min-weight preemption path, reserve the target cid for A before releasing the lock
//     idle and pinned/migration-disabled direct-dispatch paths do not create a reservation
// running(A):
//     set running_weight[cid] to A's priority
//     clear pending weight and owner only if A owns the reservation
//     reset A.pending_cid to NR_CPUS
// stopping(A):
//     clear running_weight[cid] and refresh the shard minimum
//     leave pending reservations unchanged, even when A remains runnable

#define JLFP_DEBUG 1

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif

#ifndef SCHED_RR
#define SCHED_RR 2
#endif

// from qmap
// max number of times to try idle claim
#define IDLE_PICK_RETRIES	16

// per-cid priorities and preemption reservations, grouped by shard
// shared by scheduler instances reusing the pinned shard_ctx_map
struct shard_ctx {
  // shard lock
  struct bpf_res_spin_lock lock;

  // shared JLFP priority state
  weight_tuple_t cid_running_weight[SCX_CID_SHARD_MAX_CPUS];
  weight_tuple_t cid_pending_weight[SCX_CID_SHARD_MAX_CPUS];
  u64 cid_pending_owner[SCX_CID_SHARD_MAX_CPUS];

  // min effective_weight[cid] over all cids in shard (cid stored in misc bits of weight tuple)
  // updated under the shard lock; unlocked readers use it only to select a candidate shard
  weight_tuple_t min_effective;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NR_CPUS);
  __type(key, u32);
  __type(value, struct shard_ctx);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} shard_ctx_map SEC(".maps");

static __always_inline weight_tuple_t sctx_get_effective_weight(struct shard_ctx *sctx, u32 shard_offset) {
  // may be stale if shard lock not acquired
  weight_tuple_t running = sctx->cid_running_weight[shard_offset];
  weight_tuple_t pending = sctx->cid_pending_weight[shard_offset];
  return running > pending ? running : pending;
};

static __always_inline weight_tuple_t get_effective_weight(struct jlfp_arena __arena *a, u32 cid) {
  u32 shard = a->scx.topo.cids[cid & (NR_CPUS - 1)].shard_idx;
  struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &shard);
  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return 0; // for verifier, should not happen

  return sctx_get_effective_weight(sctx, shard_offset);
}

static __always_inline void update_min_effective_locked(struct jlfp_arena __arena *a, u32 cid, u32 shard, struct shard_ctx *sctx) {
  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  weight_tuple_t new_weight = sctx_get_effective_weight(sctx, shard_offset);
  weight_tuple_t curr_min_weight = WT_STRIP_MISC(sctx->min_effective);
  u32 curr_min_cid = WT_MISC(sctx->min_effective);

  // if existing min higher than new min, simple update
  if (new_weight < curr_min_weight) {
    sctx->min_effective = ((u128)cid << WT_MISC_SHIFT) | new_weight;
    return;
  }

  // if new weight is higher than min, min only changes if the cid matches
  if (new_weight == curr_min_weight || curr_min_cid != cid) {
    return;
  }

  // need to search shard for new min
  u32 base_cid = a->scx.topo.shards[shard].base_cid;
  curr_min_weight = sctx_get_effective_weight(sctx, 0);
  curr_min_cid = base_cid;
  u32 end = a->scx.topo.shards[shard].nr_cids;
  if (unlikely(end > SCX_CID_SHARD_MAX_CPUS)) end = SCX_CID_SHARD_MAX_CPUS; // for verifier, should not happen

  u32 i;
  bpf_for(i, 1, end) {
    weight_tuple_t w = sctx_get_effective_weight(sctx, i);
    if (w < curr_min_weight) {
      curr_min_weight = w;
      curr_min_cid = i + base_cid;
    }
  }


  // note: if finds lower existing weight, prev min_running was wrong
  // but cannot assert due to holding lock, cannot release lock due to verifier

  sctx->min_effective = ((u128)curr_min_cid << WT_MISC_SHIFT) | curr_min_weight;
}

static __always_inline void set_running_weight_locked(struct jlfp_arena __arena *a, u32 cid, u32 shard, weight_tuple_t wt, struct shard_ctx *sctx) {
  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  sctx->cid_running_weight[shard_offset] = wt;
  update_min_effective_locked(a, cid, shard, sctx);
}

static __always_inline void set_pending_weight_locked(struct jlfp_arena __arena *a, u32 cid, u32 shard, weight_tuple_t wt, struct shard_ctx *sctx, u64 scx_tid) {
  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(!sctx || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  sctx->cid_pending_weight[shard_offset] = wt;
  sctx->cid_pending_owner[shard_offset] = scx_tid;
  update_min_effective_locked(a, cid, shard, sctx);
}

static __always_inline s32 jlfp_init_core(struct jlfp_arena __arena *a, u64 cgroup_id, u32 max_tasks) {
  TRACE_FUNC_START("init");
  bpf_printk("[INFO] [JLFP] [INIT] cgroup=%llu", cgroup_id);
  bpf_printk("[INFO] [JLFP] [INIT] SCX_TASK_QUEUED=%u", SCX_TASK_QUEUED);
  TRACE_EVENT(struct sched_trace_event_init, SCHED_TRACE_INIT,
    e->cgrp_id = cgroup_id;
  );

  s32 err = scx_init(&a->scx, cgroup_id, max_tasks);
  if (err) return err;

  if (cgroup_id == 0) {
    // clear new shard context in case junk from prior scheduler
    struct topo_data *topo = fetch_global_topo();
    u32 shard;
    bpf_for(shard, 0, topo->nr_shards) {
      struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &shard);
      if (unlikely(shard >= NR_CPUS || !sctx)) { // for verifier, should not happen
        scx_bpf_error("Failed to lookup shard %d", shard);
        continue;
      }

      u32 i;
      bpf_for(i, 0, SCX_CID_SHARD_MAX_CPUS) {
        sctx->cid_pending_owner[i] = 0;
        sctx->cid_pending_weight[i] = 0;
        sctx->cid_running_weight[i] = 0;
      }
      sctx->min_effective = (weight_tuple_t)topo->shards[shard].base_cid << WT_MISC_SHIFT;
    }
  }

  // init cgroup data structs
  a->scx.self_cgroup_weight = DEFAULT_CGROUP_WEIGHT;
  u32 cid;
  u32 i;
  u32 nr_cids = scx_bpf_nr_cids();
  if (nr_cids > NR_CPUS) nr_cids = NR_CPUS;

  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    a->porder[i] = i;
  }
  bpf_for(cid, 0, NR_CPUS) {
    bpf_for(i, 0, MAX_SUB_SCHEDS) {
      a->cid_data[cid].porder[i] = i;
    }
  }
  bpf_for(cid, 0, nr_cids) {
    cmask_init(&a->cid_data[cid].tmp_cmask.mask, 0, nr_cids);
  }

  // init task data structs
  if (cgroup_id) {
    a->dsq_id = cgroup_id;
  } else {
    // root cgroup
    a->dsq_id = 1;
    a->scx.self_cgroup_weight = WT_CGRP_WEIGHT_MASK;
  }
  scx_bpf_create_dsq(a->dsq_id, -1);

  TRACE_FUNC_END("init", "");
  return err;
}

static __always_inline void copy_porder(u32 __arena *src, u32 __arena *dst) {
  u32 i;
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    dst[i] = src[i];
  }
}

// only call in attach/detach/set_weights so that we know no other cgroups are changing weights at the same time
static __always_inline void update_porder(struct jlfp_arena __arena *a, u32 cid, u32 sub_index) {
  u32 weight = a->scx.sub_scheds[sub_index & (MAX_SUB_SCHEDS - 1)].weight;
  
  // use local porder to sort subs by weight in decreasing order
  // can just copy global porder since no updates are happening at the same time
  struct cid_data __arena *cd = &a->cid_data[cid];
  copy_porder(a->porder, cd->porder);
  
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
    if (porder_idx > 0 && a->scx.sub_scheds[cd->porder[porder_idx-1] & (MAX_SUB_SCHEDS - 1)].weight < weight) {
      // bubble down
      u32 t = cd->porder[porder_idx];
      cd->porder[porder_idx] = cd->porder[porder_idx-1];
      cd->porder[porder_idx-1] = t;
      porder_idx--;
    } else if (porder_idx+1 < MAX_SUB_SCHEDS && a->scx.sub_scheds[cd->porder[porder_idx+1] & (MAX_SUB_SCHEDS - 1)].weight > weight) {
      // bubble up
      u32 t = cd->porder[porder_idx];
      cd->porder[porder_idx] = cd->porder[porder_idx+1];
      cd->porder[porder_idx+1] = t;
      porder_idx++;
    } else {
      // in correct position, done
      break;
    }
    
    #if JLFP_DEBUG
    bpf_for(i, 1, MAX_SUB_SCHEDS) {
      if (unlikely(a->scx.sub_scheds[cd->porder[i-1] & (MAX_SUB_SCHEDS - 1)].weight < a->scx.sub_scheds[cd->porder[i] & (MAX_SUB_SCHEDS - 1)].weight)) {
        u32 j;
        bpf_printk("[ERROR] [JLFP] [UPDATE_PORDER] porder not sorted after update for cid %u", cid);
        bpf_for(j, 0, MAX_SUB_SCHEDS) {
          bpf_printk("[ERROR] [JLFP] [UPDATE_PORDER] porder[%u]=%u weight=%u", j, cd->porder[j], a->scx.sub_scheds[cd->porder[j] & (MAX_SUB_SCHEDS - 1)].weight);
        }
        scx_bpf_error("Error in porder sorting");
        break;
      }
    }
    #endif
  }

  // write to global porder
  seqlock_update_start(&a->porder_lock);
  copy_porder(cd->porder, a->porder);
  seqlock_update_end(&a->porder_lock);
  
  // update local lock to match global lock
  cd->porder_lock.gen = a->porder_lock.gen_fin;
  
  return;
}

// syncs local porder with global porder
// local copies (gen_fin, data, gen_beg) in that order
// if gen_fin = gen_beg, then update finished by start of copy and no new update arrived by end of copy
// thus if gen_fin = gen_beg, data is consistent and of generation gen_fin = gen_beg
// so local porder updated with copied global porder
// if this is not the case, this update is ignored until the next sync
// fine since dispatches to invalid cgroups just return false and newly attached cgroups should be picked up eventually if weight updates are infrequent enough
static __always_inline bool sync_porder(struct jlfp_arena __arena *a, u32 cid) {
  if (unlikely(cid >= NR_CPUS)) return false; // for verifier, should not happen
  
  struct latency_ctx lctx;
  lstat_start(&lctx);
  
  struct cid_data __arena *cd = &a->cid_data[cid];
  u64 gen_fin = READ_ONCE(a->porder_lock.gen_fin);
  if (gen_fin == cd->porder_lock.gen) { // already synced
    lstat_record(&lctx, &a->stats[cid].sync_porder_cached);
    return false;
  }
  
  // copy data from global to local
  smp_rmb();
  copy_porder(a->porder, cd->porder_sync_buff);
  smp_rmb();
  
  u64 gen_beg = READ_ONCE(a->porder_lock.gen_beg);
  if (gen_beg != gen_fin) { // update failed due to write during copy
    lstat_record(&lctx, &a->stats[cid].sync_porder_fail);
    return false;
  }
  
  // copied data is consistent, update local porder
  copy_porder(cd->porder_sync_buff, cd->porder);
  cd->porder_lock.gen = gen_fin;
  
  lstat_record(&lctx, &a->stats[cid].sync_porder_update);
  return true;
}

// NOTE: assume sub_attach, sub_detach, and cpuctl_set_weight are done sequentially

static __always_inline s32 jlfp_sub_attach_core(struct jlfp_arena __arena *a, struct scx_sub_attach_args *args) {
  TRACE_FUNC_START("sub_attach");
  
  struct latency_ctx lctx;
  lstat_start(&lctx);
  
  u32 cid = scx_bpf_this_cid();
  u64 sub_cgroup_id = args->ops->sub_cgroup_id;

  // kernel should not call sub_attach on attached cgroup so no need to check for duplicates
  struct sub_sched_ctx __arena *sub = sub_lookup(&a->scx, 0);
  if (unlikely(!sub)) {
    scx_bpf_error("sub attach: MAX SUBS EXCEEDED");
    return -ENOMEM;
  }

  sub->cgroup_id = sub_cgroup_id;
  sub->weight = cgroup_curr_weight(sub_cgroup_id);
  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - a->scx.sub_scheds;
    e->cgrp_id = sub->cgroup_id;
    e->weight = sub->weight;
  );

  update_porder(a, cid, sub - a->scx.sub_scheds);

  // debug output cmask
  // bpf_printk("[INFO] [JLFP] [SUB_ATTACH] cgroup=%llu weight=%llu cmask=%016llx", sub_cgroup_id, sub->weight, cmask_to_u64(&a->scx.self_cids.mask));

  scx_bpf_sub_grant(sub_cgroup_id, SCX_CAP_ENQ_IMMED | SCX_CAP_ENQ | SCX_CAP_PREEMPT, (void *)(long)&a->scx.self_cids.mask, NULL);

  lstat_record(&lctx, &a->stats[cid].sub_attach);
  TRACE_FUNC_END("sub_attach", "");
  return 0;
}

static __always_inline void jlfp_sub_detach_core(struct jlfp_arena __arena *a, struct scx_sub_detach_args *args) {
  TRACE_FUNC_START("sub_detach");

  struct latency_ctx lctx;
  lstat_start(&lctx);

  u32 cid = scx_bpf_this_cid();
  u64 sub_cgroup_id = args->ops->sub_cgroup_id;
  struct sub_sched_ctx __arena *sub = sub_lookup(&a->scx, sub_cgroup_id);
  if (unlikely(!sub)) { // for verifier, should not happen
    TRACE_FUNC_END("sub_detach", "NOT ATTACHED");
    return;
  }

  sub->cgroup_id = 0;
  sub->weight = 0;
  update_porder(a, cid, sub - a->scx.sub_scheds);

  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - a->scx.sub_scheds;
    e->cgrp_id = 0;
    e->weight = 0;
  );

  lstat_record(&lctx, &a->stats[cid].sub_detach);
  TRACE_FUNC_END("sub_detach", "");
}

static __always_inline void jlfp_cpuctl_set_weight_core(struct jlfp_arena __arena *a, struct cgroup *cgrp, u32 weight) {
  TRACE_FUNC_START("cpuctl_set_weight");

  u64 sub_cgroup_id = cgrp->kn->id;
  TRACE_EVENT(struct sched_trace_event_set_weight_args, SCHED_TRACE_SET_WEIGHT_ARGS,
    e->cgrp_id = sub_cgroup_id;
    e->weight = weight;
  );

  struct latency_ctx lctx;
  lstat_start(&lctx);

  u32 cid = scx_bpf_this_cid();

  if (sub_cgroup_id == a->scx.cgroup_id) {
    a->scx.self_cgroup_weight = weight;
    TRACE_FUNC_END("cpuctl_set_weight", "SELF");
    return; // self not in subs
  }

  struct sub_sched_ctx __arena *sub = sub_lookup(&a->scx, sub_cgroup_id);
  if (!sub) {
    TRACE_FUNC_END("cpuctl_set_weight", "NOT ATTACHED");
    return;
  }

  sub->weight = weight;
  TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
    e->idx = sub - a->scx.sub_scheds;
    e->cgrp_id = sub->cgroup_id;
    e->weight = sub->weight;
  );
  update_porder(a, cid, sub - a->scx.sub_scheds);

  lstat_record(&lctx, &a->stats[cid].cpuctl_weight_update);

  TRACE_FUNC_END("cpuctl_set_weight", "");
}

// try an eligible global dsq task that beats prev, otherwise resume runnable prev
// returns the chosen task pid, or zero when no task can run
static __always_inline u64 jlfp_try_task_dispatch(struct jlfp_arena __arena *a, u32 cid, struct task_struct *prev, u64 slice, u64 prev_priority) {
  TRACE_FUNC_START("jlfp_try_task_dispatch")
  if (unlikely(cid >= NR_CPUS)) return false; // for verifier, should not happen

  // if prev task has a weight and is runnable, need to consider it
  weight_tuple_t prev_weight = 0;
  u32 scx_flags = prev ? BPF_CORE_READ(prev, scx.flags) : 0;
  task_ctx_t *pctx = NULL;
  if (scx_flags & SCX_TASK_QUEUED) {
    pctx = get_task_ctx(prev);
    if (likely(pctx)) {
      // refresh before comparison so weight changes also apply when prev resumes directly
      prev_weight = WT_FROM_FIELDS(prev_priority, is_migration_disabled(prev), a->scx.self_cgroup_weight, 0);
      get_jlfp_task_ctx(pctx)->weight = prev_weight;
    }
  }

  struct latency_ctx lctx;
  lstat_start(&lctx);

  // move highest weight in global dsq that can run on this cpu to local dsq
  struct task_struct *t;
  bool moved = false;
  u64 moved_pid = 0;
  u64 moved_weight = 0;
  bpf_for_each(scx_dsq, t, a->dsq_id, 0) {
    task_ctx_t *tctx = get_task_ctx(t);
    if (unlikely(!tctx)) continue; // for verifier, should not happen

    // since tasks ordered by decreasing weight in gdsq, early exit if weight can't beat prev
    if (prev_weight && WT_STRIP_MISC(get_jlfp_task_ctx(tctx)->weight) <= prev_weight) {
      break;
    }

    // skip tasks that can't run on this cpu (either due to cmask or is non-migratable on another cpu)
    if (!cmask_test(cid, &tctx->cpus_allowed) ||
      (is_migration_disabled(t) && scx_bpf_task_cid(t) != cid)) {
      // HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_gdsq_iter, SCHED_TRACE_DISPATCH_GDSQ_ITER,
      //   e->result = SCHED_TRACE_DISPATCH_GDSQ_ITER_CMASK_MISMATCH;
      //   e->tid = t->pid;
      //   e->weight = WT_LOWER_FROM_VTIME(t->scx.dsq_vtime);
      // );
      continue;
    }

    // this move only fails if another cpu's dispatch claims the task first
    if (likely(scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0))) {
      moved = true;
      moved_pid = t->pid;
      moved_weight = get_jlfp_task_ctx(tctx)->weight;
      // HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_gdsq_iter, SCHED_TRACE_DISPATCH_GDSQ_ITER,
      //   e->result = SCHED_TRACE_DISPATCH_GDSQ_ITER_SUCCESS;
      //   e->tid = t->pid;
      //   e->weight = WT_LOWER_FROM_VTIME(t->scx.dsq_vtime);
      // );
      break;
    }

    // HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_gdsq_iter, SCHED_TRACE_DISPATCH_GDSQ_ITER,
    //   e->result = SCHED_TRACE_DISPATCH_GDSQ_ITER_MOVE_FAIL;
    //   e->tid = t->pid;
    //   e->weight = WT_LOWER_FROM_VTIME(t->scx.dsq_vtime);
    // );
  }

  lstat_record(&lctx, &a->stats[cid].task_dispatch);

  // rerun the previous task
  if (!moved && prev_weight && likely(prev && pctx)) {
    moved = true;
    moved_pid = prev->pid;
    moved_weight = WT_LOWER(prev_weight);
    scx_bpf_task_set_slice(prev, slice);
  }

  TRACE_FUNC_END("jlfp_try_task_dispatch", moved ? "MOVED" : "NOT MOVED");

  if (moved) {
    HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_result, SCHED_TRACE_DISPATCH_RESULT,
      e->sub_dispatch = false;
      e->prev_tid = prev ? prev->pid : 0;
      e->prev_weight = prev_weight;
      e->next_tid = moved_pid;
      e->next_weight = moved_weight;
    );
  }

  return moved_pid;
}

static __always_inline void jlfp_dispatch_core(struct jlfp_arena __arena *a, s32 cid, struct task_struct *prev, u64 slice, u64 prev_priority) {
  if (unlikely(cid >= NR_CPUS)) return; // for testing limited CPUs

  // bpf_printk("[INFO] [JLFP] [DISPATCH] dispatching on cpu %u", cpu);
  TRACE_FUNC_START("dispatch");

  struct latency_ctx lctx;
  lstat_start(&lctx);

  cid = cid & (NR_CPUS - 1); // for verifier

  // dispatch task
  u64 tid = jlfp_try_task_dispatch(a, cid, prev, slice, prev_priority);
  if (tid) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    TRACE_FUNC_END("dispatch", prev && tid == prev->pid ? "DISPATCHED PREV" : "DISPATCHED TASK");
    return;
  }

  // dispatch cgroups if no tasks
  struct latency_ctx lctx_sub;
  lstat_start(&lctx_sub);

  sync_porder(a, cid);
  struct cid_data __arena *cd = &a->cid_data[cid];
  u32 i;
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    u32 idx = cd->porder[i] & (MAX_SUB_SCHEDS - 1);
    u64 sub_cgroup_id = a->scx.sub_scheds[idx].cgroup_id;

    if (sub_cgroup_id == 0) { // empty slots at lowest priority
      break;
    }

    cd->curr_idx = idx;
    if (scx_bpf_sub_dispatch(sub_cgroup_id)) {
      lstat_record(&lctx_sub, &a->stats[cid].sub_dispatch);
      lstat_record(&lctx, &a->stats[cid].dispatch);
      TRACE_FUNC_END("dispatch", "DISPATCHED CGROUP");

      HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_result, SCHED_TRACE_DISPATCH_RESULT,
        e->sub_dispatch = true;
        e->prev_tid = prev ? prev->pid : 0;
        e->next_tid = idx;
        e->next_weight = a->scx.sub_scheds[idx].weight;
      );
      return;
    }
  }

  lstat_record(&lctx, &a->stats[cid].dispatch);
  TRACE_FUNC_END("dispatch", "NO READY SUBS");
  if (prev) {
    HOTPATH_TRACE_EVENT(struct sched_trace_event_dispatch_result, SCHED_TRACE_DISPATCH_RESULT,
      e->sub_dispatch = false;
      e->prev_tid = prev ? prev->pid : 0;
      e->next_tid = 0;
      e->next_weight = 0;
    );
    return; // no sub schedulers
  }
}

// caller supplies task priority; jlfp_pick_cid adds migration and cgroup priority fields
// inserts directly into a local or global dsq from select_cid or enqueue
// insertion from select_cid skips the enqueue callback
static void __always_inline jlfp_pick_cid(struct jlfp_arena __arena *a, struct task_struct *p, u32 prev_cid, u64 enq_flags, u64 priority, u64 slice, bool global_search) {
  TRACE_FUNC_START("jlfp_pick_cid");

  struct latency_ctx lctx;
  lstat_start(&lctx);

  uint8_t dispatch_type = 0; // 0 = prev cid (idle or nmig), 1 = nearest idle, 2 = min weight preemption

  if (enq_flags & SCX_TASK_REENQ_CAP) {
    scx_bpf_error("capability issue: pid=%d enq_flags=%llu", p->pid, enq_flags);
    return;
  }

  prev_cid = prev_cid & (NR_CPUS - 1); // for verifier

  // setup
  u32 target_cid = prev_cid;
  bool nmig = is_migration_disabled(p);
  weight_tuple_t task_weight = WT_FROM_FIELDS(priority, nmig, a->scx.self_cgroup_weight, 0);
  task_ctx_t *tctx = get_task_ctx(p);
  bool weight_changed = get_jlfp_task_ctx(tctx)->weight != task_weight;
  get_jlfp_task_ctx(tctx)->weight = task_weight;

  // handle case where task was re-enqueued from enq_immed
  // this happens when its pending_cid is still set
  if (get_jlfp_task_ctx(tctx)->pending_cid < NR_CPUS) {
    u32 pending_cid = get_jlfp_task_ctx(tctx)->pending_cid;
    u32 pending_shard = a->scx.topo.cids[pending_cid].shard_idx;
    if (unlikely(pending_shard >= NR_CPUS)) {
      scx_bpf_error("Invalid pending shard %u", pending_shard);
      return;
    }
    u32 shard_offset = pending_cid - a->scx.topo.shards[pending_shard].base_cid;
    if (unlikely(pending_cid < a->scx.topo.shards[pending_shard].base_cid || shard_offset >= SCX_CID_SHARD_MAX_CPUS)) {
      scx_bpf_error("Failed to fetch pending cid %u or pending shard %u", pending_cid, pending_shard);
      return;
    }
    struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &pending_shard);
    if (unlikely(!sctx)) {
      scx_bpf_error("Failed to lookup pending shard %u", pending_shard);
      return;
    }
    if (unlikely(bpf_res_spin_lock(&sctx->lock))) {
      scx_bpf_error("Failed to lock pending shard %u", pending_shard);
      goto dispatch_fail;
    }

    // SHARD LOCK CS START

    if (sctx->cid_pending_owner[shard_offset] == p->scx.tid) {
      set_pending_weight_locked(a, pending_cid, pending_shard, 0, sctx, 0);
    }
    bpf_res_spin_unlock(&sctx->lock);

    // SHARD LOCK CS END
    get_jlfp_task_ctx(tctx)->pending_cid = NR_CPUS;
  }

  // IDLE SEARCH

  // prev cid
  if (likely(cmask_test(prev_cid, &tctx->cpus_allowed))) {
    if (likely(cmask_test_and_clear(prev_cid, &a->scx.idle_cids.mask))) {
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
    if (task_weight <= get_effective_weight(a, prev_cid)) goto dispatch_fail;

    goto dispatch;
  }

  dispatch_type = 1;

  // nearest idle cpu in numa topology
  u32 prev_shard = a->scx.topo.cids[prev_cid].shard_idx & (NR_CPUS - 1);
  u32 __arena *order = a->scx.topo.shards[prev_shard].shard_dist_order;
  u32 i;
  bpf_for(i, 0, a->scx.topo.nr_shards) {
    if (unlikely(i >= NR_CPUS)) break; // for verifier, should not happen

    u32 shard = order[i] & (NR_CPUS - 1);
    u32 cid = a->scx.topo.shards[shard].base_cid;

    // from qmap
    bpf_repeat(IDLE_PICK_RETRIES) {
      cid = cmask_next_and2_set_wrap(&tctx->cpus_allowed,
                  &a->scx.idle_cids.mask,
                  &a->scx.self_cids.mask, cid);

      barrier_var(cid);

      if (cid >= a->scx.topo.shards[shard].base_cid + a->scx.topo.shards[shard].nr_cids) break; // no idle
      if (likely(cmask_test_and_clear(cid, &a->scx.idle_cids.mask))) {
        target_cid = cid;
        goto dispatch;
      }
      ++cid;
    }
  }

  // MIN WEIGHT SEARCH
  // find target shard:
  // - if global_search is enabled: search min weight across all fully-overlapped shards and target that shard
  // - otherwise, or if no candidate has lower effective weight: target previous shard
  // find target cid:
  // - lock target shard
  // - find min weight cid in shard
  // - if affinity allows and task weight beats the minimum, reserve pending weight and release lock
  // - continue to dispatch (either to target cid or gdsq)

  dispatch_type = 2;

  // find min weight shard (no locking)
  // tiebreak based on shard distance from prev_cid by traversing using shard_dist_order
  u32 target_shard = prev_shard;
  if (global_search) {
    u32 cid = scx_bpf_this_cid() & (NR_CPUS - 1);
    struct cid_data __arena *cd = &a->cid_data[cid];
    weight_tuple_t min_effective = U128_MAX; // min over full overlap shards
    cmask_andnot(&cd->tmp_cmask.mask, &cd->tmp_cmask.mask); // use tmp cmask to store candidate shards
    bool partial_exists = false;
    bpf_for(i, 0, a->scx.topo.nr_shards) {
      if (unlikely(i >= NR_CPUS)) break; // for verifier, should not happen

      // check if full overlapped
      if (!cmask_subset(&a->scx.shard_cids[order[i] & (NR_CPUS - 1)].mask, &tctx->cpus_allowed)) {
        continue;
      }

      u32 shard = order[i] & (NR_CPUS - 1);
      struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &shard);
      if (unlikely(!sctx)) continue; // for verifier, should not happen

      // unlocked effective-weight hint; recheck the chosen shard under its lock
      barrier_var(sctx);
      weight_tuple_t shard_min_effective = READ_ONCE(sctx->min_effective);
      barrier_var(shard_min_effective);

      if (WT_STRIP_MISC(shard_min_effective) < WT_STRIP_MISC(min_effective)) {
        min_effective = shard_min_effective;
        target_shard = shard;
      }
    }

    if (partial_exists) {
      bpf_printk("WARNING: task %d has partial shard overlap, partial shards skipped", p->pid);
    }
    if (WT_STRIP_MISC(min_effective) >= task_weight) {
      // fall back on previous shard
      target_shard = prev_shard;
    }
  }

  struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &target_shard);
  if (unlikely(!sctx)) goto dispatch_fail; // for verifier, should not happen

  if (unlikely(bpf_res_spin_lock(&sctx->lock))) {
    scx_bpf_error("Failed to lock target shard %u", target_shard);
    goto dispatch_fail;
  }

  // SHARD LOCK CS START

  u128 min_weight = WT_STRIP_MISC(sctx->min_effective);
  target_cid = WT_MISC(sctx->min_effective);

  if (prev_shard == target_shard) {
    // if min weight matches prev cid's weight, prefer it even if min_cid is different (tie break)
    u32 shard_offset = prev_cid - a->scx.topo.shards[target_shard].base_cid;
    if (unlikely(shard_offset >= SCX_CID_SHARD_MAX_CPUS)) { // for verifier, should not happen
      bpf_res_spin_unlock(&sctx->lock);
      goto dispatch_fail;
    }

    u128 prev_cid_weight = sctx_get_effective_weight(sctx, shard_offset);
    if (prev_cid_weight == min_weight) {
      target_cid = prev_cid;
    }
  }

  // if outside cmask, add to gdsq instead since assuming tasks have shard aligned cpusets
  if (!cmask_test(target_cid, &tctx->cpus_allowed) || task_weight <= min_weight) {
    bpf_res_spin_unlock(&sctx->lock);
    goto dispatch_fail;
  }

  // reserve cid
  set_pending_weight_locked(a, target_cid, target_shard, task_weight, sctx, p->scx.tid);
  get_jlfp_task_ctx(tctx)->pending_cid = target_cid;
  bpf_res_spin_unlock(&sctx->lock);

  // SHARD LOCK CS END

  goto dispatch;

  // DISPATCH
  // running weight is updated by jlfp_running_core after the task starts

  dispatch:
  // SCX_ENQ_PREEMPT handles the kicking
  scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (target_cid & (NR_CPUS - 1)), slice, SCX_ENQ_PREEMPT | SCX_ENQ_IMMED);

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, dispatch_type == 0 ? &a->stats[cid].pick_cid_prev : dispatch_type == 1 ? &a->stats[cid].pick_cid_idle : &a->stats[cid].pick_cid_search);
  TRACE_FUNC_END("jlfp_pick_cid", "");
  goto pick_cid_end;

  // NO DISPATCH
  dispatch_fail:

  target_cid = NR_CPUS;

  // enqueue to global dsq instead
  u64 vtime = WT_VTIME_FROM_LOWER(WT_LOWER(task_weight));
  scx_bpf_dsq_insert_vtime(p, a->dsq_id, slice, vtime, enq_flags);

  cid = scx_bpf_this_cid();
  lstat_record(&lctx, dispatch_type == 0 ? &a->stats[cid].pick_cid_prev : dispatch_type == 1 ? &a->stats[cid].pick_cid_idle : &a->stats[cid].pick_cid_search);
  TRACE_FUNC_END("jlfp_pick_cid", "GLOBAL DSQ");

  pick_cid_end:

  if (unlikely(weight_changed)) {
    TRACE_EVENT(struct sched_trace_event_set_task_weight, SCHED_TRACE_SET_TASK_WEIGHT,
      e->tid = p->pid;
      e->weight = task_weight;
    );
  }

  HOTPATH_TRACE_EVENT(struct sched_trace_event_pick_cid_result, SCHED_TRACE_PICK_CID_RESULT,
    enum sched_trace_pick_cid_type type;
    switch (dispatch_type) {
      case 0:
        type = nmig ? SCHED_TRACE_PICK_CID_NMIG : SCHED_TRACE_PICK_CID_PREV_IMMED;
        break;
      case 1:
        type = SCHED_TRACE_PICK_CID_IDLE;
        break;
      case 2:
        type = SCHED_TRACE_PICK_CID_SEARCH;
        break;
      default: // should not happen
        type = SCHED_TRACE_PICK_CID_NMIG;
        break;
    }
    e->type = type;
    e->tid = p->pid;
    e->enq_flags = enq_flags;
    e->prev_cid = prev_cid;
    e->target_cid = target_cid == NR_CPUS ? -1 : target_cid;
  );
}

static __always_inline void jlfp_running_core(struct jlfp_arena __arena *a, struct task_struct *p, task_ctx_t *tctx, weight_tuple_t wt, struct latency_ctx *lctx) {
  u32 cid = scx_bpf_this_cid();
  // update running weight and clear pending weight
  u32 shard = a->scx.topo.cids[cid & (NR_CPUS - 1)].shard_idx;
  struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &shard);
  if (unlikely(!sctx)) return; // for verifier, should not happen

  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  if (unlikely(bpf_res_spin_lock(&sctx->lock))) {
    scx_bpf_error("Failed to lock shard %u", shard);
    return;
  }

  // SHARD LOCK CS START

  sctx->cid_running_weight[shard_offset] = wt;
  if (sctx->cid_pending_owner[shard_offset] == p->scx.tid) {
    // only clear pending if this is the pending owner
    // case where its not owner: this task won the race to local dsq and pending owner got re-enqueued
    // in this case, pending owner will clear its pending status in jlfp_pick_cid
    sctx->cid_pending_weight[shard_offset] = 0;
    sctx->cid_pending_owner[shard_offset] = 0;
  }
  update_min_effective_locked(a, cid, shard, sctx);

  bpf_res_spin_unlock(&sctx->lock);

  // SHARD LOCK CS END

  if (likely(tctx)) get_jlfp_task_ctx(tctx)->pending_cid = NR_CPUS;
  lstat_record(lctx, &a->stats[cid].running);

  HOTPATH_TRACE_EVENT(struct sched_trace_event_running, SCHED_TRACE_RUNNING,
    e->tid = p->pid;
    e->weight = WT_LOWER(wt);
  );
}

static __always_inline void jlfp_stopping_core(struct jlfp_arena __arena *a, struct task_struct *p, bool runnable) {
  if (unlikely(!p)) { // for verifier, should not happen
    scx_bpf_error("Stopping task is NULL");
    return;
  }
  struct latency_ctx lctx;
  lstat_start(&lctx);

  u32 cid = scx_bpf_this_cid();

  // update running weight only
  u32 shard = a->scx.topo.cids[cid & (NR_CPUS - 1)].shard_idx;
  struct shard_ctx *sctx = bpf_map_lookup_elem(&shard_ctx_map, &shard);
  if (unlikely(!sctx)) { // for verifier, should not happen
    scx_bpf_error("Failed to lookup sctx");
    return;
  }

  u32 shard_offset = cid - a->scx.topo.shards[shard].base_cid;
  if (unlikely(shard_offset >= SCX_CID_SHARD_MAX_CPUS)) return; // for verifier, should not happen

  if (unlikely(bpf_res_spin_lock(&sctx->lock))) {
    scx_bpf_error("Failed to lock shard %u", shard);
    return;
  }

  // SHARD LOCK CS START

  set_running_weight_locked(a, cid, shard, 0, sctx);
  bpf_res_spin_unlock(&sctx->lock);

  // SHARD LOCK CS END

  lstat_record(&lctx, &a->stats[cid].stopping);

  HOTPATH_TRACE_EVENT(struct sched_trace_event_stopping, SCHED_TRACE_STOPPING,
    e->tid = p->pid;
    e->runnable = runnable;
  );
}


#endif
