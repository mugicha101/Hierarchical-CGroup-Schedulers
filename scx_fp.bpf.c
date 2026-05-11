#include <scx/common.bpf.h>

#include "trace_events.h"
CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// job-level fixed priority scheduler
// prioritized by weight (higher weight = higher priority)
// tie breaks handled arbitrarily

// prioritize tasks over cgroups

// cgroups:
// can use same system as wrr but keep track of priority order in a local sorted array (sorting is slow)
// optimization 1: if none if system sync with new data, can re-use prior order (still needs to check all entries)
// optimization 2: another seqlock tells if any entry has changed in global, so can skip syncing all entries if epoch is unchanged
// note: priority >= 1 (set_cgroup_weight limited to weight >= 1 anyways)

// tasks:
// use global vtime queue and per-cpu single element staging queues
// enqueue
//   adds to global dsq
//   finds min priority running task that isn't marked as kicked
//   preempts that CPU, updates priority of that CPU, marks as kicked
// dispatch
//   pulls highest priority in global dsq

const volatile u64 cgroup_id;
u64 self_cgroup_weight;

#define CPU_LIMIT 2 // for testing, limit CPUs to run on
#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_WEIGHT 1
#define MAX_PENDING_UPDATES 1024
#define TIMER_INTERVAL_NS (1 * 1000000ULL) // 1ms
#define NTRIALS 100 // enough trials to be functionally infinite for rare race-conditioned events
// #define CPUSET_SIZE NR_CPUS / 64

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

UEI_DEFINE(uei);

// seqlock implementation
// single writer multiple reader lock-free structure
// allows global data to sync with local data
// can be nested inside another seqlock s.t. syncs only occur if all in the chain are consistent
// parent seqlocks only need to update when update not contained in a single nested seqlock
// need to call sync on nested synclocks, cannot call sync on just parent synclock for data to be protected
struct seqlock_global {
	__u64 gen_fin; // incremented when update ends (generation of the last finished update)
	__u64 gen_beg; // incremented when update begins (generation of the last started update)
};

struct seqlock_local {
	__u64 gen;
};

inline void seqlock_update_start(struct seqlock_global *g) {
	WRITE_ONCE(g->gen_beg, g->gen_beg + 1);
	smp_wmb();
}

inline void seqlock_update_end(struct seqlock_global *g) {
	smp_wmb();
	WRITE_ONCE(g->gen_fin, g->gen_fin + 1);
}

struct sub_params {
	__u64 cgrp_id;
  __u64 weight; 
};

struct global_sub_params {
	struct sub_params sp;
	struct seqlock_global lock;
};

struct local_sub_params {
	struct sub_params sp;
	struct seqlock_local lock;
};

// data only accessed by its own CPU, no locking needed
struct cpu_sched_state {
  __u64 local_gen; // for checking if global_gen updated
	u32 curr_idx; // index of currently running subscheduler
  u64 priority[MAX_SUB_SCHEDS]; // cached priorities of subs
  int porder[MAX_SUB_SCHEDS]; // cached indices of subs in decreasing priority order
};

// data used for global task scheduling decisions, locked by global_task_lock
struct cpu_task_state {
	u64 running_weight; // weight of currently running task on this CPU (0 if no task or running a sub cgroup, ~0 if unknown weight
	bool kicked; // whether CPU already kicked and waiting on dispatch (prevents redundant kicks)
	u64 cgrp_weight; // last known cgroup weight of running task (impacted by other schedulers)
};

// data shared between all cores
struct global_data {
	// concurrency: single writer, multiple readers
	struct bpf_spin_lock global_subs_write_lock;
	struct global_sub_params global_subs[MAX_SUB_SCHEDS];
	__u64 global_gen; // incremented after new data written to
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_data);
} global SEC(".maps");

// lock-protected global task data
struct global_task_data {
	struct bpf_spin_lock global_task_lock; // locks both cpu_task_states and global task dsq
	struct cpu_task_state cpu_task_states[NR_CPUS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_task_data);
} global_task_data SEC(".maps");

// used to get cgroup weight on attach
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} cgroup_weights SEC(".maps");

// synced with global_subs
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_SUB_SCHEDS);
	__type(key, u32);
	__type(value, struct local_sub_params);
} local_subs SEC(".maps");

// per-cpu scheduling data
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_CPUS);
	__type(key, u32);
	__type(value, struct cpu_sched_state);
} sched_state SEC(".maps");

inline struct global_data *fetch_global() {
	const u32 idx = 0;
	return bpf_map_lookup_elem(&global, &idx);
}

inline struct global_task_data *fetch_global_task_data() {
	const u32 idx = 0;
	return bpf_map_lookup_elem(&global_task_data, &idx);
}

// global weight of each task (should not change after enqueue due to fixed priority, re-enqueue if does change)
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} task_weights SEC(".maps");

// seqlock sync
// sync local sp to global sp if global sp is consistent
// local copies (gen_fin, sp, gen_beg) in that order
// if gen_fin = gen_beg, then update finished by start of copy and no new update arrived by end of copy
// thus if gen_fin = gen_beg, data is consistent and of generation gen_fin = gen_beg
// so local sp updated with copied global sp
// if this is not the case, this update is ignored until the next sync
static __always_inline bool sync_local_sub(struct global_sub_params *global_subs, u32 idx) {
	if (idx >= MAX_SUB_SCHEDS) return false;

	struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &idx);
	if (unlikely(!lsp)) return false; // for verifier, should not happen

	struct global_sub_params *gsp = &global_subs[idx & (MAX_SUB_SCHEDS - 1)];

	struct sub_params tmp_data;
	u64 gen_fin = READ_ONCE(gsp->lock.gen_fin);
	if (gen_fin == lsp->lock.gen) return false;
	
	smp_rmb();
	tmp_data.cgrp_id = gsp->sp.cgrp_id;
	tmp_data.weight = gsp->sp.weight;
	smp_rmb();
	
	u64 gen_beg = READ_ONCE(gsp->lock.gen_beg);
	if (gen_beg != gen_fin) return false;

	lsp->sp.cgrp_id = tmp_data.cgrp_id;
	lsp->sp.weight = tmp_data.weight;
	u64 old_gen = lsp->lock.gen;
	lsp->lock.gen = gen_fin;
	// bpf_printk("[INFO] [FP] [SYNC] cpu %d: Synced index %u: gen %llu -> gen %llu (new weight: %llu)", bpf_get_smp_processor_id(), idx, old_gen, gen_fin, lsp->sp.weight);

	return true;
}

u64 dsq_id = 0; // id of global vtime-based task dsq
s32 BPF_STRUCT_OPS_SLEEPABLE(fp_init)
{
	// bpf_printk("[INFO] [FP] [INIT] Initializing SCX FP Scheduler");
	TRACE_FUNC_START("init");
	
	// init cgroup data structs
	self_cgroup_weight = DEFAULT_WEIGHT;
	u32 err = 0;
	u32 cpu;
	bpf_for(cpu, 0, CPU_LIMIT) {
		struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
		if (unlikely(!ss)) return -EINVAL; // for verifier, should not happen
		
    u32 i;
    bpf_for(i, 0, MAX_SUB_SCHEDS) {
      ss->porder[i] = i;
    }
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

void BPF_STRUCT_OPS(fp_exit)
{
	bpf_printk("[INFO] [FP] [EXIT] Exiting SCX FP Scheduler\n");
}

// looks for cgroup in global_subs
// returns true iff exists
// if exists, res := address of it in subs
// otherwise, res := address of the first free location (NULL if no free location)
// special case if cgrp_id is 0: returns true and first free location if exists, false if no more free locations
// does not handle locking
// assigns index of res to res_idx if not null (if res = NULL, assigns it MAX_SUB_SCHEDS)
bool global_sub_lookup(struct global_sub_params *global_subs, u64 cgrp_id, struct global_sub_params **res, u32 *res_idx) {
	struct global_sub_params *first_free = NULL;
	u32 first_free_idx = MAX_SUB_SCHEDS;
	for (u32 idx = 0; idx < MAX_SUB_SCHEDS; ++idx) {
		struct global_sub_params *gsp = &global_subs[idx];
		if (unlikely(!gsp)) continue; // for verifier, should not happen
		if (gsp->sp.cgrp_id == cgrp_id) {
			*res = gsp;
			if (res_idx) *res_idx = idx;
			return true;
		}
		if (gsp->sp.cgrp_id == 0 && first_free_idx == MAX_SUB_SCHEDS) {
			first_free = gsp;
			first_free_idx = idx;
		}
	}
	*res = first_free;
	if (res_idx) *res_idx = first_free_idx;
	return false;
}

// NOTE: assume sub_attach, sub_detach, and cgroup_set_weight are done sequentially

s32 BPF_STRUCT_OPS(fp_sub_attach, struct scx_sub_attach_args *args)
{
	u64 cgrp_id = args->ops->sub_cgroup_id;
	TRACE_FUNC_START("sub_attach");
	// bpf_printk("[INFO] [FP] [SUB_ATTACH] Attaching cgroup %llu", cgrp_id);
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return -EINVAL; // for verifier, should not happen

	u32 *cached_weight = bpf_map_lookup_elem(&cgroup_weights, &cgrp_id);
	u64 weight = cached_weight ? *cached_weight : DEFAULT_WEIGHT;
	
	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (global_sub_lookup(global_subs, cgrp_id, &gsp, NULL)) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [FP] [SUB_ATTACH] %llu already attached", cgrp_id);
		TRACE_FUNC_END("sub_attach", "ALREADY ATTACHED");
		return -EEXIST;
	}
	if (!gsp) {
		bpf_spin_unlock(global_subs_write_lock);
		// bpf_printk("[INFO] [FP] [SUB_ATTACH] %llu attaching sub would exceed MAX_SUB_SCHEDS", cgrp_id);
		TRACE_FUNC_END("sub_attach", "MAX SUBS EXCEEDED");
		return -ENOMEM;
	}

	seqlock_update_start(&gsp->lock);
	
	gsp->sp.cgrp_id = cgrp_id;
	gsp->sp.weight = weight;
	
	seqlock_update_end(&gsp->lock);

	global->global_gen++;
	
	bpf_spin_unlock(global_subs_write_lock);
	// bpf_printk("[INFO] [FP] [SUB_ATTACH] cgroup %llu attached with weight %llu", cgrp_id, weight);
	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	
	TRACE_FUNC_END("sub_attach", "");
  return 0;
}

void BPF_STRUCT_OPS(fp_sub_detach, struct scx_sub_detach_args *args)
{
  u64 cgrp_id = args->ops->sub_cgroup_id;
	// bpf_printk("[INFO] [FP] [SUB_DETACH] Detaching cgroup %llu", cgrp_id);
	TRACE_FUNC_START("sub_detach");
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return; // for verifier, should not happen
	
	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (!global_sub_lookup(global_subs, cgrp_id, &gsp, NULL) || !gsp) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [FP] [SUB_DETACH] %llu not attached", cgrp_id);
		TRACE_FUNC_END("sub_detach", "NOT ATTACHED");
		return;
	}

	seqlock_update_start(&gsp->lock);

	gsp->sp.cgrp_id = 0;
	gsp->sp.weight = 0;
	
	seqlock_update_end(&gsp->lock);

	global->global_gen++;

	bpf_spin_unlock(global_subs_write_lock);

	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = 0;
		e->weight = 0;
	);
	TRACE_FUNC_END("sub_detach", "");
}

void BPF_STRUCT_OPS(fp_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgrp_id = cgrp->kn->id;
	if (cgrp_id == cgroup_id) {
		self_cgroup_weight = weight;
	}
	// bpf_printk("[INFO] [FP] [SET_WEIGHT] Setting cgroup %llu weight to %u", cgrp_id, weight);
	TRACE_FUNC_START("cgroup_set_weight");
	TRACE_EVENT(struct sched_trace_event_set_weight_args, SCHED_TRACE_SET_WEIGHT_ARGS,
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	bpf_map_update_elem(&cgroup_weights, &cgrp_id, &weight, BPF_ANY);
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return; // for verifier, should not happen

	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (!global_sub_lookup(global_subs, cgrp_id, &gsp, NULL) || !gsp) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [FP] [SET_WEIGHT] cgroup_set_weight %llu not attached", cgrp_id);
		TRACE_FUNC_END("cgroup_set_weight", "NOT ATTACHED");
		return;
	}
	
	seqlock_update_start(&gsp->lock);
	gsp->sp.weight = weight;
	seqlock_update_end(&gsp->lock);

	global->global_gen++;

	bpf_spin_unlock(global_subs_write_lock);
	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	TRACE_FUNC_END("cgroup_set_weight", "");
}

// re-purpose for assigning affinities
void BPF_STRUCT_OPS(fp_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	// bpf_printk("[INFP] [CGROUP_SET_BANDWIDTH] %llu period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, period_us, quota_us, burst_us);
}

// attempt to dispatch a task from global dsq to local dsq
static __always_inline bool try_task_dispatch(u32 cpu, struct global_task_data *global) {
	if (cpu >= NR_CPUS) return false; // for verifier, should not happen
	// return scx_bpf_dsq_move_to_local(dsq_id);
	
	TRACE_FUNC_START("try_task_dispatch");
	// then try fetching from global dsq
	// need to atomically move and get the weight of the task
	u64 peeked_weight = 0;
	bool moved_from_global = false;
	bool empty = false;
	u32 trials;
	bpf_for(trials, 0, NTRIALS) {
    struct task_struct *t;
		empty = true;
    bpf_for_each(scx_dsq, t, dsq_id, 0) {
			empty = false;
			peeked_weight = ~0ULL - t->scx.dsq_vtime;

			if (likely(scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0))) {
				moved_from_global = true;
			}
			break;
    }

		if (empty || moved_from_global) {
			break;
		}
	}
	
	// update running weight and kicked status
	// don't need to lock since enqueue skips tasks that aren't marked as kicked
	struct cpu_task_state *cts = &global->cpu_task_states[cpu];
	cts->running_weight = moved_from_global ? peeked_weight : 0;
	smp_wmb(); // must write kicked last to prevent enqueue from reading stale weight
	cts->kicked = false;
	if (empty) {
		TRACE_FUNC_END("try_task_dispatch", "GLOBAL DSQ EMPTY");
	} else if (moved_from_global) {
		TRACE_FUNC_END("try_task_dispatch", "DISPATCHED TASK");
	} else {
		TRACE_FUNC_END("try_task_dispatch", "FAILED TO DISPATCH");
	}
	return moved_from_global;
}

static __always_inline void sync_priority_order(struct global_data *global, struct cpu_sched_state *ss) {
  // skip if local_gen matches global_gen (no updates since last sync)
  u64 global_gen = global->global_gen;
  if (global_gen == ss->local_gen) return;

  // check each entry for updates
  u32 i;
  bool modified = false; // NOTE: correctness assumes this is the only place that calls sync_local_sub (otherwise can sync but not update priority)
	bpf_for(i, 0, MAX_SUB_SCHEDS) {
    modified = modified | sync_local_sub(global->global_subs, i);
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &i);
    if (unlikely(!lsp)) break; // for verifier, should not happen

    u32 safe_i = i & (MAX_SUB_SCHEDS - 1);
    ss->priority[safe_i] = lsp->sp.weight;
	}
  if (!modified) return; // no updates after syncing, so priority order unchanged

  // selection sort faster than quicksort for small MAX_SUB_SCHEDS
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    if (unlikely(i >= MAX_SUB_SCHEDS)) break; // for verifier, should not happen

    u32 j;
    bpf_for(j, i+1, MAX_SUB_SCHEDS) {
      u32 safe_i = i & (MAX_SUB_SCHEDS - 1);
      u32 safe_j = j & (MAX_SUB_SCHEDS - 1);
      u32 safe_oi = ss->porder[safe_i] & (MAX_SUB_SCHEDS - 1);
      u32 safe_oj = ss->porder[safe_j] & (MAX_SUB_SCHEDS - 1);
      if (ss->priority[safe_oj] > ss->priority[safe_oi]) {
        ss->porder[safe_i] = safe_oj;
        ss->porder[safe_j] = safe_oi;
      }
    }
  }
}

void BPF_STRUCT_OPS(fp_dispatch, s32 cpu, struct task_struct *prev)
{
	// FOR TESTING (limits CPUs to prevent freezing)
	if (cpu >= CPU_LIMIT) return;

	// bpf_printk("[INFO] [FP] [DISPATCH] dispatching on cpu %u", cpu);
	TRACE_FUNC_START("dispatch");

	u32 ucpu = cpu;
	struct global_data *global = fetch_global();
	struct global_task_data *global_task_data = fetch_global_task_data();
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	if (unlikely(!global) || unlikely(!ss) || unlikely(!global_task_data)) return; // for verifier, should not happen

	// dispatch task
	if (try_task_dispatch(cpu, global_task_data)) {
		TRACE_FUNC_END("dispatch", "DISPATCHED TASK");
		return;
	}

	// dispatch cgroups if no tasks
  sync_priority_order(global, ss);
	u32 i;
	bpf_for(i, 0, MAX_SUB_SCHEDS) {
		u32 idx = ss->porder[i];
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &idx);
		if (unlikely(!lsp)) return; // for verifier, should not happen

		if (lsp->sp.cgrp_id == 0) { // empty slots at lowest priority
			break;
		}

    ss->curr_idx = idx;
		if (scx_bpf_sub_dispatch(lsp->sp.cgrp_id)) {
			TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
				e->idx = idx;
				e->success = true;
			);
      TRACE_FUNC_END("dispatch", "DISPATCHED CGROUP");
      return;
    }
		TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
			e->idx = idx;
			e->success = false;
		);
	}
	TRACE_FUNC_END("dispatch", "NO READY SUBS");
	return; // no sub schedulers
}

s32 BPF_STRUCT_OPS(fp_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	// bpf_printk("[INFO] [FP] [CGROUP_INIT] %llu weight=%u period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, args->weight, args->bw_period_us,
				// args->bw_quota_us, args->bw_burst_us);
				
	TRACE_FUNC_START("cgroup_init");
	u64 cgrp_id = cgrp->kn->id;
	u32 weight = args->weight;
	if (cgrp_id == cgroup_id) {
		self_cgroup_weight = weight;
	}
	TRACE_EVENT(struct sched_trace_event_cgroup_init_args, SCHED_TRACE_CGROUP_INIT_ARGS,
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	bpf_map_update_elem(&cgroup_weights, &cgrp_id, &weight, BPF_ANY);
	TRACE_FUNC_END("cgroup_init", "");
	return 0;
}

// task scheduling functions that should not be called
s32 BPF_STRUCT_OPS(fp_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// bpf_printk("[INFO] [FP] fp_select_cpu called unexpectedly");
  // scx_bpf_error("fp_select_cpu called unexpectedly");
    return prev_cpu; // Required to return a valid CPU even when erroring
}

u64 __always_inline get_task_weight(struct task_struct *p) {
	u64 weight = DEFAULT_WEIGHT;
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

// assumes RCU lock held
void __always_inline update_cpu_cgroup_weight(u32 cpu, struct global_task_data *global) {
	if (cpu >= NR_CPUS) return; // for verifier, should not happen

	struct cpu_task_state *cts = &global->cpu_task_states[cpu];
	struct task_struct *cpu_task = scx_bpf_cpu_curr(cpu);
	if (unlikely(!cpu_task)) return; // for verifier, should not happen

	pid_t pid = BPF_CORE_READ(cpu_task, pid);
	if (pid == 0) {
		cts->cgrp_weight = 0; // idle task, treat as weight 0
		return;
	}

	// running task, fetch cgroup
	u64 cgrp_id = BPF_CORE_READ(cpu_task, cgroups, dfl_cgrp, kn, id);
	u32 *cgrp_weight = bpf_map_lookup_elem(&cgroup_weights, &cgrp_id);
	cts->cgrp_weight = cgrp_weight ? *cgrp_weight : DEFAULT_WEIGHT;
}

void BPF_STRUCT_OPS(fp_enqueue, struct task_struct *p, u64 enq_flags)
{
	TRACE_FUNC_START("enqueue");

	// determine weight of enqueued task
	u64 weight = get_task_weight(p);
	u64 vtime = ~0ULL - weight;

	// insert into global dsq
	scx_bpf_dsq_insert_vtime(p, dsq_id, SCX_SLICE_INF, vtime, enq_flags);
	// u32 cpu = bpf_get_smp_processor_id();
	// scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	// TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
	// 	e->cpu = cpu;
	// );
	
	struct global_task_data *global = fetch_global_task_data();
	if (unlikely(!global)) return; // for verifier, should not happen

	// find min priority unkicked CPU to kick
	// why unkicked? if two tasks try to kick same CPU, one might get starved on global dsq
	// worst case just an extra enqueue to sort out
	// should be rare since time between kick and dispatch is small
	// if all CPUs are kicked (extremely unlikely) try again
	u32 trials;
	bpf_for(trials, 0, NTRIALS) {
		// first fetch a snapshot of what cgroups each cpu is running to avoid preempting ones with higher weight
		// concurrent updates from multiple enqueues doesn't matter since they're reading the same thing
		// staleness bad but not critical, since worst case preempting higher weight cgroup will just go through dispatch again
		bpf_rcu_read_lock();
		u32 cpu;
		bpf_for(cpu, 0, CPU_LIMIT) {
			update_cpu_cgroup_weight(cpu, global);
		}
		bpf_rcu_read_unlock();

		u64 cached_self_cgroup_weight = self_cgroup_weight; // lock in self cgroup weight here to avoid changing mid-loop

		bpf_spin_lock(&global->global_task_lock); // prevent other enqueues from claiming same CPU
		u32 target_cpu = NR_CPUS;
		u64 target_cpu_weight = ~0ULL;
		bpf_for(cpu, 0, CPU_LIMIT) {
			struct cpu_task_state *cts = &global->cpu_task_states[cpu];
			u64 running_weight = cts->cgrp_weight > cached_self_cgroup_weight ? ~0ULL : cts->running_weight; // treat higher weight cgroups as infinitely heavy to avoid preempting them
			if (cts->kicked || running_weight >= target_cpu_weight) continue;
			target_cpu = cpu;
			target_cpu_weight = running_weight;
			if (target_cpu_weight == 0) break; // can't do better than an idle CPU
		}

		if (target_cpu < NR_CPUS) {
			// check if weight high enough
			if (target_cpu_weight >= weight) {
				bpf_spin_unlock(&global->global_task_lock);
				TRACE_FUNC_END("enqueue", "CANNOT KICK");
				break; // all CPUs have higher or equal weight, no need to kick
			}
			
			// kick CPU
			global->cpu_task_states[target_cpu].kicked = true;
			bpf_spin_unlock(&global->global_task_lock);
			scx_bpf_kick_cpu(target_cpu, (u64)SCX_KICK_PREEMPT);
			TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
				e->cpu = target_cpu;
			);
			break;
		}
		bpf_spin_unlock(&global->global_task_lock);
	}

	TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(fp_dequeue, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [FP] [DEQUEUE] dequeuing pid=%d", p->pid);
  // scx_bpf_error("fp_dequeue called unexpectedly");
}

void BPF_STRUCT_OPS(fp_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	// bpf_printk("[INFO] [FP] fp_cpu_acquire called unexpectedly");
  // scx_bpf_error("fp_cpu_acquire called unexpectedly");
}

void BPF_STRUCT_OPS(fp_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	// bpf_printk("[INFO] [FP] fp_cpu_release called unexpectedly");
  // scx_bpf_error("fp_cpu_release called unexpectedly");
}

void BPF_STRUCT_OPS(fp_running, struct task_struct *p)
{
	TRACE_FUNC_START("running");
  TRACE_EVENT(struct sched_trace_event_run_task, SCHED_TRACE_RUN_TASK,
		e->pid = p->pid;
	);

	// update running weight and kicked status
	// don't need to lock since enqueue skips tasks that aren't marked as kicked
	// u32 cpu = bpf_get_smp_processor_id();
	// struct global_task_data *global = fetch_global_task_data();
	// if (unlikely(!global)) return; // for verifier, should not happen
	
	// struct cpu_task_state *cts = &global->cpu_task_states[cpu];
	// cts->running_weight = ~0ULL - p->scx.dsq_vtime;
	// smp_wmb(); // must write kicked last to prevent enqueue from reading stale weight
	// cts->kicked = false;

	// TRACE_FUNC_END("running", "");
}

void BPF_STRUCT_OPS(fp_stopping, struct task_struct *p, bool runnable)
{
	TRACE_EVENT(struct sched_trace_event_stop_task, SCHED_TRACE_STOP_TASK,
		e->pid = p->pid;
	);
}

void BPF_STRUCT_OPS(fp_runnable, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("[INFO] [FP] fp_runnable called unexpectedly");
  // scx_bpf_error("fp_runnable called unexpectedly");
}

void BPF_STRUCT_OPS(fp_quiescent, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [FP] fp_quiescent called unexpectedly");
  // scx_bpf_error("fp_quiescent called unexpectedly");
}

s32 BPF_STRUCT_OPS(fp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	// bpf_printk("[INFO] [FP] fp_init_task called (pid: %u policy: %d)", p->pid, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(fp_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	// bpf_printk("[INFO] [FP] fp_exit_task called unexpectedly");
  // scx_bpf_error("fp_exit_task called unexpectedly");
}

// ops

SCX_OPS_DEFINE(fp_ops,
	// setup
	.name			= "fp",
	.init			= (void *)fp_init,
	.exit			= (void *)fp_exit,

	// flags:
	// SCX_OPS_SWITCH_PARTIAL: does not assign tasks to sched_ext by default
	// SCX_OPS_ENQ_LAST: if no work on subscheduler, enqueues current running task rather than continuing it and calls dispatch again
	//									 allows for skipping an idle sub and running next sub instead of continuing prev sub
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	// .dump			= (void *)fp_dump,

	// task scheduling (should not be called)
	.select_cpu		= (void *)fp_select_cpu,
	.enqueue		= (void *)fp_enqueue,
	.dequeue		= (void *)fp_dequeue,
	.cpu_acquire	= (void *)fp_cpu_acquire,
	.cpu_release	= (void *)fp_cpu_release,
	.running		= (void *)fp_running,
	.stopping		= (void *)fp_stopping,
	.runnable		= (void *)fp_runnable,
	.quiescent		= (void *)fp_quiescent,
	.init_task		= (void *)fp_init_task,
	.exit_task		= (void *)fp_exit_task,
	// .enable			= (void *)fp_enable,
	// .disable		= (void *)fp_disable,
	// .dump_task		= (void *)fp_dump_task,

	// subscheduling support
	.dispatch		= (void *)fp_dispatch,
	.cgroup_init		= (void *)fp_cgroup_init,

	// user cgroup interface
	.cgroup_set_weight	= (void *)fp_cgroup_set_weight,
	.cgroup_set_bandwidth	= (void *)fp_cgroup_set_bandwidth,
	.sub_attach		= (void *)fp_sub_attach,
	.sub_detach		= (void *)fp_sub_detach
);
