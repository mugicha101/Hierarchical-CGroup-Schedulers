#include <scx/common.bpf.h>

#include "trace_events.h"
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
// during select_cpu/enqueue, if task can preempt lower priority task / idle cpu, will kick it
// during dispatch, finds highest priority task in global dsq to run
// during running/stopping, associates the cgroup weight + task weight to the current cpu for future select_cpu/enqueue decisions (ignores race conditions caused by gap between dsq pop and setting)
//    assumes this is done by all subschedulers during running, since using bpf helper functions to pull cgroup info is slow (requires RCU lock)
//    can also be done during enqueue into local dsq to reduce desync time and thus race conditions, but not necessary
//    to resolve race conditions between various entities moving to local dsq, should always update it in running/stopping regardless
// cpu search order:
//     last cpu if idle
//     nearest idle cpu
//     min cpu to preempt based on weight with tie breaks: last cpu > cpu in same numa node > any cpu
// this search is done in either select_cpu or enqueue
// if cpu found, enqueues to local dsq directly rather than going through dispatch

// TODO: update kernel and use SCX_ENQ_IMMED to resolve race condition where both dispatch and enqueue move to local dsq, causing multiple tasks in local dsq

const volatile u64 cgroup_id;
const volatile bool preemptive; // use kicks instead of slices
u64 self_cgroup_weight;
u64 slice = 1000000ULL; // 1ms

#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_CGROUP_WEIGHT 1
#define DEFAULT_TASK_WEIGHT (~0ULL)
#define MAX_PENDING_UPDATES 1024
// #define NMIG_TIMER_PERIOD_NS (1 * 1000000ULL) // 1ms
#define NTRIALS 10000 // enough trials to be functionally infinite for rare race-conditioned events
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

#define u128 unsigned __int128
typedef u128 weight_tuple_t;
// tuple consists of 2 64 bit halves
// upper: misc data (48 bits), cgrp_weight (16 bits)
// lower: is_nmig(1 bit), task_weight (63 bits)
// inverse of lower is used as vtime in global dsq
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

// construction macros
#define WT_LOWER_FROM_FIELDS(task_weight, is_nmig) (((u64)(is_nmig) << WT_IS_NMIG_SHIFT) | (u64)task_weight)
#define WT_UPPER_FROM_FIELDS(cgrp_weight, misc) ((u64)(misc << (WT_MISC_SHIFT-64)) | (u64)cgrp_weight)
#define WT_FROM_HALVES(lower, upper) ((weight_tuple_t)(lower) | ((weight_tuple_t)(upper) << 64))
#define WT_FROM_FIELDS(task_weight, is_nmig, cgrp_weight, misc) (((weight_tuple_t)(task_weight) | ((weight_tuple_t)(is_nmig) << WT_IS_NMIG_SHIFT) | ((weight_tuple_t)(cgrp_weight) << WT_CGRP_WEIGHT_SHIFT) | ((weight_tuple_t)(misc) << WT_MISC_SHIFT)))

// conversion macros
#define WT_VTIME_FROM_LOWER(lower) (~0ULL - (u64)(lower))
#define WT_LOWER_FROM_VTIME(vtime) (~0ULL - (u64)(vtime))

// id of global vtime-based task dsq (non-migrateable per-cpu dsqs stored at dsq_id + 1 + cpu)
// updated to cgroup_id in init
u64 dsq_id = 0;

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
// local to this scheduler
struct cpu_sched_state {
  __u64 local_gen; // for checking if global_gen updated
	u32 curr_idx; // index of currently running subscheduler
  u64 priority[MAX_SUB_SCHEDS]; // cached priorities of subs
  int porder[MAX_SUB_SCHEDS]; // cached indices of subs in decreasing priority order
	int can_run[NR_CPUS]; // whether current enqueued task can run on each CPU
};

// data shared between all cores
// local to scheduler
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

// data tracking weight of task running on each cpu
// shared between all cores and schedulers
// updated in running/stopping
struct global_running_data {
	weight_tuple_t cpu_running_weight[NR_CPUS];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_running_data);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} global_running SEC(".maps");

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

// per-cpu runtime data

inline struct global_data *fetch_global() {
	const u32 idx = 0;
	return bpf_map_lookup_elem(&global, &idx);
}

inline struct global_running_data *fetch_running() {
	const u32 idx = 0;
	return bpf_map_lookup_elem(&global_running, &idx);
}

// per-cpu stats
struct cpu_stats {
	u64 n_select_cpu_calls;
	u64 n_dispatch_calls;
	u64 n_enqueue_calls;
	u64 n_pick_cpu_calls;
	u64 n_ldsq_insertions;
	u64 n_gdsq_insertions;
	u64 n_kicks;
	u64 kick_wcet;
	u64 pick_cpu_wcet;
	u64 dispatch_wcet;
	u64 search_wcet;
	u64 task_dispatch_wcet;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CPUS);
	__type(key, u32);
	__type(value, struct cpu_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ffp_cpu_stats SEC(".maps");

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
	// u64 old_gen = lsp->lock.gen;
	lsp->lock.gen = gen_fin;
	// bpf_printk("[INFO] [FP] [SYNC] cpu %d: Synced index %u: gen %llu -> gen %llu (new weight: %llu)", bpf_get_smp_processor_id(), idx, old_gen, gen_fin, lsp->sp.weight);

	return true;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ffp_init)
{
	TRACE_FUNC_START("init");
	bpf_printk("[INFO] [FP] [INIT] cgroup=%d", cgroup_id);
	bpf_printk("SCX_OPS_ENQ_MIGRATION_DISABLED: %d", SCX_OPS_ENQ_MIGRATION_DISABLED);
	TRACE_EVENT(struct sched_trace_event_self, SCHED_TRACE_SELF,
		e->cgrp_id = cgroup_id;
		e->weight = DEFAULT_CGROUP_WEIGHT;
	);
	
	// init cgroup data structs
	self_cgroup_weight = DEFAULT_CGROUP_WEIGHT;
	s32 err = 0;
	u32 cpu;
	bpf_for(cpu, 0, NR_CPUS) {
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

void BPF_STRUCT_OPS(ffp_exit, struct scx_exit_info *ei)
{
	bpf_printk("[INFO] [FP] [EXIT] cgroup=%d\n", cgroup_id);
	UEI_RECORD(uei, ei);
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

s32 BPF_STRUCT_OPS(ffp_sub_attach, struct scx_sub_attach_args *args)
{
	u64 cgrp_id = args->ops->sub_cgroup_id;
	TRACE_FUNC_START("sub_attach");
	// bpf_printk("[INFO] [FP] [SUB_ATTACH] Attaching cgroup %llu", cgrp_id);
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return -EINVAL; // for verifier, should not happen

	u32 *cached_weight = bpf_map_lookup_elem(&cgroup_weights, &cgrp_id);
	u64 weight = cached_weight ? *cached_weight : DEFAULT_CGROUP_WEIGHT;
	
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

void BPF_STRUCT_OPS(ffp_sub_detach, struct scx_sub_detach_args *args)
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

void BPF_STRUCT_OPS(ffp_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgrp_id = cgrp->kn->id;
	if (cgrp_id == cgroup_id) {
		self_cgroup_weight = weight;
		TRACE_EVENT(struct sched_trace_event_self, SCHED_TRACE_SELF,
			e->cgrp_id = cgroup_id;
			e->weight = weight;
		);
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
void BPF_STRUCT_OPS(ffp_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	// bpf_printk("[INFP] [CGROUP_SET_BANDWIDTH] %llu period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, period_us, quota_us, burst_us);
}

// attempt to dispatch a task from global dsq to local dsq
static __always_inline bool try_task_dispatch(u32 cpu, struct global_running_data *grd, struct cpu_sched_state *ss, struct cpu_stats *stats) {
	TRACE_FUNC_START("try_task_dispatch")
	if (unlikely(cpu >= NR_CPUS || !ss || !stats)) return false; // for verifier, should not happen

	u64 start = bpf_ktime_get_ns();

	// move highest weight in global dsq that can run on this cpu to local dsq
	struct task_struct *t;
	bool moved = false;
	bpf_for_each(scx_dsq, t, dsq_id, 0) {
		if (!bpf_cpumask_test_cpu(cpu, t->cpus_ptr) && likely(!is_migration_disabled(t) || scx_bpf_task_cpu(t) == cpu)) {
			continue;
		}

		// this move only fails if another cpu's dispatch claims the task first
		if (likely(scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0))) {
			moved = true;
			break;
		}
	}
	
	u64 delay = bpf_ktime_get_ns() - start;
	if (unlikely(delay > stats->task_dispatch_wcet)) stats->task_dispatch_wcet = delay;

	TRACE_FUNC_END("try_task_dispatch", moved ? "MOVED" : "NOT MOVED");
	return moved;
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

void BPF_STRUCT_OPS(ffp_dispatch, s32 cpu, struct task_struct *prev)
{
	if (unlikely(cpu >= NR_CPUS)) return; // for testing limited CPUs
	
	// bpf_printk("[INFO] [FP] [DISPATCH] dispatching on cpu %u", cpu);
	TRACE_FUNC_START("dispatch");
	u64 start = bpf_ktime_get_ns();

	u32 ucpu = cpu;
	struct global_data *global = fetch_global();
	struct global_running_data *grd = fetch_running();
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	const u32 zero = 0;
	struct cpu_stats *stats = bpf_map_lookup_elem(&ffp_cpu_stats, &zero);
	if (unlikely(!global || !ss || !grd || !stats)) return; // for verifier, should not happen

	++stats->n_dispatch_calls;

	// dispatch task
	if (try_task_dispatch(cpu, grd, ss, stats)) {
		u64 delay = bpf_ktime_get_ns() - start;
		if (unlikely(delay > stats->dispatch_wcet)) stats->dispatch_wcet = delay;
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
			u64 delay = bpf_ktime_get_ns() - start;
			if (unlikely(delay > stats->dispatch_wcet)) stats->dispatch_wcet = delay;
      TRACE_FUNC_END("dispatch", "DISPATCHED CGROUP");
      return;
    }
		TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
			e->idx = idx;
			e->success = false;
		);
	}
	
	u64 delay = bpf_ktime_get_ns() - start;
	if (unlikely(delay > stats->dispatch_wcet)) stats->dispatch_wcet = delay;
	TRACE_FUNC_END("dispatch", "NO READY SUBS");
	return; // no sub schedulers
}

s32 BPF_STRUCT_OPS(ffp_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	// bpf_printk("[INFO] [FP] [CGROUP_INIT] %llu weight=%u period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, args->weight, args->bw_period_us,
				// args->bw_quota_us, args->bw_burst_us);
				
	TRACE_FUNC_START("cgroup_init");
	u64 cgrp_id = cgrp->kn->id;
	u32 weight = args->weight;
	if (cgrp_id == cgroup_id) {
		self_cgroup_weight = weight;
		TRACE_EVENT(struct sched_trace_event_self, SCHED_TRACE_SELF,
			e->cgrp_id = cgroup_id;
			e->weight = weight;
		);
	}
	TRACE_EVENT(struct sched_trace_event_cgroup_init_args, SCHED_TRACE_CGROUP_INIT_ARGS,
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	bpf_map_update_elem(&cgroup_weights, &cgrp_id, &weight, BPF_ANY);
	TRACE_FUNC_END("cgroup_init", "");
	if (preemptive) slice = SCX_SLICE_INF;
	return 0;
}

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

// called from either select_cpu or enqueue
// moves directly into dsq (either local cpu dsq if high enough priority or global otherwise)
// if ran in select_cpu, will skip enqueue
void __always_inline pick_cpu(struct task_struct *p, s32 prev_cpu, u64 enq_flags, struct cpu_stats *stats) {
  TRACE_FUNC_START("pick_cpu");
  prev_cpu = prev_cpu & (NR_CPUS - 1); // for verifier
  struct global_data *global = fetch_global();
  struct global_running_data *grd = fetch_running();
  if (unlikely(!global || !grd || !stats)) return; // for verifier, should not happen

	++stats->n_pick_cpu_calls;

  // setup
  int target_cpu = -1;
  bool nmig = is_migration_disabled(p);
  weight_tuple_t task_weight = WT_FROM_FIELDS(get_task_weight(p), nmig, self_cgroup_weight, 0);

	// NON MIGRATEABLE CASE: just need to check prev cpu
	if (unlikely(nmig)) {
		if (unlikely(!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))) goto dispatch_fail;

		target_cpu = prev_cpu;
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) goto dispatch_idle;

		if (!preemptive || task_weight <= grd->cpu_running_weight[prev_cpu]) goto dispatch_fail;
		
		goto dispatch_preempt;
	}

  // IDLE SEARCH

  // prev cpu
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		target_cpu = prev_cpu;
		goto dispatch_idle;
	}

  // nearest idle cpu in numa topology
  s32 prev_node = scx_bpf_cpu_node(prev_cpu);
  target_cpu = scx_bpf_pick_idle_cpu_node(p->cpus_ptr, prev_node, 0);
  if (target_cpu >= 0) goto dispatch_idle;

  // MIN WEIGHT SEARCH

	if (!preemptive) goto dispatch_fail;
  
  // tie break: prev cpu (misc 2) > cpu on prev numa node (misc 1) > any cpu (misc 0)
	u64 search_start = bpf_ktime_get_ns();
  target_cpu = -1;
  weight_tuple_t target_weight = U128_MAX;
	u32 cpu;
  bpf_for(cpu, 0, NR_CPUS) {
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) continue;

    uint numa_class = cpu == prev_cpu ? 2 : scx_bpf_cpu_node(cpu) == prev_node ? 1 : 0;
    weight_tuple_t running_weight = grd->cpu_running_weight[cpu] | ((weight_tuple_t)numa_class << WT_MISC_SHIFT);
    if (running_weight < target_weight) {
      target_cpu = cpu;
      target_weight = running_weight;
    }
  }
  target_weight &= ~(U128_MAX << WT_MISC_SHIFT); // remove misc data (only used for tie breaks)
	u64 search_delay = bpf_ktime_get_ns() - search_start;
	if (unlikely(search_delay > stats->search_wcet)) stats->search_wcet = search_delay;
  if (task_weight <= target_weight) goto dispatch_fail;

  // DISPATCH
	dispatch_preempt:
	u64 kick_start = bpf_ktime_get_ns();
	scx_bpf_kick_cpu(target_cpu & (NR_CPUS - 1), (u64)SCX_KICK_PREEMPT);
	u64 kick_delay = bpf_ktime_get_ns() - kick_start;
	if (unlikely(kick_delay > stats->kick_wcet)) stats->kick_wcet = kick_delay;
	++stats->n_kicks;

  dispatch_idle:
  scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (target_cpu & (NR_CPUS - 1)), slice, 0);
	++stats->n_ldsq_insertions;

	TRACE_FUNC_END("pick_cpu", "");
	return;

	// NO DISPATCH
	dispatch_fail:

	// enqueue to global dsq instead
	u64 vtime = WT_VTIME_FROM_LOWER(WT_LOWER(task_weight));
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
	++stats->n_gdsq_insertions;
	TRACE_FUNC_END("pick_cpu", "GLOBAL DSQ");
}

// task scheduling functions that should not be called
s32 BPF_STRUCT_OPS(ffp_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
  TRACE_FUNC_START("select_cpu");
	const u32 zero = 0;
	struct cpu_stats *stats = bpf_map_lookup_elem(&ffp_cpu_stats, &zero);
	if (unlikely(!stats)) return prev_cpu; // for verifier, should not happen
	++stats->n_select_cpu_calls;
	u64 start = bpf_ktime_get_ns();
  pick_cpu(p, prev_cpu, SCX_ENQ_WAKEUP | wake_flags, stats);
	u64 delay = bpf_ktime_get_ns() - start;
	if (unlikely(delay > stats->pick_cpu_wcet)) stats->pick_cpu_wcet = delay;
  TRACE_FUNC_END("select_cpu", "");
  return prev_cpu; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(ffp_enqueue, struct task_struct *p, u64 enq_flags) {
  TRACE_FUNC_START("enqueue");
	const u32 zero = 0;
	struct cpu_stats *stats = bpf_map_lookup_elem(&ffp_cpu_stats, &zero);
	if (unlikely(!stats)) return; // for verifier, should not happen
	++stats->n_enqueue_calls;
	u64 start = bpf_ktime_get_ns();
  pick_cpu(p, scx_bpf_task_cpu(p), enq_flags, stats);
	u64 delay = bpf_ktime_get_ns() - start;
	if (unlikely(delay > stats->pick_cpu_wcet)) stats->pick_cpu_wcet = delay;
  TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(ffp_dequeue, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [FP] [DEQUEUE] cgroup=%d pid=%d comm=%s flags=%llu", cgroup_id, p->pid, p->comm, deq_flags);
	TRACE_EVENT(struct sched_trace_event_dequeue_task, SCHED_TRACE_DEQUEUE_TASK,
		e->pid = p->pid;
		e->deq_flags = deq_flags;
	);
  // scx_bpf_error("ffp_dequeue called unexpectedly");
}

void BPF_STRUCT_OPS(ffp_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	// bpf_printk("[INFO] [FP] ffp_cpu_acquire called unexpectedly");
  // scx_bpf_error("ffp_cpu_acquire called unexpectedly");
}

void BPF_STRUCT_OPS(ffp_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	// bpf_printk("[INFO] [FP] ffp_cpu_release called unexpectedly");
  // scx_bpf_error("ffp_cpu_release called unexpectedly");
}

void BPF_STRUCT_OPS(ffp_running, struct task_struct *p)
{
  // bpf_printk("[INFO] [FP] [RUNNING] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
	TRACE_EVENT(struct sched_trace_event_run_task, SCHED_TRACE_RUN_TASK,
		e->pid = p->pid;
	);
	
	struct global_running_data *grd = fetch_running();
	if (unlikely(!grd)) return; // for verifier, should not happen

	u32 cpu = bpf_get_smp_processor_id();
	weight_tuple_t wt = WT_FROM_FIELDS(get_task_weight(p), is_migration_disabled(p), self_cgroup_weight, 0);
	grd->cpu_running_weight[cpu] = wt;
}

void BPF_STRUCT_OPS(ffp_stopping, struct task_struct *p, bool runnable)
{
	// bpf_printk("[INFO] [FP] [STOPPING] cgroup=%d pid=%d comm=%s runnable=%d", cgroup_id, p->pid, p->comm, runnable);
	TRACE_EVENT(struct sched_trace_event_stop_task, SCHED_TRACE_STOP_TASK,
		e->pid = p->pid;
	);
	struct global_running_data *grd = fetch_running();
	if (unlikely(!grd)) return; // for verifier, should not happen
	
	u32 cpu = bpf_get_smp_processor_id();
	grd->cpu_running_weight[cpu] = 0;
}

void BPF_STRUCT_OPS(ffp_runnable, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("[INFO] [FP] ffp_runnable called unexpectedly");
  // scx_bpf_error("ffp_runnable called unexpectedly");
}

void BPF_STRUCT_OPS(ffp_quiescent, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [FP] ffp_quiescent called unexpectedly");
  // scx_bpf_error("ffp_quiescent called unexpectedly");
}

s32 BPF_STRUCT_OPS(ffp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	// bpf_printk("[INFO] [FP] ffp_init_task called (pid: %u policy: %d)", p->pid, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(ffp_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	// bpf_printk("[INFO] [FP] ffp_exit_task called unexpectedly");
  // scx_bpf_error("ffp_exit_task called unexpectedly");
}

void BPF_STRUCT_OPS(ffp_enable, struct task_struct *p)
{
	TRACE_EVENT(struct sched_trace_event_enable_task, SCHED_TRACE_ENABLE_TASK,
		e->pid = p->pid;
	);
}

void BPF_STRUCT_OPS(ffp_disable, struct task_struct *p)
{
	TRACE_EVENT(struct sched_trace_event_disable_task, SCHED_TRACE_DISABLE_TASK,
		e->pid = p->pid;
	);
}

// void BPF_STRUCT_OPS(ffp_cgroup_move, struct task_struct *p, 
//                     struct cgroup *from, struct cgroup *to)
// {
//     u64 to_id = BPF_CORE_READ(to, kn, id);
// 		bpf_printk("[INFO] [FP] [CGROUP_MOVE] Task %d MOVING from cgroup %llu to cgroup %llu\n", 
// 							 p->pid, BPF_CORE_READ(from, kn, id), to_id);
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
	u32 cpu = scx_bpf_task_cpu(p);
	*task_weight_ptr = weight;
	bpf_task_release(p);

	TRACE_EVENT(struct sched_trace_event_set_task_weight, SCHED_TRACE_SET_TASK_WEIGHT,
		e->pid = pid;
		e->weight = weight;
	);

	// kick cpu
	scx_bpf_kick_cpu(cpu, (u64)SCX_KICK_PREEMPT);
	TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
		e->cpu = cpu;
	);

	return 0;
}

// ops

SCX_OPS_DEFINE(ffp_ops,
	// setup
	.name			= "fp",
	.init			= (void *)ffp_init,
	.exit			= (void *)ffp_exit,

	// flags:
	// SCX_OPS_SWITCH_PARTIAL: does not assign tasks to sched_ext by default
	// SCX_OPS_ENQ_LAST: if no work on subscheduler, enqueues current running task rather than continuing it and calls dispatch again
	//									 allows for skipping an idle sub and running next sub instead of continuing prev sub
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_BUILTIN_IDLE_PER_NODE | SCX_OPS_ENQ_MIGRATION_DISABLED,
	// .dump			= (void *)ffp_dump,

	// task scheduling
	.select_cpu		= (void *)ffp_select_cpu,
	.enqueue		= (void *)ffp_enqueue,
	.dequeue		= (void *)ffp_dequeue,
	.cpu_acquire	= (void *)ffp_cpu_acquire,
	.cpu_release	= (void *)ffp_cpu_release,
	.running		= (void *)ffp_running,
	.stopping		= (void *)ffp_stopping,
	.runnable		= (void *)ffp_runnable,
	.quiescent		= (void *)ffp_quiescent,
	.init_task		= (void *)ffp_init_task,
	.exit_task		= (void *)ffp_exit_task,
	.enable			= (void *)ffp_enable,
	.disable		= (void *)ffp_disable,
	// .tick 			= (void *)ffp_tick,
	// .dump_task		= (void *)ffp_dump_task,

	// subscheduling support
	.dispatch		= (void *)ffp_dispatch,
	.cgroup_init		= (void *)ffp_cgroup_init,

	// user cgroup interface
	.cgroup_set_weight	= (void *)ffp_cgroup_set_weight,
	.cgroup_set_bandwidth	= (void *)ffp_cgroup_set_bandwidth,
	// .cgroup_move		= (void *)ffp_cgroup_move,
	.sub_attach		= (void *)ffp_sub_attach,
	.sub_detach		= (void *)ffp_sub_detach
);
