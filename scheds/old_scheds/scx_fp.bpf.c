#include <scx/common.bpf.h>

#include "trace_events.h"
CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// job-level fixed priority scheduler
// prioritized by weight (higher weight = higher priority)
// tie breaks handled arbitrarily
// weights can be modified at runtime via the cgroup fs interface (/sys/fs/bpf/task_weights) but tasks must be reenqueued for their weight to update

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
// migration disabled tasks
//   treat as higher priority than migrateable tasks since in PREEMPT_RT the runnable non-migratable portion of a critical section should be pretty short
//   store in per-cpu vtime queues
//   while this causes issues, will have issues anyways with PREEMPT_RT since no priority inheritence support yet
// NOTE: for correctness, tasks must all share the same CPU set, otherwise cannot greedily choose highest priority from the global set
// NOTE: assumes cgroup weights are unique, treats lower priority cgroups as idle and higher priority cgroups as max priority
// TODO: fix nmig to check on migrate enable whether to keep running nonmigrateable task

const volatile u64 cgroup_id;
u64 self_cgroup_weight;

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
struct cpu_sched_state {
  __u64 local_gen; // for checking if global_gen updated
	u32 curr_idx; // index of currently running subscheduler
  u64 priority[MAX_SUB_SCHEDS]; // cached priorities of subs
  int porder[MAX_SUB_SCHEDS]; // cached indices of subs in decreasing priority order
	int can_run[NR_CPUS]; // whether current enqueued task can run on each CPU
	// struct bpf_timer nmig_timer; // timer to periodically check if non-migrateable tasks become migrateable
};

// data used for global task scheduling decisions, locked by global_task_lock
struct cpu_task_state {
	u64 running_weight; // weight of currently running task on this CPU (0 if no task or running a sub cgroup, only updated on dispatch so if a different cgroup is running, use cgroup weights instead)
	bool running_nmig; // whether CPU running non-migrateable task
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
	struct bpf_spin_lock global_task_lock; // locks cpu_task_states
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

// per-cpu runtime data

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
	// u64 old_gen = lsp->lock.gen;
	lsp->lock.gen = gen_fin;
	// bpf_printk("[INFO] [FP] [SYNC] cpu %d: Synced index %u: gen %llu -> gen %llu (new weight: %llu)", bpf_get_smp_processor_id(), idx, old_gen, gen_fin, lsp->sp.weight);

	return true;
}

// assumes RCU lock held
void __always_inline update_cpu_cgroup_weight(u32 cpu, struct cpu_task_state *cts) {
	cpu &= (NR_CPUS - 1); // for verifier

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
	cts->cgrp_weight = cgrp_weight ? *cgrp_weight : DEFAULT_CGROUP_WEIGHT;
}

// periodically checks if task is still non-migrateable
// static int nmig_timer_callback(void *map, int *key, struct bpf_timer *timer) {
// 	TRACE_FUNC_START("nmig_timer_callback");
// 	TRACE_EVENT(struct sched_trace_event_timer_cancel, SCHED_TRACE_TIMER_CANCEL,
// 		e->timer_addr = (u64)timer;
// 	);
// 	u32 cpu = (u32)(*key) & (NR_CPUS-1);

// 	// check if running this cgroup still
// 	struct global_task_data *gtd = fetch_global_task_data();
// 	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
// 	if (unlikely(!gtd || !ss)) return 0; // for verifier, should not happen
	
// 	// check running cgroup
// 	// if not running this cgroup, no need to update nmig as dispatch will handle and enqueue will use cgroup weight instead
// 	struct cpu_task_state *cts = &gtd->cpu_task_states[cpu & (NR_CPUS-1)];
// 	if (!cts) return 0; // for verifier, should not happen

// 	bpf_rcu_read_lock();
// 	update_cpu_cgroup_weight(cpu, cts);
// 	if (cts->cgrp_weight != self_cgroup_weight) {
// 		bpf_rcu_read_unlock();
// 		TRACE_FUNC_END("nmig_timer_callback", "DIFF CGROUP");
// 		return 0;
// 	}

// 	// check current task
// 	struct task_struct *cpu_task = scx_bpf_cpu_curr(cpu);
// 	pid_t pid = cpu_task ? BPF_CORE_READ(cpu_task, pid) : 0;
// 	bpf_rcu_read_unlock();
	
// 	// if idle, no need to nmig as dispatch will handle and enqueue will use cgroup weight instead
// 	if (pid == 0) {
// 		TRACE_FUNC_END("nmig_timer_callback", "IDLE");
// 		return 0;
// 	}
	
// 	// if task still non-migrateable, start next timer period
// 	if (is_migration_disabled(cpu_task)) {
// 		bpf_timer_start(&ss->nmig_timer, NMIG_TIMER_PERIOD_NS, BPF_F_TIMER_CPU_PIN);
// 		TRACE_EVENT(struct sched_trace_event_timer_start, SCHED_TRACE_TIMER_START,
// 			e->timer_addr = (u64)(&ss->nmig_timer);
// 			e->duration = NMIG_TIMER_PERIOD_NS;
// 		);
// 		TRACE_FUNC_END("nmig_timer_callback", "STILL NMIG");
// 		return 0;
// 	}

// 	// update non-migrateable flag
// 	// NOTE: since dispatch cancels this timer and runs on same CPU, this should refer to the same task that started this timer
// 	//       unless a different scheduler's dispatch runs, in which case cgroup weight will be used until this schedulers dispatch runs again, which updates the nmig flag
// 	cts->running_nmig = false;

// 	// check if we should preempt this task
// 	// if tasks on nmig queue, preempt
// 	// if global dsq has a higher priority task, preempt
// 	bool preempt = !scx_bpf_dsq_peek(dsq_id + 1 + cpu);
// 	if (!preempt) {
// 		struct task_struct *top = scx_bpf_dsq_peek(dsq_id);
// 		preempt = top && (~0ULL - top->scx.dsq_vtime) > cts->running_weight;
// 	}
// 	if (!preempt) {
// 		TRACE_FUNC_END("nmig_timer_callback", "NO KICK");
// 		return 0;
// 	}

// 	// kick cpu
// 	bpf_spin_lock(&gtd->global_task_lock);
// 	bool do_kick = !cts->kicked;
// 	cts->kicked = true;
// 	bpf_spin_unlock(&gtd->global_task_lock);
// 	if (do_kick) {
// 		scx_bpf_kick_cpu(cpu, (u64)SCX_KICK_PREEMPT);
// 		TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
// 			e->cpu = cpu;
// 		);
// 	}

// 	TRACE_FUNC_END("nmig_timer_callback", "KICK");
// 	return 0;
// }

s32 BPF_STRUCT_OPS_SLEEPABLE(fp_init)
{
	TRACE_FUNC_START("init");
	bpf_printk("[INFO] [FP] [INIT] cgroup=%d", cgroup_id);
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
	bpf_for(cpu, 0, NR_CPUS) {
		scx_bpf_create_dsq(dsq_id + 1 + cpu, cpu);
		struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
		if (unlikely(!ss)) return -EINVAL; // for verifier, should not happen
		// bpf_timer_init(&ss->nmig_timer, &sched_state, CLOCK_MONOTONIC);
		// err = bpf_timer_set_callback(&ss->nmig_timer, nmig_timer_callback);
		// if (err) break;
	}
	TRACE_FUNC_END("init", "");
	return err;
}

void BPF_STRUCT_OPS(fp_exit, struct scx_exit_info *ei)
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

s32 BPF_STRUCT_OPS(fp_sub_attach, struct scx_sub_attach_args *args)
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
void BPF_STRUCT_OPS(fp_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	// bpf_printk("[INFP] [CGROUP_SET_BANDWIDTH] %llu period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, period_us, quota_us, burst_us);
}

// attempt to dispatch a task from global dsq to local dsq
static __always_inline bool try_task_dispatch(u32 cpu, struct global_task_data *gtd, struct cpu_sched_state *ss) {
	TRACE_FUNC_START("try_task_dispatch");

	if (unlikely(cpu >= NR_CPUS || !ss)) return false; // for verifier, should not happen

	// unset nmig timer
	// if (ss && bpf_timer_cancel(&ss->nmig_timer)) {
	// 	TRACE_EVENT(struct sched_trace_event_timer_cancel, SCHED_TRACE_TIMER_CANCEL,
	// 		e->timer_addr = (u64)&ss->nmig_timer;
	// 	);
	// }

	// first try fetching from the non-migrateable per-cpu dsq
	struct task_struct *t;
	bool moved = false;
	u64 peeked_weight = 0;
	bpf_for_each(scx_dsq, t, dsq_id + 1 + cpu, 0) {
		peeked_weight = ~0ULL - t->scx.dsq_vtime;

		// this should always work since only this CPU can move tasks off this dsq
		moved = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0);
		break;
	}
	bool from_nmig = moved;

	// then try fetching from global dsq
	// need to atomically move and get the weight of the task
	bool empty = false;
	if (!moved) {
		u32 trials;
		bpf_for(trials, 0, NTRIALS) { // also gives time for another process to claim first in case cannot run on this CPU
			empty = true;
			bpf_for_each(scx_dsq, t, dsq_id, 0) {
				if (!bpf_cpumask_test_cpu(cpu, t->cpus_ptr)) {
					continue;
				}
				
				empty = false;
				peeked_weight = ~0ULL - t->scx.dsq_vtime;

				if (likely(scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t, SCX_DSQ_LOCAL, 0))) {
					moved = true;
				}
				break;
			}

			if (empty || moved) {
				break;
			}
		}
	}

	// update running weight and kicked status
	// don't need to lock since enqueue skips tasks that aren't marked as kicked
	struct cpu_task_state *cts = &gtd->cpu_task_states[cpu];
	cts->running_weight = moved ? peeked_weight : 0;
	cts->running_nmig = from_nmig;
	smp_wmb(); // must write kicked last to prevent enqueue from reading stale weight
	cts->kicked = false;

	// start nmig timer
	// if (from_nmig && ss) {
	// 	bpf_timer_start(&ss->nmig_timer, NMIG_TIMER_PERIOD_NS, BPF_F_TIMER_CPU_PIN);
	// 	TRACE_EVENT(struct sched_trace_event_timer_start, SCHED_TRACE_TIMER_START,
	// 		e->timer_addr = (u64)(&ss->nmig_timer);
	// 		e->duration = NMIG_TIMER_PERIOD_NS;
	// 	);
	// }

	if (empty) {
		TRACE_FUNC_END("try_task_dispatch", "EMPTY");
	} else if (moved) {
		TRACE_FUNC_END("try_task_dispatch", from_nmig ? "NMIG TASK" : "TASK");
	} else {
		TRACE_FUNC_END("try_task_dispatch", "FAIL");
	}
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

void BPF_STRUCT_OPS(fp_dispatch, s32 cpu, struct task_struct *prev)
{
	if (unlikely(cpu >= NR_CPUS)) return; // for testing limited CPUs

	// bpf_printk("[INFO] [FP] [DISPATCH] dispatching on cpu %u", cpu);
	TRACE_FUNC_START("dispatch");

	u32 ucpu = cpu;
	struct global_data *global = fetch_global();
	struct global_task_data *gtd = fetch_global_task_data();
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	if (unlikely(!global) || unlikely(!ss) || unlikely(!gtd)) return; // for verifier, should not happen

	// dispatch task
	if (try_task_dispatch(cpu, gtd, ss)) {
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

void BPF_STRUCT_OPS(fp_enqueue, struct task_struct *p, u64 enq_flags)
{
	TRACE_FUNC_START("enqueue");
	// bpf_printk("[INFO] [FP] [ENQUEUE] cgroup=%d pid=%d comm=%s flags=%llu", cgroup_id, p->pid, p->comm, enq_flags);
	TRACE_EVENT(struct sched_trace_event_enqueue_task, SCHED_TRACE_ENQUEUE_TASK,
		e->pid = p->pid;
		e->enq_flags = enq_flags;
	);

	// setup struct pointers
	u32 cpu = bpf_get_smp_processor_id() & (NR_CPUS - 1); // if NR_CPUS redefined, this prevents enqueue failures
	struct global_task_data *gtd = fetch_global_task_data();
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
	if (unlikely(!gtd || !ss)) return; // for verifier, should not happen

	// determine weight of enqueued task
	u64 weight = get_task_weight(p);
	u64 vtime = ~0ULL - weight;
	u32 task_cpu = scx_bpf_task_cpu(p) & (NR_CPUS - 1);
	TRACE_EVENT(struct sched_trace_event_set_task_weight, SCHED_TRACE_SET_TASK_WEIGHT,
		e->pid = p->pid;
		e->weight = weight;
	);

	// check if must run on local CPU due to migration disabled (bypasses priority system)
	if (is_migration_disabled(p)) {
		scx_bpf_dsq_insert_vtime(p, dsq_id + 1 + task_cpu, SCX_SLICE_INF, vtime, enq_flags);

		// check if should preempt current task
		bool do_kick = false;
		struct cpu_task_state *cts = &gtd->cpu_task_states[task_cpu];
		update_cpu_cgroup_weight(task_cpu, cts);

		bpf_spin_lock(&gtd->global_task_lock); // prevent another enqueue from updating kick
		if (likely(!cts->kicked)) {
			// higher weight cgroups treated as weight INF
			// lower weight cgroups treated as weight 0
			// if running task is migrateable, treated as weight 0
			// otherwise use running weight
			u64 running_weight = cts->cgrp_weight > self_cgroup_weight ? ~0ULL : cts->cgrp_weight < self_cgroup_weight ? 0 : !cts->running_nmig ? 0 : cts->running_weight;
			if (running_weight < weight) {
				do_kick = true;
				cts->kicked = true;
			}
		}
		bpf_spin_unlock(&gtd->global_task_lock);

		if (do_kick) {
			scx_bpf_kick_cpu(task_cpu, (u64)SCX_KICK_PREEMPT);
			TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
				e->cpu = task_cpu;
			);
		}
		return;
	}

	// insert into global dsq
	scx_bpf_dsq_insert_vtime(p, dsq_id, SCX_SLICE_INF, vtime, enq_flags);
	// u32 cpu = bpf_get_smp_processor_id();
	// scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	// TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
	// 	e->cpu = cpu;
	// );

	// find min priority unkicked CPU to kick
	// why unkicked? if two tasks try to kick same CPU, one might get starved on global dsq
	// worst case just an extra enqueue to sort out
	// should be rare since time between kick and dispatch is small
	// if all CPUs are kicked (extremely unlikely) try again

	// optimization: first check if any idle and kick that one
	// check prev CPU first to avoid migrations
	s32 idle_cpu = scx_bpf_test_and_clear_cpu_idle(task_cpu) ? task_cpu : scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle_cpu >= 0 && idle_cpu < NR_CPUS) {
		struct cpu_task_state *cts = &gtd->cpu_task_states[idle_cpu & (NR_CPUS - 1)];

		// kick cpu
		bpf_spin_lock(&gtd->global_task_lock); // prevent other enqueues from claiming same CPU
		bool do_kick = !cts->kicked;
		cts->kicked = true;
		bpf_spin_unlock(&gtd->global_task_lock);
		
		if (do_kick) {
			scx_bpf_kick_cpu(idle_cpu, (u64)SCX_KICK_PREEMPT);
			TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
				e->cpu = idle_cpu;
			);
			TRACE_FUNC_END("enqueue", "kicked idle");
			return;
		}
	}

	// then do the slow search
	u32 trials;
	bpf_for(trials, 0, NTRIALS) {
		// first fetch a snapshot of what cgroups each cpu is running to avoid preempting ones with higher weight
		// concurrent updates from multiple enqueues doesn't matter since they're reading the same thing
		// staleness bad but not critical, since worst case preempting higher weight cgroup will just go through dispatch again
		// also figure out which CPU this task can run (TODO: probably some race conditions involved with this since it can be stale)
		bpf_rcu_read_lock();
		u32 cpu;
		bpf_for(cpu, 0, NR_CPUS) {
			ss->can_run[cpu] = bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
			if (ss->can_run[cpu]) {
				struct cpu_task_state *cts = &gtd->cpu_task_states[cpu];
				update_cpu_cgroup_weight(cpu, cts);
			}
		}
		bpf_rcu_read_unlock();

		u64 cached_self_cgroup_weight = self_cgroup_weight; // lock in self cgroup weight here to avoid changing mid-loop

		bpf_spin_lock(&gtd->global_task_lock); // prevent other enqueues from claiming same CPU
		u32 target_cpu = NR_CPUS;
		u64 target_cpu_weight = ~0ULL;
		bpf_for(cpu, 0, NR_CPUS) {
			struct cpu_task_state *cts = &gtd->cpu_task_states[cpu];

			// must check kicked first since is unset last in dispatch, otherwise may read stale running weight
			if (!ss->can_run[cpu] || cts->kicked) continue;

			// higher weight cgroups treated as weight INF
			// lower weight cgroups treated as weight 0
			// if running task is non-migrateable, treated as weight INF
			// otherwise use running weight
			u64 running_weight = cts->cgrp_weight > cached_self_cgroup_weight ? ~0ULL : cts->cgrp_weight < cached_self_cgroup_weight ? 0 : cts->running_nmig ? ~0ULL : cts->running_weight;
			if (running_weight >= target_cpu_weight) continue;
		
			target_cpu = cpu;
			target_cpu_weight = running_weight;
			if (target_cpu_weight == 0) break; // can't do better than an idle CPU
		}

		if (target_cpu < NR_CPUS) {
			// check if weight high enough
			if (target_cpu_weight >= weight) {
				bpf_spin_unlock(&gtd->global_task_lock);
				TRACE_FUNC_END("enqueue", "CANNOT KICK");
				break; // all CPUs have higher or equal weight, no need to kick
			}
			
			// kick CPU
			gtd->cpu_task_states[target_cpu].kicked = true;
			bpf_spin_unlock(&gtd->global_task_lock);
			scx_bpf_kick_cpu(target_cpu, (u64)SCX_KICK_PREEMPT);
			TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
				e->cpu = target_cpu;
			);
			break;
		}
		bpf_spin_unlock(&gtd->global_task_lock);
	}

	TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(fp_dequeue, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [FP] [DEQUEUE] cgroup=%d pid=%d comm=%s flags=%llu", cgroup_id, p->pid, p->comm, deq_flags);
	TRACE_EVENT(struct sched_trace_event_dequeue_task, SCHED_TRACE_DEQUEUE_TASK,
		e->pid = p->pid;
		e->deq_flags = deq_flags;
	);
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
  // bpf_printk("[INFO] [FP] [RUNNING] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
	TRACE_EVENT(struct sched_trace_event_run_task, SCHED_TRACE_RUN_TASK,
		e->pid = p->pid;
	);
}

void BPF_STRUCT_OPS(fp_stopping, struct task_struct *p, bool runnable)
{
	// bpf_printk("[INFO] [FP] [STOPPING] cgroup=%d pid=%d comm=%s runnable=%d", cgroup_id, p->pid, p->comm, runnable);
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

void BPF_STRUCT_OPS(fp_enable, struct task_struct *p)
{
	TRACE_EVENT(struct sched_trace_event_enable_task, SCHED_TRACE_ENABLE_TASK,
		e->pid = p->pid;
	);
}

void BPF_STRUCT_OPS(fp_disable, struct task_struct *p)
{
	TRACE_EVENT(struct sched_trace_event_disable_task, SCHED_TRACE_DISABLE_TASK,
		e->pid = p->pid;
	);
}

// void BPF_STRUCT_OPS(fp_cgroup_move, struct task_struct *p, 
//                     struct cgroup *from, struct cgroup *to)
// {
//     u64 to_id = BPF_CORE_READ(to, kn, id);
// 		bpf_printk("[INFO] [FP] [CGROUP_MOVE] Task %d MOVING from cgroup %llu to cgroup %llu\n", 
// 							 p->pid, BPF_CORE_READ(from, kn, id), to_id);
// }


// in PREEMPT_RT some locks are replaced by nonmigrateable sections
// on migrate_disable, we can continue running this task until enable kicks it and it becomes enqueued again since its priority is increased
// on enqueue it'll realize the task is non-migrateable and reacquire the CPU immediately
// while this has a redundant kick, we save on overhead by not having to check the migration status of every CPU during enqueue's search for a CPU to kick
// however, for migrate_enable, its priority decreases so need to check if we should kick it to allow a job from the global dsq to run
#define MIGRATE_ENABLE 0x04
#define MIGRATE_DISABLE 0x02
SEC("fentry/__set_cpus_allowed_ptr")
int BPF_PROG(trace_migrate_enable, struct task_struct *p, struct affinity_context *ac) {
	bpf_printk("[INFO] [FP] [SET_CPUS_ALLOWED_PTR] %x\n", ac->flags);
	// const u32 idx = 0;
	// struct global_task_data *gtd = bpf_map_lookup_elem(&global_task_data, &idx);
	// if (unlikely(!gtd)) return 0; // for verifier, should not happen
	
	// // unset running_nmig flag, no need to lock since flag only modified by this cpu
	// u32 cpu = bpf_get_smp_processor_id();
	// if (unlikely(cpu >= NR_CPUS)) return 0; // for verifier, should not happen
	
	// struct cpu_task_state *cts = &gtd->cpu_task_states[cpu];
	// if (!cts->running_nmig) return false;
	// cts->running_nmig = false;

	// // now that priority is back to migrateable, check if need to preempt by peeking global dsq
	// struct task_struct *top = scx_bpf_dsq_peek(dsq_id);
	// if (top && top->pid != 0 && (~0ULL - top->scx.dsq_vtime) > cts->running_weight) {
	// 	// since cannot use spinlocks, just preempt always regardless of kick
	// 	scx_bpf_kick_cpu(cpu, (u64)SCX_KICK_PREEMPT);
	// 	TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
	// 		e->cpu = cpu;
	// 	);
	// }
	// scx_bpf_kick_cpu(bpf_get_smp_processor_id(), (u64)SCX_KICK_PREEMPT);
	return 0;
}

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

SCX_OPS_DEFINE(fp_ops,
	// setup
	.name			= "fp",
	.init			= (void *)fp_init,
	.exit			= (void *)fp_exit,

	// flags:
	// SCX_OPS_SWITCH_PARTIAL: does not assign tasks to sched_ext by default
	// SCX_OPS_ENQ_LAST: if no work on subscheduler, enqueues current running task rather than continuing it and calls dispatch again
	//									 allows for skipping an idle sub and running next sub instead of continuing prev sub
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED,
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
	.enable			= (void *)fp_enable,
	.disable		= (void *)fp_disable,
	// .dump_task		= (void *)fp_dump_task,

	// subscheduling support
	.dispatch		= (void *)fp_dispatch,
	.cgroup_init		= (void *)fp_cgroup_init,

	// user cgroup interface
	.cgroup_set_weight	= (void *)fp_cgroup_set_weight,
	.cgroup_set_bandwidth	= (void *)fp_cgroup_set_bandwidth,
	// .cgroup_move		= (void *)fp_cgroup_move,
	.sub_attach		= (void *)fp_sub_attach,
	.sub_detach		= (void *)fp_sub_detach
);
