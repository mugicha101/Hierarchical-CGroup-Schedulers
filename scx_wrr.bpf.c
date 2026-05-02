#include <scx/common.bpf.h>

#include "trace_events.h"
CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// weighted round robin hierarchical scheduler
// cannot directly handle tasks, only allocate runtime to subschedulers
// subscheduler requirements:
// - pause its time on cpu_release and resume it on sub_dispatch
// - limit size of cpu local dsqs to 1
// each core has a round robin queue
// TODO: setup cpusets
// TODO: skip subscheduler if nothing to run

// if subscheduler yields the cpu before budget depleted, that subscheduler is handed back the cpu to run a different task until its budget depletes
// if subscheduler's dispatch schedules nothing, moves on to the next subscheduler

const bool cgroup_msgs = true;
const volatile u64 cgroup_id;

#ifndef SCX_KICK_REPICK
#define SCX_KICK_REPICK 0b10
#endif

#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_WEIGHT 100000000ull // 100ms
#define MAX_PENDING_UPDATES 1024
#define NS_PER_WEIGHT 10000000 // weight 1 = 10ms
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
	// __u64 cpuset[CPUSET_SIZE]; WIP
};

struct global_sub_params {
	struct sub_params sp;
	struct seqlock_global lock;
};

struct local_sub_params {
	struct sub_params sp;
	struct seqlock_local lock;
};

struct cpu_sched_state {
	struct bpf_timer budget_timer; // budget enforcement timer
	u32 curr_rr_idx; // index of currently running subscheduler
	u32 next_rr_idx; // next index in rr order
	u64 budget_depletion_time; // time when budget runs out
};

// data shared between all cores
// concurrency: single writer, multiple readers
struct global_data {
	struct bpf_spin_lock global_subs_write_lock;
	struct global_sub_params global_subs[MAX_SUB_SCHEDS];
	// struct seqlock_global global_subs_seqlock; // used when update modifies entire array (not needed currently)
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_data);
} global SEC(".maps");

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
	// bpf_printk("[INFO] [WRR] [SYNC] cpu %d: Synced index %u: gen %llu -> gen %llu (new weight: %llu)", bpf_get_smp_processor_id(), idx, old_gen, gen_fin, lsp->sp.weight);

	return true;
}

static int budget_timer_callback(void *map, int *key, struct bpf_timer *timer) {
	// bpf_printk("[INFO] [WRR] [TIMER] timer callback on cpu %d", bpf_get_smp_processor_id());
	TRACE_FUNC_START("budget_timer_callback");
	TRACE_EVENT(struct sched_trace_event_timer_cancel, SCHED_TRACE_TIMER_CANCEL,
		e->timer_addr = (u64)timer;
	);
	s32 cpu = *key;
	TRACE_EVENT(struct sched_trace_event_kick_cpu, SCHED_TRACE_KICK_CPU,
		e->cpu = cpu;
	);
	scx_bpf_kick_cpu(cpu, (u64)SCX_KICK_REPICK);
	TRACE_FUNC_END("budget_timer_callback", "");
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(wrr_init)
{
	// bpf_printk("[INFO] [WRR] [INIT] Initializing SCX WRR Scheduler");
	TRACE_FUNC_START("init");
	u32 err = 0;
	u32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
		if (unlikely(!ss)) return -EINVAL; // for verifier, should not happen
		bpf_timer_init(&ss->budget_timer, &sched_state, CLOCK_MONOTONIC);
		err = bpf_timer_set_callback(&ss->budget_timer, budget_timer_callback);
		if (err) break;
	}
	TRACE_FUNC_END("init", "");
	return err;
}

void BPF_STRUCT_OPS(wrr_exit)
{
	// bpf_printk("[INFO] [WRR] [EXIT] Exiting SCX WRR Scheduler\n");
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

s32 BPF_STRUCT_OPS(wrr_sub_attach, struct scx_sub_attach_args *args)
{
	u64 cgrp_id = args->ops->sub_cgroup_id;
	TRACE_FUNC_START("sub_attach");
	// bpf_printk("[INFO] [WRR] [SUB_ATTACH] Attaching cgroup %llu", cgrp_id);
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return -EINVAL; // for verifier, should not happen

	u32 *cached_weight = bpf_map_lookup_elem(&cgroup_weights, &cgrp_id);
	u64 weight = cached_weight ? *cached_weight * NS_PER_WEIGHT : DEFAULT_WEIGHT;
	
	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (global_sub_lookup(global_subs, cgrp_id, &gsp, NULL)) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [WRR] [SUB_ATTACH] %llu already attached", cgrp_id);
		TRACE_FUNC_END("sub_attach", "ALREADY ATTACHED");
		return -EEXIST;
	}
	if (!gsp) {
		bpf_spin_unlock(global_subs_write_lock);
		// bpf_printk("[INFO] [WRR] [SUB_ATTACH] %llu attaching sub would exceed MAX_SUB_SCHEDS", cgrp_id);
		TRACE_FUNC_END("sub_attach", "MAX SUBS EXCEEDED");
		return -ENOMEM;
	}

	seqlock_update_start(&gsp->lock);
	
	gsp->sp.cgrp_id = cgrp_id;
	gsp->sp.weight = weight;
	
	seqlock_update_end(&gsp->lock);
	
	bpf_spin_unlock(global_subs_write_lock);
	// bpf_printk("[INFO] [WRR] [SUB_ATTACH] cgroup %llu attached with weight %llu", cgrp_id, weight);
	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	
	TRACE_FUNC_END("sub_attach", "");
  return 0;
}

void BPF_STRUCT_OPS(wrr_sub_detach, struct scx_sub_detach_args *args)
{
  u64 cgrp_id = args->ops->sub_cgroup_id;
	// bpf_printk("[INFO] [WRR] [SUB_DETACH] Detaching cgroup %llu", cgrp_id);
	TRACE_FUNC_START("sub_detach");
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return; // for verifier, should not happen
	
	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (!global_sub_lookup(global_subs, cgrp_id, &gsp, NULL) || !gsp) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [WRR] [SUB_DETACH] %llu not attached", cgrp_id);
		TRACE_FUNC_END("sub_detach", "NOT ATTACHED");
		return;
	}

	seqlock_update_start(&gsp->lock);

	gsp->sp.cgrp_id = 0;
	gsp->sp.weight = 0;
	
	seqlock_update_end(&gsp->lock);

	bpf_spin_unlock(global_subs_write_lock);

	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = 0;
		e->weight = 0;
	);
	TRACE_FUNC_END("sub_detach", "");
}

void BPF_STRUCT_OPS(wrr_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgrp_id = cgrp->kn->id;
	// bpf_printk("[INFO] [WRR] [SET_WEIGHT] Setting cgroup %llu weight to %u", cgrp_id, weight);
	TRACE_FUNC_START("cgroup_set_weight");
	TRACE_EVENT(struct sched_trace_event_set_weight_args, SCHED_TRACE_SET_WEIGHT_ARGS,
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	bpf_map_update_elem(&cgroup_weights, &cgrp_id, &weight, BPF_ANY);
	struct global_sub_params *gsp;
	struct global_data *global = fetch_global();
	if (unlikely(!global)) return; // for verifier, should not happen

	u64 weight_ns = (u64)weight * NS_PER_WEIGHT;

	struct global_sub_params *global_subs = global->global_subs;
	struct bpf_spin_lock *global_subs_write_lock = &global->global_subs_write_lock;
	bpf_spin_lock(global_subs_write_lock);

	if (!global_sub_lookup(global_subs, cgrp_id, &gsp, NULL) || !gsp) {
		bpf_spin_unlock(global_subs_write_lock);
 		// bpf_printk("[INFO] [WRR] [SET_WEIGHT] cgroup_set_weight %llu not attached", cgrp_id);
		TRACE_FUNC_END("cgroup_set_weight", "NOT ATTACHED");
		return;
	}
	
	seqlock_update_start(&gsp->lock);
	gsp->sp.weight = weight_ns;
	seqlock_update_end(&gsp->lock);

	bpf_spin_unlock(global_subs_write_lock);
	TRACE_EVENT(struct sched_trace_sub_params_update, SCHED_TRACE_SUB_PARAMS_UPDATE,
		e->idx = gsp - global_subs;
		e->cgrp_id = cgrp_id;
		e->weight = weight_ns;
	);
	TRACE_FUNC_END("cgroup_set_weight", "");
}

// re-purpose for assigning affinities
void BPF_STRUCT_OPS(wrr_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	// bpf_printk("[INFP] [CGROUP_SET_BANDWIDTH] %llu period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, period_us, quota_us, burst_us);
}

// returns true if dispatched successfully
static __always_inline bool try_sub_dispatch(struct local_sub_params *lsp, struct cpu_sched_state *ss, u64 now) {
	if (now >= ss->budget_depletion_time) return false;

	// bpf_printk("[INFO] [WRR] [DISPATCH] dispatching cgroup %d rem_time=%llu", lsp->sp.cgrp_id, rem_time);
	if (!scx_bpf_sub_dispatch(lsp->sp.cgrp_id)) {
		// bpf_printk("[INFO] [WRR] [TIMER] timer cancelled: dispatch failed");
		TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
			e->idx = ss->next_rr_idx;
			e->success = false;
		);
		return false;
	}

	// start budget enforcement timer
	u64 rem_time = ss->budget_depletion_time - now; // TODO: figure out if need to update now if dispatch takes a long time
	bpf_timer_start(&ss->budget_timer, rem_time, BPF_F_TIMER_CPU_PIN);
	TRACE_EVENT(struct sched_trace_event_timer_start, SCHED_TRACE_TIMER_START,
		e->timer_addr = (u64)&ss->budget_timer;
		e->duration = rem_time;
	);

	TRACE_EVENT(struct sched_trace_try_sub_dispatch, SCHED_TRACE_TRY_SUB_DISPATCH,
		e->idx = ss->next_rr_idx;
		e->success = true;
	);

	return true;
}

void BPF_STRUCT_OPS(wrr_dispatch, s32 cpu, struct task_struct *prev)
{
	// FOR TESTING (limits CPUs to prevent freezing)
	if (cpu >= 1) return;

	// bpf_printk("[INFO] [WRR] [DISPATCH] dispatching on cpu %u", cpu);
	TRACE_FUNC_START("dispatch");
	u32 ucpu = cpu;
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	struct global_data *global = fetch_global();
	if (unlikely(!ss) || unlikely(!global)) return; // for verifier, should not happen

	// check if sub yielded early, in which case should dispatch itself again until budget gone
	if (bpf_timer_cancel(&ss->budget_timer)) {
		TRACE_EVENT(struct sched_trace_event_timer_cancel, SCHED_TRACE_TIMER_CANCEL,
			e->timer_addr = (u64)&ss->budget_timer;
		);
		// bpf_printk("[INFO] [WRR] [TIMER] timer cancelled: yielded early");
		u64 now = bpf_ktime_get_ns();
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &ss->curr_rr_idx);
		if (unlikely(!lsp)) return; // for verifier, should not happen

		if (now < ss->budget_depletion_time && try_sub_dispatch(lsp, ss, now)) {
			TRACE_FUNC_END("dispatch", "RESUME EARLY YIELD");
			return;
		}

		// preserve budget for next attempt (TODO: figure out if need to clear here)
	}
	// bpf_printk("[INFO] [WRR] [DISPATCH] cpu=%d finding next cgroup to run...", cpu);

	u32 i;
	bpf_for(i, 0, MAX_SUB_SCHEDS) {
		sync_local_sub(global->global_subs, ss->next_rr_idx);
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &ss->next_rr_idx);
		if (unlikely(!lsp)) return; // for verifier, should not happen

		if (lsp->sp.cgrp_id == 0) { // skip empty slots
			ss->next_rr_idx = ss->next_rr_idx + 1 == MAX_SUB_SCHEDS ? 0 : ss->next_rr_idx + 1;
			continue;
		}

		u64 now = bpf_ktime_get_ns();
		ss->budget_depletion_time = now + lsp->sp.weight;
		// bpf_printk("[INFO] [WRR] [DISPATCH] cgroup %d weight: %llu", lsp->sp.cgrp_id, lsp->sp.weight);

		ss->curr_rr_idx = ss->next_rr_idx;
		ss->next_rr_idx = ss->next_rr_idx + 1 == MAX_SUB_SCHEDS ? 0 : ss->next_rr_idx + 1;
		
		if (try_sub_dispatch(lsp, ss, now)) {
			TRACE_FUNC_END("dispatch", "");
			return;
		}
	}
	TRACE_FUNC_END("dispatch", "NO READY SUBS");
	return; // no sub schedulers
}

s32 BPF_STRUCT_OPS(wrr_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	// bpf_printk("[INFO] [WRR] [CGROUP_INIT] %llu weight=%u period=%lu quota=%ld burst=%lu",
				// cgrp->kn->id, args->weight, args->bw_period_us,
				// args->bw_quota_us, args->bw_burst_us);
				
	TRACE_FUNC_START("cgroup_init");
	u64 cgrp_id = cgrp->kn->id;
	u32 weight = args->weight;
	TRACE_EVENT(struct sched_trace_event_cgroup_init_args, SCHED_TRACE_CGROUP_INIT_ARGS,
		e->cgrp_id = cgrp_id;
		e->weight = weight;
	);
	bpf_map_update_elem(&cgroup_weights, &cgrp_id, &weight, BPF_ANY);
	TRACE_FUNC_END("cgroup_init", "");
	return 0;
}

// task scheduling functions that should not be called
s32 BPF_STRUCT_OPS(wrr_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// bpf_printk("[INFO] [WRR] wrr_select_cpu called unexpectedly");
  // scx_bpf_error("wrr_select_cpu called unexpectedly");
    return prev_cpu; // Required to return a valid CPU even when erroring
}

void BPF_STRUCT_OPS(wrr_enqueue, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("[INFO] [WRR] [ENQUEUE] enqueueing pid=%d", p->pid);
	// scx_bpf_error("wrr_enqueue called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_dequeue, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [WRR] [DEQUEUE] dequeuing pid=%d", p->pid);
  // scx_bpf_error("wrr_dequeue called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	// bpf_printk("[INFO] [WRR] wrr_cpu_acquire called unexpectedly");
  // scx_bpf_error("wrr_cpu_acquire called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	// bpf_printk("[INFO] [WRR] wrr_cpu_release called unexpectedly");
  // scx_bpf_error("wrr_cpu_release called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_running, struct task_struct *p)
{
	// bpf_printk("[INFO] [WRR] wrr_running called unexpectedly");
  // scx_bpf_error("wrr_running called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_stopping, struct task_struct *p, bool runnable)
{
	// bpf_printk("[INFO] [WRR] wrr_stopping called unexpectedly");
  // scx_bpf_error("wrr_stopping called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_runnable, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("[INFO] [WRR] wrr_runnable called unexpectedly");
  // scx_bpf_error("wrr_runnable called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_quiescent, struct task_struct *p, u64 deq_flags)
{
	// bpf_printk("[INFO] [WRR] wrr_quiescent called unexpectedly");
  // scx_bpf_error("wrr_quiescent called unexpectedly");
}

s32 BPF_STRUCT_OPS(wrr_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	// bpf_printk("[INFO] [WRR] wrr_init_task called (pid: %u policy: %d)", p->pid, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(wrr_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	// bpf_printk("[INFO] [WRR] wrr_exit_task called unexpectedly");
  // scx_bpf_error("wrr_exit_task called unexpectedly");
}

// ops

SCX_OPS_DEFINE(wrr_ops,
	// setup
	.name			= "wrr",
	.init			= (void *)wrr_init,
	.exit			= (void *)wrr_exit,

	// flags:
	// SCX_OPS_SWITCH_PARTIAL: does not assign tasks to sched_ext by default
	// SCX_OPS_ENQ_LAST: if no work on subscheduler, enqueues current running task rather than continuing it and calls dispatch again
	//									 allows for skipping an idle sub and running next sub instead of continuing prev sub
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_HAS_CGROUP_WEIGHT,
	// .dump			= (void *)wrr_dump,

	// task scheduling (should not be called)
	.select_cpu		= (void *)wrr_select_cpu,
	.enqueue		= (void *)wrr_enqueue,
	.dequeue		= (void *)wrr_dequeue,
	.cpu_acquire	= (void *)wrr_cpu_acquire,
	.cpu_release	= (void *)wrr_cpu_release,
	.running		= (void *)wrr_running,
	.stopping		= (void *)wrr_stopping,
	.runnable		= (void *)wrr_runnable,
	.quiescent		= (void *)wrr_quiescent,
	.init_task		= (void *)wrr_init_task,
	.exit_task		= (void *)wrr_exit_task,
	// .enable			= (void *)wrr_enable,
	// .disable		= (void *)wrr_disable,
	// .dump_task		= (void *)wrr_dump_task,

	// subscheduling support
	.dispatch		= (void *)wrr_dispatch,
	.cgroup_init		= (void *)wrr_cgroup_init,

	// user cgroup interface
	.cgroup_set_weight	= (void *)wrr_cgroup_set_weight,
	.cgroup_set_bandwidth	= (void *)wrr_cgroup_set_bandwidth,
	.sub_attach		= (void *)wrr_sub_attach,
	.sub_detach		= (void *)wrr_sub_detach
);
