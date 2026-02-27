#include <scx/common.bpf.h>

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

#define wrr_DSQ 1
#define MAX_SUB_SCHEDS 64
#define DEFAULT_WEIGHT 1000
#define MAX_PENDING_UPDATES 1024
#define CPUSET_SIZE NR_CPUS / 64

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
	u64 gen_fin; // incremented when update ends (generation of the last finished update)
	u64 gen_beg; // incremented when update begins (generation of the last started update)
};

struct seqlock_local {
	u64 gen;
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
	u64 cgrp_id;
  u64 weight;
	// u64 cpuset[CPUSET_SIZE]; WIP
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

// subscheduler maps
// concurrency: single writer multiple readers
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SUB_SCHEDS);
	__type(key, u32);
	__type(value, struct global_sub_params);
} global_subs SEC(".maps");
struct bpf_spin_lock global_subs_write_lock;
struct seqlock_global global_subs_seqlock; // used when update modifies entire array

// synced with global sub map
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

// seqlock sync
// sync local sp to global sp if global sp is consistent
// local copies (gen_fin, sp, gen_beg) in that order
// if gen_fin = gen_beg, then update finished by start of copy and no new update arrived by end of copy
// thus if gen_fin = gen_beg, data is consistent and of generation gen_fin = gen_beg
// so local sp updated with copied global sp
// if this is not the case, this update is ignored until the next sync
bool sync_local_sub(u32 idx) {
	struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &idx);
	struct global_sub_params *gsp = bpf_map_lookup_elem(&global_subs, &idx);
	if (!lsp || !gsp) return false;

	struct sub_params tmp_data;
	u64 gen_fin = READ_ONCE(gsp->lock.gen_fin);
	smp_rmb();
	if (gen_fin != lsp->lock.gen) return false;

	__builtin_memcpy(&tmp_data, &gsp->sp, sizeof(struct sub_params));
	
	smp_rmb();
	u64 gen_beg = READ_ONCE(gsp->lock.gen_beg);

	if (gen_beg != gen_fin) return false;

	__builtin_memcpy(&lsp->sp, &tmp_data, sizeof(struct sub_params));
	lsp->lock.gen = gen_fin;

	return true;
}

static int budget_timer_callback(void *map, int *key, struct bpf_timer *timer) {
	u32 cpu = *key;
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(wrr_init)
{
	u32 err = 0;
	for (u32 cpu = 0; cpu < NR_CPUS && !err; ++cpu) {
		struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
		bpf_timer_init(&ss->budget_timer, &sched_state, CLOCK_MONOTONIC);
		err = bpf_timer_set_callback(&ss->budget_timer, budget_timer_callback);
	}
	return 0;
}

void BPF_STRUCT_OPS(wrr_exit)
{
	bpf_printk("[INFO] [EXIT] Exiting SCX Deadline Scheduler\n");
}

// looks for cgroup in global_subs
// returns true iff exists
// if exists, res := address of it in subs
// otherwise, res := address of the first free location (NULL if no free location)
// special case if cgrp_id is 0: returns true and first free location if exists, false if no more free locations
// does not handle locking
// assigns index of res to res_idx if not null (if res = NULL, assigns it MAX_SUB_SCHEDS)
bool global_sub_lookup(u64 cgrp_id, struct global_sub_params **res, u32 *res_idx) {
	struct global_sub_params *first_free = NULL;
	u32 first_free_idx = MAX_SUB_SCHEDS;
	for (u32 idx = 0; idx < MAX_SUB_SCHEDS; ++idx) {
		struct global_sub_params *gsp = (struct global_sub_params *)bpf_map_lookup_elem(&global_subs, &idx);
		if (unlikely(!gsp)) continue; // for compiler, should not happen
		if (gsp->sp.cgrp_id == cgrp_id) {
			*res = gsp;
			if (res_idx) *res_idx = idx;
			return true;
		}
		if (gsp->sp.cgrp_id == 0 && !first_free) first_free = gsp;
	}
	*res = first_free;
	if (res_idx) *res_idx = first_free_idx;
	return false;
}

s32 BPF_STRUCT_OPS(wrr_sub_attach, struct scx_sub_attach_args *args)
{
	u64 cgrp_id = args->ops->sub_cgroup_id;
	struct global_sub_params *gsp;
	
	bpf_spin_lock(&global_subs_write_lock);

	if (global_sub_lookup(cgrp_id, &gsp, NULL)) {
 		bpf_printk("[INFO] [ATTACH] %llu already attached", cgrp_id);
		bpf_spin_unlock(&global_subs_write_lock);
		return -EEXIST;
	}
	if (!gsp) {
		bpf_spin_unlock(&global_subs_write_lock);

		bpf_printk("[INFO] [ATTACH] %llu attaching sub would exceed MAX_SUB_SCHEDS", cgrp_id);
		return -ENOMEM;
	}

	seqlock_update_start(&gsp->lock);
	
	gsp->sp.cgrp_id = cgrp_id;
	gsp->sp.weight = DEFAULT_WEIGHT;
	
	seqlock_update_end(&gsp->lock);

	bpf_spin_unlock(&global_subs_write_lock);

  return 0;
}

void BPF_STRUCT_OPS(wrr_sub_detach, struct scx_sub_detach_args *args)
{
  u64 cgrp_id = args->ops->sub_cgroup_id;
	struct global_sub_params *gsp;

	bpf_spin_lock(&global_subs_write_lock);

	if (!global_sub_lookup(cgrp_id, &gsp, NULL) || !gsp) {
		bpf_spin_unlock(&global_subs_write_lock);

 		bpf_printk("[INFO] [DETACH] %llu not attached", cgrp_id);
		return;
	}

	seqlock_update_start(&gsp->lock);

	gsp->sp.cgrp_id = 0;
	gsp->sp.weight = 0;
	
	seqlock_update_end(&gsp->lock);

	bpf_spin_unlock(&global_subs_write_lock);
}

void BPF_STRUCT_OPS(wrr_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
  u64 cgrp_id = cgrp->kn->id;
	struct global_sub_params *gsp;

	bpf_spin_lock(&global_subs_write_lock);
	if (!global_sub_lookup(cgrp_id, &gsp, NULL) || !gsp) {
 		bpf_printk("[INFO] [SET_WEIGHT] cgroup_set_weight %llu not attached", cgrp_id);
		bpf_spin_unlock(&global_subs_write_lock);
		return;
	}
	
	seqlock_update_start(&gsp->lock);
	gsp->sp.weight = weight;
	seqlock_update_end(&gsp->lock);

	bpf_spin_unlock(&global_subs_write_lock);
}

// re-purpose for assigning affinities
void BPF_STRUCT_OPS(wrr_cgroup_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	bpf_printk("[INFP] [CGROUP_SET_BANDWIDTH] %llu period=%lu quota=%ld burst=%lu",
				cgrp->kn->id, period_us, quota_us, burst_us);
}

// returns true if dispatched successfully
bool try_sub_dispatch(struct local_sub_params *lsp, struct cpu_sched_state *ss, u64 now) {
	if (now >= ss->budget_depletion_time) return false;

	u64 rem_time = ss->budget_depletion_time - now;
	bpf_timer_start(&ss->budget_timer, rem_time, 0);

	if (!scx_bpf_sub_dispatch(lsp->sp.cgrp_id)) {
		bpf_timer_cancel(&ss->budget_timer);
		return false;
	}

	return true;
}

void BPF_STRUCT_OPS(wrr_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 ucpu = cpu;
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	if (unlikely(!ss)) return; // for compiler, should not happen

	// check if sub yielded early, in which case should dispatch itself again until budget gone
	if (bpf_timer_cancel(&ss->budget_timer)) {
		u64 now = bpf_ktime_get_ns();
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &ss->curr_rr_idx);
		if (now < ss->budget_depletion_time && try_sub_dispatch(lsp, ss, now)) {
			return;
		}
	}

	for (u32 i = 0; i < MAX_SUB_SCHEDS; ++i) {
		sync_local_sub(ss->next_rr_idx);
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &ss->next_rr_idx);
		u64 now = bpf_ktime_get_ns();
		ss->budget_depletion_time = now + lsp->sp.weight;
		ss->curr_rr_idx = ss->next_rr_idx;
		ss->next_rr_idx = ss->next_rr_idx + 1 == MAX_SUB_SCHEDS ? 0 : ss->next_rr_idx + 1;
		if (try_sub_dispatch(lsp, ss, now)) {
			return;
		}
	}
	return; // no sub schedulers
}

s32 BPF_STRUCT_OPS(wrr_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	bpf_printk("[INFO] [CGROUP_INIT] %llu weight=%u period=%lu quota=%ld burst=%lu",
				cgrp->kn->id, args->weight, args->bw_period_us,
				args->bw_quota_us, args->bw_burst_us);
	return 0;
}

// task scheduling functions that should not be called
s32 BPF_STRUCT_OPS(wrr_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
  scx_bpf_error("wrr_select_cpu called unexpectedly");
    return prev_cpu; // Required to return a valid CPU even when erroring
}

void BPF_STRUCT_OPS(wrr_enqueue, struct task_struct *p, u64 enq_flags)
{
  scx_bpf_error("wrr_enqueue called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_dequeue, struct task_struct *p, u64 deq_flags)
{
  scx_bpf_error("wrr_dequeue called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
  scx_bpf_error("wrr_cpu_acquire called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
  scx_bpf_error("wrr_cpu_release called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_running, struct task_struct *p)
{
  scx_bpf_error("wrr_running called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_stopping, struct task_struct *p, bool runnable)
{
  scx_bpf_error("wrr_stopping called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_runnable, struct task_struct *p, u64 enq_flags)
{
  scx_bpf_error("wrr_runnable called unexpectedly");
}

void BPF_STRUCT_OPS(wrr_quiescent, struct task_struct *p, u64 deq_flags)
{
  scx_bpf_error("wrr_quiescent called unexpectedly");
}

s32 BPF_STRUCT_OPS(wrr_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  scx_bpf_error("wrr_init_task called unexpectedly");
    return -EINVAL;
}

void BPF_STRUCT_OPS(wrr_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
  scx_bpf_error("wrr_exit_task called unexpectedly");
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
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
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