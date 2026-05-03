#include <scx/common.bpf.h>

#include "trace_events.h"
CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// fixed priority scheduler with earliest arrival tie breaks
// weight = priority (higher weight = higher priority)
// can use same system as wrr but keep track of priority order in a local sorted array (sorting is slow)
// optimization 1: if none if system sync with new data, can re-use prior order (still needs to check all entries)
// optimization 2: another seqlock tells if any entry has changed in global, so can skip syncing all entries if epoch is unchanged
// note: priority >= 1 (set_cgroup_weight limited to weight >= 1 anyways)

const volatile u64 cgroup_id;

#ifndef SCX_KICK_REPICK
#define SCX_KICK_REPICK 0b10
#endif

#define MAX_SUB_SCHEDS 64 // must be power of 2
#define DEFAULT_WEIGHT 100000000ull // 100ms
#define MAX_PENDING_UPDATES 1024
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

struct cpu_sched_state {
  __u64 local_gen; // for checking if global_gen updated
	u32 curr_idx; // index of currently running subscheduler
  u64 priority[MAX_SUB_SCHEDS]; // cached priorities of subs
  int porder[MAX_SUB_SCHEDS]; // cached indices of subs in decreasing priority order
};

// data shared between all cores
// concurrency: single writer, multiple readers
struct global_data {
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
	// bpf_printk("[INFO] [FP] [SYNC] cpu %d: Synced index %u: gen %llu -> gen %llu (new weight: %llu)", bpf_get_smp_processor_id(), idx, old_gen, gen_fin, lsp->sp.weight);

	return true;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fp_init)
{
	// bpf_printk("[INFO] [FP] [INIT] Initializing SCX FP Scheduler");
	TRACE_FUNC_START("init");
	u32 err = 0;
	u32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &cpu);
		if (unlikely(!ss)) return -EINVAL; // for verifier, should not happen

    u32 i;
    bpf_for(i, 0, MAX_SUB_SCHEDS) {
      ss->porder[i] = i;
    }
	}
	TRACE_FUNC_END("init", "");
	return err;
}

void BPF_STRUCT_OPS(fp_exit)
{
	// bpf_printk("[INFO] [FP] [EXIT] Exiting SCX FP Scheduler\n");
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
		if (unlikely(!lsp)) return; // for verifier, should not happen

    ss->priority[i] = lsp->sp.weight;
	}
  if (!modified) return; // no updates after syncing, so priority order unchanged

  // selection sort faster than quicksort for small MAX_SUB_SCHEDS
  bpf_for(i, 0, MAX_SUB_SCHEDS) {
    u32 j;
    bpf_for(j, i+1, MAX_SUB_SCHEDS) {
      if (ss->priority[ss->porder[j]] < ss->priority[ss->porder[i]]) {
        u32 t = ss->porder[i];
        ss->porder[i] = ss->porder[j];
        ss->porder[j] = t;
      }
    }
  }
}

void BPF_STRUCT_OPS(fp_dispatch, s32 cpu, struct task_struct *prev)
{
	// FOR TESTING (limits CPUs to prevent freezing)
	if (cpu >= 4) return;

	// bpf_printk("[INFO] [FP] [DISPATCH] dispatching on cpu %u", cpu);
	TRACE_FUNC_START("dispatch");
	u32 ucpu = cpu;
	struct cpu_sched_state *ss = bpf_map_lookup_elem(&sched_state, &ucpu);
	struct global_data *global = fetch_global();
	if (unlikely(!ss) || unlikely(!global)) return; // for verifier, should not happen

  sync_priority_order(global, ss);

	u32 i;
	bpf_for(i, 0, MAX_SUB_SCHEDS) {
		struct local_sub_params *lsp = bpf_map_lookup_elem(&local_subs, &ss->porder[i]);
		if (unlikely(!lsp)) return; // for verifier, should not happen

		if (lsp->sp.cgrp_id == 0) { // empty slots at lowest priority
			break;
		}

    ss->curr_idx = ss->porder[i];
		if (scx_bpf_sub_dispatch(lsp->sp.cgrp_id)) {
      TRACE_FUNC_END("dispatch", "");
      return;
    }
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

void BPF_STRUCT_OPS(fp_enqueue, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("[INFO] [FP] [ENQUEUE] enqueueing pid=%d", p->pid);
	// scx_bpf_error("fp_enqueue called unexpectedly");
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
	// bpf_printk("[INFO] [FP] fp_running called unexpectedly");
  // scx_bpf_error("fp_running called unexpectedly");
}

void BPF_STRUCT_OPS(fp_stopping, struct task_struct *p, bool runnable)
{
	// bpf_printk("[INFO] [FP] fp_stopping called unexpectedly");
  // scx_bpf_error("fp_stopping called unexpectedly");
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
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_HAS_CGROUP_WEIGHT,
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
