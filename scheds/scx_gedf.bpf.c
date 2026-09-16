// Global Earliest Deadline First (GEDF) scheduler for the Linux kernel
// sub-policy of JLFP
// Task sporadic parameters can be modified via a FIFO file at /sys/fs/cgroup/<cgroup path>/task_rt_params
// works by setting the slice to time until next deadline.
// Note: any slice extensions from kthread interrupts are considered part of overhead and not accounted for.

// TODO: main logic changes needed
// 1 - add task_realtime_params which maps a task to its period, relative deadline, and whether its periodic or sporadic
// 2 - add a fifo file in the cgroup directory that can update a tasks params similar to how existing cgroup pseudofiles work
//     service writes to this file in userspace c program
// 3 - handle period update inside get_task_weight
//     if task is before its deadline, no update
//     if task is at or after its deadline, update period end
//     new period end depends on type of task
//     - for periodic: last period end + period (note: last period is not necessarily the period represented by abs deadline since another period could have passed since then)
//                     can use ceil div to update this in O(1) (be wary of overflow)
//                     this should always produce a time in the future (never current time)
//     - for sporadic: max(now, period end) + period
//     updating the period at deadline end allows for early execution
// 4 - update both slice and priority whenever a task is dispatched based on get_task_weight's result
//     ops.dispatch when popping task from GDSQ
//     ops.dispatch when renewing prev task's slice
//     pick_cid when moving enqueued task to LDSQ
//     this can be done in helper function update_task_dl which calls get_task_weight
//     to prevent disparities from multiple timing measurements, pass the measured time as a timestamp to get_task_weight and use this same timestamp for all operations
//     slice is updated to time until next deadline (should be positive)
// 5 - priorities can change while a task sits in the GDSQ since their deadlines might pass
//     its guaranteed that tasks whose deadline changed are at top of GDSQ since its ordered by increasing deadline
//     its also guaranteed that the new priority is lower and thus the task should still be in the GDSQ
//     thus when popping the GDSQ we check if its deadline is passed first
//     if its deadline changed, we re-enqueue it into the GDSQ with its new deadline as detailed in 3/4 (slice update should be omitted)
//     if the CPU won the race to re-enqueue it, it updates its task weight
//     even if that task dispatches before task_weights is updated, the time until the next deadline shouldn't be on the order of ns (otherwise scheduling overhead would make it unviable anyways)
//     thus its unlikely that it overwrites a new weight set by the dispatching CPU
//     timestamp desync between CPUs could cause task_weight to be updated to an older deadline than dispatching task assigns
//     but this requires a periodic task to be first considered for dispatch straddling a deadline after its period expired
//     worst case its task_weight is updated to a priority matching a deadline 1 period earlier (assuming periods are larger than the gap between dispatch and set, which is reasonable), giving it excessive priority
//     this case requires a periodic task to have a deadline overrun and thus recovery is best-effort anyways, so this is pretty minor.
// 6 - treat tasks without realtime parameters as non-realtime low priority tasks which get dispatched only if the core has no realtime work
//     these should have weight 0
//     this only serves as a fallback mechanism in case a subscheduler exits
//     thus execution order doesn't really matter
// 7 - copy over JLFP stats

#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "trace_events.h"
#include "scx_gedf.h"

char _license[] SEC("license") = "GPL";

const volatile u64 cgroup_id; // id of this cgroup, 0 if root
const volatile u32 max_tasks; // max tasks allowed in the cgroup (include non-scx, stores a cmask for all tasks)
const volatile bool global_search; // search all fully-overlapped shards (fallback on prev shard if no fully-overlapped shards)
u64 slice = 1000000ULL; // 1ms

UEI_DEFINE(uei);

struct gedf_arena __arena_global aa;

// shared with JLFP
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_weights SEC(".maps");

// global sporadic params map
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct sporadic_params);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_sporadic_params SEC(".maps");

// configured priority for selection, enqueue, and reconsidering runnable prev
// apply period replenishment here
u64 __always_inline get_task_weight(struct task_struct *p) {
  u64 weight = DEFAULT_TASK_WEIGHT;
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, 0, 0);
  if (lookup_weight) {
    weight = *lookup_weight;
  }
  if (unlikely(weight == 0)) {
    bpf_printk("[WARN] [GEDF] [GET_WEIGHT] Task %d has weight 0, using weight 1 instead", p->pid);
    weight = 1;
  }
  return weight;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(jlfp_init)
{
  return jlfp_init_core(&aa, cgroup_id, max_tasks);
}

void BPF_STRUCT_OPS(jlfp_exit, struct scx_exit_info *ei)
{
  TRACE_EVENT(struct sched_trace_event_exit, SCHED_TRACE_EXIT,
    e->cgrp_id = cgroup_id;
  );
  bpf_printk("[INFO] [JLFP] [EXIT] cgroup=%llu\n", cgroup_id);
  UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(jlfp_sub_attach, struct scx_sub_attach_args *args)
{
  return jlfp_sub_attach_core(&aa, args);
}

void BPF_STRUCT_OPS(jlfp_sub_detach, struct scx_sub_detach_args *args)
{
  jlfp_sub_detach_core(&aa, args);
}

void BPF_STRUCT_OPS(jlfp_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
  jlfp_cpuctl_set_weight_core(&aa, cgrp, weight);
}

// configured priority for selection, enqueue, and reconsidering runnable prev
u64 __always_inline get_task_weight(struct task_struct *p) {
  u64 weight = DEFAULT_TASK_WEIGHT;
  u64 *lookup_weight = bpf_task_storage_get(&task_weights, p, 0, 0);
  if (lookup_weight) {
    weight = *lookup_weight;
  }
  if (unlikely(weight == 0)) {
    bpf_printk("[WARN] [JLFP] [GET_WEIGHT] Task %d has weight 0, using weight 1 instead", p->pid);
    weight = 1;
  }
  return weight;
}

void BPF_STRUCT_OPS(jlfp_dispatch, s32 cid, struct task_struct *prev)
{
  u64 prev_priority = 0;
  if (prev && (BPF_CORE_READ(prev, scx.flags) & SCX_TASK_QUEUED)) {
    prev_priority = get_task_weight(prev);
  }
  jlfp_dispatch_core(&aa, cid, prev, slice, prev_priority);
}

s32 BPF_STRUCT_OPS(jlfp_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
  // bpf_printk("[INFO] [JLFP] [SELECT_CID] cgroup=%d pid=%d comm=%s prev_cid=%d wake_flags=%llu", cgroup_id, p->pid, p->comm, prev_cid, wake_flags);
  TRACE_FUNC_START("select_cid");

  struct latency_ctx lctx;
  lstat_start(&lctx);
  pick_cid(&aa, p, (u32)prev_cid, SCX_ENQ_WAKEUP | wake_flags, get_task_weight(p), slice, global_search);
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].select_cid);

  TRACE_FUNC_END("select_cid", "");
  return prev_cid; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(jlfp_enqueue, struct task_struct *p, u64 enq_flags)
{
  // bpf_printk("[INFO] [JLFP] [ENQUEUE] cgroup=%d pid=%d comm=%s enq_flags=%llu", cgroup_id, p->pid, p->comm, enq_flags);
  TRACE_FUNC_START("enqueue");

  HOTPATH_TRACE_EVENT(struct sched_trace_event_enqueue_args, SCHED_TRACE_ENQUEUE_ARGS,
    e->enq_flags = enq_flags;
    e->prev_cid = (u32)scx_bpf_task_cid(p);
    e->tid = p->pid;
  );

  struct latency_ctx lctx;
  lstat_start(&lctx);

  pick_cid(&aa, p, (u32)scx_bpf_task_cid(p), enq_flags, get_task_weight(p), slice, global_search);
  
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].enqueue);

  TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(jlfp_running, struct task_struct *p)
{
  struct latency_ctx lctx;
  lstat_start(&lctx);
  
  // check policy of task
  // for SCHED_FIFO or SCHED_RR, set weight to MAX since sched_ext cannot kick it
  // for SCHED_EXT find their weight in task context
  // for other policies, set weight to 0 since they are lower priority than SCHED_EXT
  int policy = BPF_CORE_READ(p, policy);
  weight_tuple_t wt;
  task_ctx_t *tctx = get_task_ctx(p);
  if (policy != SCHED_EXT) {
    bpf_printk("[WARN] [JLFP] [RUNNING] Task %d has policy %d", p->pid, policy);
    wt = (policy == SCHED_FIFO || policy == SCHED_RR) ? U128_MAX : 0;
  } else {
    if (unlikely(!tctx)) { // should not happen but just incase
      wt = WT_FROM_FIELDS(get_task_weight(p), is_migration_disabled(p), aa.base.self_cgroup_weight, 0);
    } else {
      wt = get_jlfp_task_ctx(tctx)->weight;
    }
  }

  jlfp_running_core(&aa, p, tctx, wt, &lctx);
}

void BPF_STRUCT_OPS(jlfp_stopping, struct task_struct *p, bool runnable)
{
  jlfp_stopping_core(&aa, p, runnable);
}

// update weight of current running task
// since this only runs in the first attached FP scheduler (typically root), doesn't know the running weight of the tasks in lower cgroups
// thus just blindly kick
// can probably improve this by loading a new instance per FP scheduler
// SEC("syscall")
// int BPF_PROG(update_weight, u64 pid, u64 weight) {
//   // bpf_printk("[INFO] [JLFP] [UPDATE_WEIGHT] Updating weight of task %d to %llu\n", pid, weight);
//   // update weight in map
//   struct task_struct *p = bpf_task_from_pid(pid);
//   if (unlikely(!p)) {
//     return 0; // for verifier, should not happen
//   }

//   u64 *task_weight_ptr = bpf_task_storage_get(&task_weights, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
//   if (unlikely(!task_weight_ptr)) {
//     bpf_task_release(p);
//     return 0; // for verifier, should not happen
//   }
//   u32 cid = scx_bpf_task_cid(p);
//   *task_weight_ptr = weight;
//   bpf_task_release(p);

//   TRACE_EVENT(struct sched_trace_event_set_task_weight, SCHED_TRACE_SET_TASK_WEIGHT,
//     e->tid = pid;
//     e->weight = weight;
//   );

//   // kick cid

//   return 0;
// }

void BPF_STRUCT_OPS(jlfp_update_idle, s32 cid, bool idle)
{
  base_update_idle(&aa.base, cid, idle);
}

// from qmap
// TODO: change to if SWITCH_PARTIAL then only allocate if SCX policy or when switches to SCX policy
// because cid-form removes enable/disable can only be done in enqueue
s32 BPF_STRUCT_OPS_SLEEPABLE(jlfp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  TRACE_FUNC_START("init_task");
  
  TRACE_EVENT(struct sched_trace_event_init_task_args, SCHED_TRACE_INIT_TASK_ARGS,
    e->tid = p->pid;
    e->fork = args->fork;
  );
  struct latency_ctx lctx;
  lstat_start(&lctx);

  // bpf_printk("[INFO] [JLFP] [INIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);

  if (unlikely(!init_jlfp_task_ctx(&aa.base, p, args))) {
    return -ENOMEM;
  }

  TRACE_FUNC_END("init_task", "");
  return 0;
}

// from qmap
void BPF_STRUCT_OPS(jlfp_exit_task, struct task_struct *p)
{
  TRACE_FUNC_START("exit_task");

  TRACE_EVENT(struct sched_trace_event_exit_task_args, SCHED_TRACE_EXIT_TASK_ARGS,
    e->tid = p->pid;
  );
  
  // bpf_printk("[INFO] [JLFP] [EXIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
  struct latency_ctx lctx;
  lstat_start(&lctx);

  if (!base_exit_task(&aa.base, p)) return;

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].exit_task);
  TRACE_FUNC_END("exit_task", "");
}

// from qmap
void BPF_STRUCT_OPS(jlfp_set_cmask, struct task_struct *p, const struct scx_cmask *cmask_in)
{
  TRACE_FUNC_START("set_cmask");
  struct latency_ctx lctx;
  lstat_start(&lctx);

  task_ctx_t *tctx = base_set_cmask(p, cmask_in);
  if (unlikely(!tctx)) return;

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].set_cmask);
  TRACE_FUNC_END("set_cmask", "");

  TRACE_EVENT(struct sched_trace_event_set_cmask, SCHED_TRACE_SET_CMASK,
    e->tid = p->pid;
    e->cmask = cmask_to_u64(&tctx->cpus_allowed);
  );
}

void BPF_STRUCT_OPS(jlfp_tick, struct task_struct *p) {
  // measure overhead of latency tracking
  struct latency_ctx lctx;
  u32 cid = scx_bpf_this_cid();
  lstat_start(&lctx);
  lstat_record(&lctx, &aa.stats[cid].no_op);
}

// ops

SCX_OPS_CID_DEFINE(jlfp_ops,
  .name               = "jlfp",
  .init               = (void *)jlfp_init,
  .exit               = (void *)jlfp_exit,
  .flags              = SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_BUILTIN_IDLE_PER_NODE | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ENQ_EXITING | SCX_OPS_TID_TO_TASK,
  .select_cid         = (void *)jlfp_select_cid,
  .enqueue            = (void *)jlfp_enqueue,
  .running            = (void *)jlfp_running,
  .stopping           = (void *)jlfp_stopping,
  .init_task          = (void *)jlfp_init_task,
  .exit_task          = (void *)jlfp_exit_task,
  .set_cmask          = (void *)jlfp_set_cmask,
  .dispatch           = (void *)jlfp_dispatch,
  .cpuctl_set_weight  = (void *)jlfp_cpuctl_set_weight,
  .sub_attach         = (void *)jlfp_sub_attach,
  .sub_detach         = (void *)jlfp_sub_detach,
  .update_idle        = (void *)jlfp_update_idle,
  .tick               = (void *)jlfp_tick
);
