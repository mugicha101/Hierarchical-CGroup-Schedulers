#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "trace_events.h"
#include "scx_jlfp.h"

CREATE_TRACE_BUFF();

char _license[] SEC("license") = "GPL";

// concrete job-level fixed-priority scheduler using the shared JLFP engine
// task weights come from the pinned task_weights map under /sys/fs/bpf/scx
// larger task weights mean higher priority within the tuple's task-priority field
// select_cid, enqueue, and dispatch reconsidering runnable prev read the map
// changing a map entry does not reorder queued tasks or preempt running tasks by itself

const volatile u64 cgroup_id; // id of this cgroup, 0 if root
const volatile u32 max_tasks; // max tasks allowed in the cgroup (include non-scx, stores a cmask for all tasks)
const volatile bool global_search; // search all fully-overlapped shards (fallback on prev shard if no fully-overlapped shards)
u64 slice = 1000000ULL; // 1ms

UEI_DEFINE(uei);

struct jlfp_arena __arena_global aa;

// configured task weights, shared through the pinned map across JLFP instances
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_weights SEC(".maps");

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
      wt = WT_FROM_FIELDS(get_task_weight(p), is_migration_disabled(p), aa.self_cgroup_weight, 0);
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
  scx_update_idle(&aa.scx, cid, idle);
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

  if (unlikely(!init_jlfp_task_ctx(&aa.scx, p, args))) {
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

  if (!scx_exit_task(&aa.scx, p)) return;

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

  task_ctx_t *tctx = scx_set_cmask(p, cmask_in);
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
