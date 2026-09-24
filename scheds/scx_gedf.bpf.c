// Global Earliest Deadline First (GEDF) scheduler
// Task realtime parameters can be modified via a FIFO file at /tmp/scx/<cgroup path>/task_realtime_params
// realtime parameters should be set before moving task into sched_ext and remain constant throughout lifetime of program
// job completions are marked with write into job_completion_flags indexed by thread id with 1 byte entries

#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "trace_events.h"
#include "scx_gedf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct gedf_arena __arena_global aa;

s32 BPF_STRUCT_OPS_SLEEPABLE(gedf_init)
{
  return jlfp_init_core(&aa.jlfp);
}

void BPF_STRUCT_OPS(gedf_exit, struct scx_exit_info *ei)
{
  TRACE_EVENT(struct sched_trace_event_exit, SCHED_TRACE_EXIT,
    e->cgrp_id = aa.jlfp.base.cgroup_id;
  );
  bpf_printk("[INFO] [GEDF] [EXIT] cgroup=%llu\n", aa.jlfp.base.cgroup_id);
  UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(gedf_sub_attach, struct scx_sub_attach_args *args)
{
  return jlfp_sub_attach_core(&aa.jlfp, args);
}

void BPF_STRUCT_OPS(gedf_sub_detach, struct scx_sub_detach_args *args)
{
  jlfp_sub_detach_core(&aa.jlfp, args);
}

void BPF_STRUCT_OPS(gedf_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
  jlfp_cpuctl_set_weight_core(&aa.jlfp, cgrp, weight);
}

void BPF_STRUCT_OPS(gedf_dispatch, s32 cid, struct task_struct *prev)
{
  struct jlfp_arena __arena *a = &aa.jlfp;
  u64 prev_weight = 0;
  if (prev && (BPF_CORE_READ(prev, scx.flags) & SCX_TASK_QUEUED))
    prev_weight = get_task_weight(prev);

  if (unlikely(cid >= NR_CPUS)) return; // for testing limited CPUs

  // bpf_printk("[INFO] [GEDF] [DISPATCH] dispatching on cpu %u", cpu);
  TRACE_FUNC_START("dispatch");

  struct latency_ctx lctx;
  lstat_start(&lctx);

  cid = cid & (NR_CPUS - 1); // for verifier

  // dispatch task
  u64 tid = jlfp_try_task_dispatch(a, cid, prev, a->slice, prev_weight);
  if (tid) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    TRACE_FUNC_END("dispatch", prev && tid == prev->pid ? "DISPATCHED PREV" : "DISPATCHED TASK");
    return;
  }

  // dispatch cgroups if no tasks
  if (jlfp_try_sub_dispatch(a, cid, prev)) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    TRACE_FUNC_END("dispatch", "DISPATCHED CGROUP");
    return;
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

s32 BPF_STRUCT_OPS(gedf_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
  // bpf_printk("[INFO] [GEDF] [SELECT_CID] cgroup=%d pid=%d comm=%s prev_cid=%d wake_flags=%llu", cgroup_id, p->pid, p->comm, prev_cid, wake_flags);
  TRACE_FUNC_START("select_cid");

  struct latency_ctx lctx;
  lstat_start(&lctx);
  jlfp_pick_cid(&aa.jlfp, p, (u32)prev_cid, SCX_ENQ_WAKEUP | wake_flags, get_task_weight(p), aa.jlfp.slice);
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].select_cid);

  TRACE_FUNC_END("select_cid", "");
  return prev_cid; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(gedf_enqueue, struct task_struct *p, u64 enq_flags)
{
  // bpf_printk("[INFO] [GEDF] [ENQUEUE] cgroup=%d pid=%d comm=%s enq_flags=%llu", cgroup_id, p->pid, p->comm, enq_flags);
  TRACE_FUNC_START("enqueue");

  HOTPATH_TRACE_EVENT(struct sched_trace_event_enqueue_args, SCHED_TRACE_ENQUEUE_ARGS,
    e->enq_flags = enq_flags;
    e->prev_cid = (u32)scx_bpf_task_cid(p);
    e->tid = p->pid;
  );

  struct latency_ctx lctx;
  lstat_start(&lctx);

  jlfp_pick_cid(&aa.jlfp, p, (u32)scx_bpf_task_cid(p), enq_flags, get_task_weight(p), aa.jlfp.slice);
  
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].enqueue);

  TRACE_FUNC_END("enqueue", "");
}

void BPF_STRUCT_OPS(gedf_running, struct task_struct *p)
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
    bpf_printk("[WARN] [GEDF] [RUNNING] Task %d has policy %d", p->pid, policy);
    wt = (policy == SCHED_FIFO || policy == SCHED_RR) ? U128_MAX : 0;
  } else {
    if (unlikely(!tctx)) { // should not happen but just incase
      wt = WT_FROM_FIELDS(get_task_weight(p), is_migration_disabled(p), aa.jlfp.base.self_cgroup_weight, 0);
    } else {
      wt = get_jlfp_task_ctx(tctx)->weight;
    }
  }

  jlfp_running_core(&aa.jlfp, p, tctx, wt, &lctx);
}

void BPF_STRUCT_OPS(gedf_stopping, struct task_struct *p, bool runnable)
{
  jlfp_stopping_core(&aa.jlfp, p, runnable);
}

void BPF_STRUCT_OPS(gedf_update_idle, s32 cid, bool idle)
{
  base_update_idle(&aa.jlfp.base, cid, idle);
}

// from qmap
// TODO: change to if SWITCH_PARTIAL then only allocate if SCX policy or when switches to SCX policy
// because cid-form removes enable/disable can only be done in enqueue
s32 BPF_STRUCT_OPS_SLEEPABLE(gedf_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  TRACE_FUNC_START("init_task");
  
  TRACE_EVENT(struct sched_trace_event_init_task_args, SCHED_TRACE_INIT_TASK_ARGS,
    e->tid = p->pid;
    e->fork = args->fork;
  );
  struct latency_ctx lctx;
  lstat_start(&lctx);

  // bpf_printk("[INFO] [GEDF] [INIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);

  if (unlikely(!init_jlfp_task_ctx(&aa.jlfp.base, p, args))) {
    return -ENOMEM;
  }

  TRACE_FUNC_END("init_task", "");
  return 0;
}

// from qmap
void BPF_STRUCT_OPS(gedf_exit_task, struct task_struct *p)
{
  TRACE_FUNC_START("exit_task");

  TRACE_EVENT(struct sched_trace_event_exit_task_args, SCHED_TRACE_EXIT_TASK_ARGS,
    e->tid = p->pid;
  );
  
  // bpf_printk("[INFO] [GEDF] [EXIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
  struct latency_ctx lctx;
  lstat_start(&lctx);

  if (!base_exit_task(&aa.jlfp.base, p)) return;

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].exit_task);
  TRACE_FUNC_END("exit_task", "");
}

// from qmap
void BPF_STRUCT_OPS(gedf_set_cmask, struct task_struct *p, const struct scx_cmask *cmask_in)
{
  TRACE_FUNC_START("set_cmask");
  struct latency_ctx lctx;
  lstat_start(&lctx);

  task_ctx_t *tctx = base_set_cmask(p, cmask_in);
  if (unlikely(!tctx)) return;

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].set_cmask);
  TRACE_FUNC_END("set_cmask", "");

  TRACE_EVENT(struct sched_trace_event_set_cmask, SCHED_TRACE_SET_CMASK,
    e->tid = p->pid;
    e->cmask = cmask_to_u64(&tctx->cpus_allowed);
  );
}

void BPF_STRUCT_OPS(gedf_tick, struct task_struct *p) {
  // measure overhead of latency tracking
  struct latency_ctx lctx;
  u32 cid = scx_bpf_this_cid();
  lstat_start(&lctx);
  lstat_record(&lctx, &aa.jlfp.stats[cid].no_op);
}

// check for job completion on wakeup
// handles case where task sleeps until next period
void BPF_STRUCT_OPS(gedf_runnable, struct task_struct *p, u64 enq_flags) {
  if (enq_flags & SCX_ENQ_WAKEUP) {
    check_completion(p);
  }
}

// check for job completion on sched_yield
// handles case where task wants to do maximal early releasing
bool BPF_STRUCT_OPS(gedf_yield, struct task_struct *from, struct task_struct *to) {
  if (!to) check_completion(from);

  from->scx.slice = 0;
  return false;
}

// ops

SCX_OPS_CID_DEFINE(gedf_ops,
  .name               = "gedf",
  .init               = (void *)gedf_init,
  .exit               = (void *)gedf_exit,
  .flags              = SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_BUILTIN_IDLE_PER_NODE | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ENQ_EXITING | SCX_OPS_TID_TO_TASK,
  .select_cid         = (void *)gedf_select_cid,
  .enqueue            = (void *)gedf_enqueue,
  .running            = (void *)gedf_running,
  .stopping           = (void *)gedf_stopping,
  .init_task          = (void *)gedf_init_task,
  .exit_task          = (void *)gedf_exit_task,
  .set_cmask          = (void *)gedf_set_cmask,
  .dispatch           = (void *)gedf_dispatch,
  .cpuctl_set_weight  = (void *)gedf_cpuctl_set_weight,
  .sub_attach         = (void *)gedf_sub_attach,
  .sub_detach         = (void *)gedf_sub_detach,
  .update_idle        = (void *)gedf_update_idle,
  .runnable           = (void *)gedf_runnable,
  .yield              = (void *)gedf_yield,
  .tick               = (void *)gedf_tick
);
