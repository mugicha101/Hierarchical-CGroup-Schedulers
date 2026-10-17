// Global Earliest Deadline First (GEDF) scheduler
// Task realtime parameters can be modified via a FIFO file at /tmp/scx/<cgroup path>/task_realtime_params
// realtime parameters should be set before moving task into sched_ext and remain constant throughout lifetime of program
// job completions are marked with atomic bitwise OR into job_completion_flags, one bit per thread id

#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "diagnostics.h"
#include "scx_gedf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct gedf_arena __arena_global aa;
bool jlfp_sched_switch_ready;

s32 BPF_STRUCT_OPS_SLEEPABLE(gedf_init)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_INIT, aa.jlfp.base.cgroup_id);

  s32 err = jlfp_init_core(&aa.jlfp);
  if (!err) {
    smp_wmb();
    WRITE_ONCE(jlfp_sched_switch_ready, true);
  }
  SCXTP_EMIT_OP_EXIT(SCXTP_OP_INIT, aa.jlfp.base.cgroup_id);
  return err;
}

void BPF_STRUCT_OPS(gedf_exit, struct scx_exit_info *ei)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_EXIT, aa.jlfp.base.cgroup_id);

  WRITE_ONCE(jlfp_sched_switch_ready, false);
  SCXTP_EMIT(exit, aa.jlfp.base.cgroup_id,
    e->cgrp_id = aa.jlfp.base.cgroup_id;
  );
  bpf_printk("[INFO] [GEDF] [EXIT] cgroup=%llu\n", aa.jlfp.base.cgroup_id);
  UEI_RECORD(uei, ei);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_EXIT, aa.jlfp.base.cgroup_id);
}

s32 BPF_STRUCT_OPS(gedf_sub_attach, struct scx_sub_attach_args *args)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_SUB_ATTACH, aa.jlfp.base.cgroup_id);

  s32 err = jlfp_sub_attach_core(&aa.jlfp, args);
  SCXTP_EMIT_OP_EXIT(SCXTP_OP_SUB_ATTACH, aa.jlfp.base.cgroup_id);
  return err;
}

void BPF_STRUCT_OPS(gedf_sub_detach, struct scx_sub_detach_args *args)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_SUB_DETACH, aa.jlfp.base.cgroup_id);

  jlfp_sub_detach_core(&aa.jlfp, args);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_SUB_DETACH, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_CPUCTL_SET_WEIGHT, aa.jlfp.base.cgroup_id);

  jlfp_cpuctl_set_weight_core(&aa.jlfp, cgrp, weight);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_CPUCTL_SET_WEIGHT, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_dispatch, s32 cid, struct task_struct *prev)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_DISPATCH, aa.jlfp.base.cgroup_id);

  struct jlfp_arena __arena *a = &aa.jlfp;
  u64 prev_weight = 0;
  if (prev && (BPF_CORE_READ(prev, scx.flags) & SCX_TASK_QUEUED))
    prev_weight = get_task_weight(prev);

  if (unlikely(cid >= NR_CPUS)) {
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_DISPATCH, aa.jlfp.base.cgroup_id);
    return; // for testing limited CPUs
  }

  // bpf_printk("[INFO] [GEDF] [DISPATCH] dispatching on cpu %u", cpu);

  struct latency_ctx lctx;
  lstat_start(&lctx);

  cid = cid & (NR_CPUS - 1); // for verifier

  // dispatch task
  u64 tid = jlfp_try_task_dispatch(a, cid, prev, a->slice, prev_weight);
  if (tid) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_DISPATCH, aa.jlfp.base.cgroup_id);
    return;
  }

  // dispatch cgroups if no tasks
  if (jlfp_try_sub_dispatch(a, cid)) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_DISPATCH, aa.jlfp.base.cgroup_id);
    return;
  }

  lstat_record(&lctx, &a->stats[cid].dispatch);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_DISPATCH, aa.jlfp.base.cgroup_id);
}

s32 BPF_STRUCT_OPS(gedf_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_SELECT_CID, aa.jlfp.base.cgroup_id);

  // bpf_printk("[INFO] [GEDF] [SELECT_CID] cgroup=%d pid=%d comm=%s prev_cid=%d wake_flags=%llu", cgroup_id, p->pid, p->comm, prev_cid, wake_flags);

  struct latency_ctx lctx;
  lstat_start(&lctx);
  check_completion(p);
  jlfp_pick_cid(&aa.jlfp, p, (u32)prev_cid, SCX_ENQ_WAKEUP | wake_flags, get_task_weight(p), aa.jlfp.slice);
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].select_cid);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_SELECT_CID, aa.jlfp.base.cgroup_id);
  return prev_cid; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(gedf_enqueue, struct task_struct *p, u64 enq_flags)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_ENQUEUE, aa.jlfp.base.cgroup_id);

  // bpf_printk("[INFO] [GEDF] [ENQUEUE] cgroup=%d pid=%d comm=%s enq_flags=%llu", cgroup_id, p->pid, p->comm, enq_flags);

  SCXTP_EMIT_HOTPATH(enqueue_args, aa.jlfp.base.cgroup_id,
    e->enq_flags = enq_flags;
    e->prev_cid = scx_bpf_task_cid(p);
    e->tid = p->pid;
  );

  struct latency_ctx lctx;
  lstat_start(&lctx);

  // check for completions on wakeup
  if (enq_flags & SCX_ENQ_WAKEUP) {
    check_completion(p);
  }
  jlfp_pick_cid(&aa.jlfp, p, (u32)scx_bpf_task_cid(p), enq_flags, get_task_weight(p), aa.jlfp.slice);
  
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].enqueue);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_ENQUEUE, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_running, struct task_struct *p)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_RUNNING, aa.jlfp.base.cgroup_id);

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
      wt = WT_FROM_FIELDS(get_task_weight(p), jlfp_task_is_nmig(p), aa.jlfp.base.self_cgroup_weight, 0);
    } else {
      wt = get_jlfp_task_ctx(tctx)->weight;
    }
  }

  jlfp_running_core(&aa.jlfp, p, tctx, wt, &lctx);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_RUNNING, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_stopping, struct task_struct *p, bool runnable)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_STOPPING, aa.jlfp.base.cgroup_id);

  jlfp_stopping_core(&aa.jlfp, p, runnable);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_STOPPING, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_update_idle, s32 cid, bool idle)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_UPDATE_IDLE, aa.jlfp.base.cgroup_id);

  base_update_idle(&aa.jlfp.base, cid, idle);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_UPDATE_IDLE, aa.jlfp.base.cgroup_id);
}

// from qmap
// TODO: change to if SWITCH_PARTIAL then only allocate if SCX policy or when switches to SCX policy
// because cid-form removes enable/disable can only be done in enqueue
s32 BPF_STRUCT_OPS_SLEEPABLE(gedf_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_INIT_TASK, aa.jlfp.base.cgroup_id);

  SCXTP_EMIT(init_task_args, aa.jlfp.base.cgroup_id,
    e->tid = p->pid;
    e->fork = args->fork;
  );
  struct latency_ctx lctx;
  lstat_start(&lctx);

  // bpf_printk("[INFO] [GEDF] [INIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);

  if (unlikely(!init_jlfp_task_ctx(&aa.jlfp.base, p, args))) {
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_INIT_TASK, aa.jlfp.base.cgroup_id);
    return -ENOMEM;
  }

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_INIT_TASK, aa.jlfp.base.cgroup_id);
  return 0;
}

// from qmap
void BPF_STRUCT_OPS(gedf_exit_task, struct task_struct *p)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_EXIT_TASK, aa.jlfp.base.cgroup_id);

  SCXTP_EMIT(exit_task_args, aa.jlfp.base.cgroup_id,
    e->tid = p->pid;
  );
  
  // bpf_printk("[INFO] [GEDF] [EXIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
  struct latency_ctx lctx;
  lstat_start(&lctx);

  // prevent a reused tid from inheriting a pending completion
  u32 idx = p->pid >> 6;
  u64 mask = 1ULL << (p->pid & 63);
  u64 *flag_entry = bpf_map_lookup_elem(&job_completion_flags, &idx);
  if (likely(flag_entry)) {
    __sync_fetch_and_and(flag_entry, ~mask);
  }

  if (!base_exit_task(&aa.jlfp.base, p)) {
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_EXIT_TASK, aa.jlfp.base.cgroup_id);
    return;
  }

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].exit_task);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_EXIT_TASK, aa.jlfp.base.cgroup_id);
}

// from qmap
void BPF_STRUCT_OPS(gedf_set_cmask, struct task_struct *p, const struct scx_cmask *cmask_in)
{
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_SET_CMASK, aa.jlfp.base.cgroup_id);

  struct latency_ctx lctx;
  lstat_start(&lctx);

  task_ctx_t *tctx = base_set_cmask(p, cmask_in);
  if (unlikely(!tctx)) {
    SCXTP_EMIT_OP_EXIT(SCXTP_OP_SET_CMASK, aa.jlfp.base.cgroup_id);
    return;
  }

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.jlfp.stats[cid].set_cmask);

  SCXTP_EMIT(set_cmask, aa.jlfp.base.cgroup_id,
    e->tid = p->pid;
    e->cmask = cmask_to_u64(&tctx->cpus_allowed);
  );

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_SET_CMASK, aa.jlfp.base.cgroup_id);
}

void BPF_STRUCT_OPS(gedf_tick, struct task_struct *p) {
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_TICK, aa.jlfp.base.cgroup_id);

  // measure overhead of latency tracking
  struct latency_ctx lctx;
  u32 cid = scx_bpf_this_cid();
  lstat_start(&lctx);
  lstat_record(&lctx, &aa.jlfp.stats[cid].no_op);

  SCXTP_EMIT_OP_EXIT(SCXTP_OP_TICK, aa.jlfp.base.cgroup_id);
}

// check for job completion on sched_yield
// handles case where task wants to do maximal early releasing
bool BPF_STRUCT_OPS(gedf_yield, struct task_struct *from, struct task_struct *to) {
  SCXTP_EMIT_OP_ENTRY(SCXTP_OP_YIELD, aa.jlfp.base.cgroup_id);

  if (!to) check_completion(from);

  scx_bpf_task_set_slice(from, 0);
  SCXTP_EMIT_OP_EXIT(SCXTP_OP_YIELD, aa.jlfp.base.cgroup_id);
  return false;
}

// based on scx_pair
// allows cid_form schedulers to detect when a cpu is used for higher priority work
// this replaces ops.cpu_acquire and ops.cpu_release which are deprecated in sched_ext_ops and unusable in cid_form schedulers
SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
  jlfp_sched_switch_core(&aa.jlfp, preempt, prev, next, prev_state);
  return 0;
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
  .yield              = (void *)gedf_yield,
  .tick               = (void *)gedf_tick
);
