#include <scx/common.bpf.h>

#include "bpf/bpf_helpers.h"
#include "scx/enums.bpf.h"
#include "diagnostics.h"
#include "scx_jlfp.h"

char _license[] SEC("license") = "GPL";

// concrete job-level fixed-priority scheduler using the shared JLFP engine
// task weights come from the pinned task_weights map under /sys/fs/bpf/scx
// larger task weights rank ahead within the tuple's task-weight field
// select_cid, enqueue, and dispatch reconsidering runnable prev read the map
// changing a map entry does not reorder queued tasks or preempt running tasks by itself

UEI_DEFINE(uei);

struct jlfp_arena __arena_global aa;
bool jlfp_sched_switch_ready;

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
  SCXTP_EMIT_OP_ENTRY(init, aa.base.cgroup_id);

  s32 err = jlfp_init_core(&aa);
  if (!err) {
    smp_wmb();
    WRITE_ONCE(jlfp_sched_switch_ready, true);
  }
  SCXTP_EMIT_OP_EXIT(init, aa.base.cgroup_id);
  return err;
}

void BPF_STRUCT_OPS(jlfp_exit, struct scx_exit_info *ei)
{
  SCXTP_EMIT_OP_ENTRY(exit, aa.base.cgroup_id);

  WRITE_ONCE(jlfp_sched_switch_ready, false);
  SCXTP_EMIT(exit, aa.base.cgroup_id,
    e->cgrp_id = aa.base.cgroup_id;
  );
  bpf_printk("[INFO] [JLFP] [EXIT] cgroup=%llu\n", aa.base.cgroup_id);
  UEI_RECORD(uei, ei);

  SCXTP_EMIT_OP_EXIT(exit, aa.base.cgroup_id);
}

s32 BPF_STRUCT_OPS(jlfp_sub_attach, struct scx_sub_attach_args *args)
{
  SCXTP_EMIT_OP_ENTRY(sub_attach, aa.base.cgroup_id);

  s32 err = jlfp_sub_attach_core(&aa, args);
  SCXTP_EMIT_OP_EXIT(sub_attach, aa.base.cgroup_id);
  return err;
}

void BPF_STRUCT_OPS(jlfp_sub_detach, struct scx_sub_detach_args *args)
{
  SCXTP_EMIT_OP_ENTRY(sub_detach, aa.base.cgroup_id);

  jlfp_sub_detach_core(&aa, args);

  SCXTP_EMIT_OP_EXIT(sub_detach, aa.base.cgroup_id);
}

void BPF_STRUCT_OPS(jlfp_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
  SCXTP_EMIT_OP_ENTRY(cgroup_set_weight, aa.base.cgroup_id);

  jlfp_cpuctl_set_weight_core(&aa, cgrp, weight);

  SCXTP_EMIT_OP_EXIT(cgroup_set_weight, aa.base.cgroup_id);
}

// configured weight for selection, enqueue, and reconsidering runnable prev
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
  SCXTP_EMIT_OP_ENTRY(dispatch, aa.base.cgroup_id);

  struct jlfp_arena __arena *a = &aa;
  u64 prev_weight = 0;
  if (prev && (BPF_CORE_READ(prev, scx.flags) & SCX_TASK_QUEUED))
    prev_weight = get_task_weight(prev);

  if (unlikely(cid >= NR_CPUS)) {
    SCXTP_EMIT_OP_EXIT(dispatch, aa.base.cgroup_id);
    return; // for testing limited CPUs
  }

  // bpf_printk("[INFO] [JLFP] [DISPATCH] dispatching on cpu %u", cpu);

  struct latency_ctx lctx;
  lstat_start(&lctx);

  cid = cid & (NR_CPUS - 1); // for verifier

  // dispatch task
  u64 tid = jlfp_try_task_dispatch(a, cid, prev, a->slice, prev_weight);
  if (tid) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    SCXTP_EMIT_OP_EXIT(dispatch, aa.base.cgroup_id);
    return;
  }

  // dispatch cgroups if no tasks
  if (jlfp_try_sub_dispatch(a, cid)) {
    lstat_record(&lctx, &a->stats[cid].dispatch);
    SCXTP_EMIT_OP_EXIT(dispatch, aa.base.cgroup_id);
    return;
  }

  lstat_record(&lctx, &a->stats[cid].dispatch);

  SCXTP_EMIT_OP_EXIT(dispatch, aa.base.cgroup_id);
}

s32 BPF_STRUCT_OPS(jlfp_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
  SCXTP_EMIT_OP_ENTRY(select_cpu, aa.base.cgroup_id);

  // bpf_printk("[INFO] [JLFP] [SELECT_CID] cgroup=%d pid=%d comm=%s prev_cid=%d wake_flags=%llu", cgroup_id, p->pid, p->comm, prev_cid, wake_flags);

  struct latency_ctx lctx;
  lstat_start(&lctx);
  jlfp_pick_cid(&aa, p, (u32)prev_cid, SCX_ENQ_WAKEUP | wake_flags, get_task_weight(p), aa.slice);
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].select_cid);

  SCXTP_EMIT_OP_EXIT(select_cpu, aa.base.cgroup_id);
  return prev_cid; // should be ignored since enqueue shouldn't run
}

void BPF_STRUCT_OPS(jlfp_enqueue, struct task_struct *p, u64 enq_flags)
{
  SCXTP_EMIT_OP_ENTRY(enqueue, aa.base.cgroup_id);

  // bpf_printk("[INFO] [JLFP] [ENQUEUE] cgroup=%d pid=%d comm=%s enq_flags=%llu", cgroup_id, p->pid, p->comm, enq_flags);

  SCXTP_EMIT_HOTPATH(enqueue_args, aa.base.cgroup_id,
    e->enq_flags = enq_flags;
    e->prev_cid = scx_bpf_task_cid(p);
    e->tid = p->pid;
  );

  struct latency_ctx lctx;
  lstat_start(&lctx);

  jlfp_pick_cid(&aa, p, (u32)scx_bpf_task_cid(p), enq_flags, get_task_weight(p), aa.slice);
  
  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].enqueue);

  SCXTP_EMIT_OP_EXIT(enqueue, aa.base.cgroup_id);
}

void BPF_STRUCT_OPS(jlfp_running, struct task_struct *p)
{
  SCXTP_EMIT_OP_ENTRY(running, aa.base.cgroup_id);

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
      wt = WT_FROM_FIELDS(get_task_weight(p), jlfp_task_is_nmig(p), aa.base.self_cgroup_weight, 0);
    } else {
      wt = get_jlfp_task_ctx(tctx)->weight;
    }
  }

  jlfp_running_core(&aa, p, tctx, wt, &lctx);

  SCXTP_EMIT_OP_EXIT(running, aa.base.cgroup_id);
}

void BPF_STRUCT_OPS(jlfp_stopping, struct task_struct *p, bool runnable)
{
  SCXTP_EMIT_OP_ENTRY(stopping, aa.base.cgroup_id);

  jlfp_stopping_core(&aa, p, runnable);

  SCXTP_EMIT_OP_EXIT(stopping, aa.base.cgroup_id);
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

//   SCXTP_EMIT(set_task_weight, aa.base.cgroup_id,
//     e->tid = pid;
//     e->weight = weight;
//   );

//   // kick cid

//   return 0;
// }

void BPF_STRUCT_OPS(jlfp_update_idle, s32 cid, bool idle)
{
  SCXTP_EMIT_OP_ENTRY(update_idle, aa.base.cgroup_id);

  base_update_idle(&aa.base, cid, idle);

  SCXTP_EMIT_OP_EXIT(update_idle, aa.base.cgroup_id);
}

// from qmap
// TODO: change to if SWITCH_PARTIAL then only allocate if SCX policy or when switches to SCX policy
// because cid-form removes enable/disable can only be done in enqueue
s32 BPF_STRUCT_OPS_SLEEPABLE(jlfp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  SCXTP_EMIT_OP_ENTRY(init_task, aa.base.cgroup_id);

  SCXTP_EMIT(init_task_args, aa.base.cgroup_id,
    e->tid = p->pid;
    e->fork = args->fork;
  );
  struct latency_ctx lctx;
  lstat_start(&lctx);

  // bpf_printk("[INFO] [JLFP] [INIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);

  if (unlikely(!init_jlfp_task_ctx(&aa.base, p, args))) {
    SCXTP_EMIT_OP_EXIT(init_task, aa.base.cgroup_id);
    return -ENOMEM;
  }

  SCXTP_EMIT_OP_EXIT(init_task, aa.base.cgroup_id);
  return 0;
}

// from qmap
void BPF_STRUCT_OPS(jlfp_exit_task, struct task_struct *p)
{
  SCXTP_EMIT_OP_ENTRY(exit_task, aa.base.cgroup_id);

  SCXTP_EMIT(exit_task_args, aa.base.cgroup_id,
    e->tid = p->pid;
  );
  
  // bpf_printk("[INFO] [JLFP] [EXIT_TASK] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
  struct latency_ctx lctx;
  lstat_start(&lctx);

  if (!base_exit_task(&aa.base, p)) {
    SCXTP_EMIT_OP_EXIT(exit_task, aa.base.cgroup_id);
    return;
  }

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].exit_task);

  SCXTP_EMIT_OP_EXIT(exit_task, aa.base.cgroup_id);
}

// from qmap
void BPF_STRUCT_OPS(jlfp_set_cmask, struct task_struct *p, const struct scx_cmask *cmask_in)
{
  SCXTP_EMIT_OP_ENTRY(set_cpumask, aa.base.cgroup_id);

  struct latency_ctx lctx;
  lstat_start(&lctx);

  task_ctx_t *tctx = base_set_cmask(p, cmask_in);
  if (unlikely(!tctx)) {
    SCXTP_EMIT_OP_EXIT(set_cpumask, aa.base.cgroup_id);
    return;
  }

  u32 cid = scx_bpf_this_cid();
  lstat_record(&lctx, &aa.stats[cid].set_cmask);

  SCXTP_EMIT(set_cmask, aa.base.cgroup_id,
    e->tid = p->pid;
    e->cmask = cmask_to_u64(&tctx->cpus_allowed);
  );

  SCXTP_EMIT_OP_EXIT(set_cpumask, aa.base.cgroup_id);
}

void BPF_STRUCT_OPS(jlfp_tick, struct task_struct *p) {
  SCXTP_EMIT_OP_ENTRY(tick, aa.base.cgroup_id);

  // measure overhead of latency tracking
  struct latency_ctx lctx;
  u32 cid = scx_bpf_this_cid();
  lstat_start(&lctx);
  lstat_record(&lctx, &aa.stats[cid].no_op);

  SCXTP_EMIT_OP_EXIT(tick, aa.base.cgroup_id);
}

// based on scx_pair
// allows cid_form schedulers to detect when a cpu is used for higher priority work
// this replaces ops.cpu_acquire and ops.cpu_release which are deprecated in sched_ext_ops and unusable in cid_form schedulers
SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
  jlfp_sched_switch_core(&aa, preempt, prev, next, prev_state);
  return 0;
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
