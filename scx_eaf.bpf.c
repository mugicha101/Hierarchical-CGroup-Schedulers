#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u64 cgroup_id = 0;
u64 dsq_id = 0;

// very simple earliest arrival first scheduler
// does not use SCX_DSQ_GLOBAL to allow hierarchical scheduling

s32 BPF_STRUCT_OPS_SLEEPABLE(eaf_init)
{
	bpf_printk("[INFO] [EAF] [INIT] cgroup=%d", cgroup_id);
	dsq_id = cgroup_id;
	s32 err = scx_bpf_create_dsq(dsq_id, -1);
	if (err < 0) {
		bpf_printk("[INFO] [EAF] [INIT] [DEBUG] cgroup=%d failed to init dsq err=%d", cgroup_id, err);
	}
	return err;
	return 0;
}

void BPF_STRUCT_OPS(eaf_exit)
{
	bpf_printk("[INFO] [EAF] [EXIT] cgroup=%d Exiting SCX EAF Scheduler\n", cgroup_id);
}

void BPF_STRUCT_OPS(eaf_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("[INFO] [EAF] [DISPATCH] cgroup=%d cpu=%d", cgroup_id, cpu);
	struct task_struct *p;
	scx_bpf_dsq_move_to_local(dsq_id);
}

s32 BPF_STRUCT_OPS(eaf_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

void BPF_STRUCT_OPS(eaf_enqueue, struct task_struct *p, u64 enq_flags)
{
	bpf_printk("[INFO] [EAF] [ENQUEUE] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
	scx_bpf_dsq_insert(p, dsq_id, 1 * 1000000000ull, enq_flags);
}

void BPF_STRUCT_OPS(eaf_dequeue, struct task_struct *p, u64 deq_flags)
{
	bpf_printk("[INFO] [EAF] [DEQUEUE] cgroup=%d pid=%d comm=%s", cgroup_id, p->pid, p->comm);
}

void BPF_STRUCT_OPS(eaf_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{

}

void BPF_STRUCT_OPS(eaf_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	
}

void BPF_STRUCT_OPS(eaf_running, struct task_struct *p)
{
	bpf_printk("[INFO] [EAF] [RUNNING] cgroup=%d cpu=%d pid=%d comm=%s", cgroup_id, bpf_get_smp_processor_id(), p->pid, p->comm);
}

void BPF_STRUCT_OPS(eaf_stopping, struct task_struct *p, bool runnable)
{
	bpf_printk("[INFO] [EAF] [STOPPING] cgroup=%d cpu=%d pid=%d comm=%s runnable=%d", cgroup_id, bpf_get_smp_processor_id(), p->pid, p->comm, runnable);
}

void BPF_STRUCT_OPS(eaf_runnable, struct task_struct *p, u64 enq_flags)
{

}

void BPF_STRUCT_OPS(eaf_quiescent, struct task_struct *p, u64 deq_flags)
{

}

s32 BPF_STRUCT_OPS(eaf_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	bpf_printk("[INFO] [EAF] [INIT_TASK] pid=%d comm=%s\n", p->pid, p->comm);
	return 0;
}

void BPF_STRUCT_OPS(eaf_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	bpf_printk("[INFO] [EAF] [EXIT_TASK] pid=%d comm=%s\n", p->pid, p->comm);
}

void BPF_STRUCT_OPS(eaf_cgroup_move, struct task_struct *p, 
                    struct cgroup *from, struct cgroup *to)
{
    u64 to_id = BPF_CORE_READ(to, kn, id);

    if (to_id == cgroup_id) {
        bpf_printk("[INFO] [EAF] [CGROUP_MOVE] Task %d MOVED INTO sub-scheduler cgroup %llu\n", 
                   p->pid, cgroup_id);
    } else {
        bpf_printk("[INFO] [EAF] [CGROUP_MOVE] Task %d MOVED OUT OF sub-scheduler cgroup\n", p->pid);
    }
}

// ops

SCX_OPS_DEFINE(eaf_ops,
	// setup
	.name			= "eaf",
	.init			= (void *)eaf_init,
	.exit			= (void *)eaf_exit,

	// flags:
	// SCX_OPS_SWITCH_PARTIAL: does not assign tasks to sched_ext by default
	// SCX_OPS_ENQ_LAST: if no work on subscheduler, enqueues current running task rather than continuing it and calls dispatch again
	.flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	// .dump			= (void *)eaf_dump,

	.dispatch		= (void *)eaf_dispatch,

	// task scheduling (should not be called)
	.select_cpu		= (void *)eaf_select_cpu,
	.enqueue		= (void *)eaf_enqueue,
	.dequeue		= (void *)eaf_dequeue,
	.cpu_acquire	= (void *)eaf_cpu_acquire,
	.cpu_release	= (void *)eaf_cpu_release,
	.running		= (void *)eaf_running,
	.stopping		= (void *)eaf_stopping,
	.runnable		= (void *)eaf_runnable,
	.quiescent		= (void *)eaf_quiescent,
	.init_task		= (void *)eaf_init_task,
	.exit_task		= (void *)eaf_exit_task,
	.cgroup_move = (void *)eaf_cgroup_move
	// .enable			= (void *)eaf_enable,
	// .disable		= (void *)eaf_disable,
	// .dump_task		= (void *)eaf_dump_task,
);