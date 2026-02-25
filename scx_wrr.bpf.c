#include <scx/common.bpf.h>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include <stdint.h>

// weighted round robin hierarchical scheduler
// cannot directly handle tasks, only allocate runtime to subschedulers
// subscheduler requirements:
// - pause its time on cpu_release and resume it on sub_dispatch
// - limit size of cpu local dsqs to 1
// TODO: figure out cpu affinity

const bool cgroup_msgs = true;

#define wrr_DSQ 1
#define MAX_SUB_SCHEDS		64
#define DEFAULT_WEIGHT 1000

UEI_DEFINE(uei);

struct sub_params {
	u64 cgrp_id;
  u64 weight;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SUB_SCHEDS);
	__type(key, u32);
	__type(value, struct sub_params);
} subs SEC(".maps");
struct bpf_spin_lock subs_write_lock;
__u64 next_sub; // atomically incremented

s32 BPF_STRUCT_OPS_SLEEPABLE(wrr_init)
{
	return 0;
}

// looks for cgroup in sub
// returns true iff exists
// if exists, res := address of it in subs
// otherwise, res := address of the first free location (NULL if no free location)
// special case if cgrp_id is 0: returns true and first free location if exists, false if no more free locations
// does not handle locking
// assigns index of res to res_idx if not null (if res = NULL, assigns it MAX_SUB_SCHEDS)
bool sub_lookup(u64 cgrp_id, struct sub_params **res, u32 *res_idx) {
	struct sub_params *first_free = NULL;
	u32 first_free_idx = MAX_SUB_SCHEDS;
	for (u32 idx = 0; idx < MAX_SUB_SCHEDS; ++idx) {
		struct sub_params *sp = (struct sub_params *)bpf_map_lookup_elem(&subs, &idx);
		if (!sp) continue; // to make compiler happy, should not occur
		if (sp->cgrp_id == cgrp_id) {
			*res = sp;
			if (res_idx) *res_idx = idx;
			return true;
		}
		if (sp->cgrp_id == 0 && !first_free) first_free = sp;
	}
	*res = first_free;
	if (res_idx) *res_idx = first_free_idx;
	return false;
}

s32 BPF_STRUCT_OPS(wrr_sub_attach, struct scx_sub_attach_args *args)
{
	u64 cgrp_id = args->ops->sub_cgroup_id;
	struct sub_params *sp;
	
	bpf_spin_lock(&subs_write_lock);

	if (sub_lookup(cgrp_id, &sp)) {
 		bpf_printk("[scx_wrr.bpf.c]: sub_attach %llu already attached", cgrp_id);
		bpf_spin_unlock(&subs_write_lock);
		return -EEXIST;
	}
	if (!sp) {
		bpf_printk("[scx_wrr.bpf.c]: sub_attach %llu attaching sub would exceed MAX_SUB_SCHEDS", cgrp_id);
		bpf_spin_unlock(&subs_write_lock);
		return -ENOMEM;
	}

	sp->cgrp_id = cgrp_id;
	sp->weight = DEFAULT_WEIGHT;

	bpf_spin_unlock(&subs_write_lock);

  return 0;
}

void BPF_STRUCT_OPS(wrr_sub_detach, struct scx_sub_detach_args *args)
{
  u64 cgrp_id = args->ops->sub_cgroup_id;
	struct sub_params *sp;

	bpf_spin_lock(&subs_write_lock);
	if (!sub_lookup(cgrp_id, &sp) || !sp) {
 		bpf_printk("[scx_wrr.bpf.c]: sub_detach %llu not attached", cgrp_id);
		bpf_spin_unlock(&subs_write_lock);
		return;
	}

	sp->weight = 0;
	sp->cgrp_id = 0;

	bpf_spin_unlock(&subs_write_lock);
}

void BPF_STRUCT_OPS(qmap_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
  u64 cgrp_id = cgrp->kn->sub_cgroup_id;

	bpf_spin_lock(&subs_write_lock);
	if (!sub_lookup(cgrp_id, &sp) || !sp) {
 		bpf_printk("[scx_wrr.bpf.c]: cgroup_set_weight %llu not attached", cgrp_id);
		bpf_spin_unlock(&subs_write_lock);
		return;
	}
	
	sp->weight = weight;

	bpf_spin_unlock(&subs_write_lock);
}


SCX_OPS_DEFINE(wrr_ops,
	// setup
	.name			= "wrr",
	.init			= (void *)wrr_init,
	.exit			= (void *)wrr_exit,
	.flags			= SCX_OPS_SWITCH_PARTIAL,
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
	.enable			= (void *)wrr_enable,
	.disable		= (void *)wrr_disable,
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