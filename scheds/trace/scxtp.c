// fixed-size scheduler tracepoints exposed to BPF struct_ops programs
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>

#define CREATE_TRACE_POINTS
#include "events.h"

__bpf_kfunc_start_defs();
SCXTP_EVENT_LIST(SCXTP_DEFINE_KFUNC)
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(scxtp_kfunc_ids)
SCXTP_EVENT_LIST(SCXTP_KFUNC_ID)
BTF_KFUNCS_END(scxtp_kfunc_ids)

static const struct btf_kfunc_id_set scxtp_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &scxtp_kfunc_ids,
};

static int __init scxtp_init(void)
{
  return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &scxtp_kfunc_set);
}

static void __exit scxtp_exit(void)
{
}

module_init(scxtp_init);
module_exit(scxtp_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("custom sched_ext scheduler tracepoints");
