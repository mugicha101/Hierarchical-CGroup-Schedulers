#ifndef __SCX_GEDF_H
#define __SCX_GEDF_H

#include "scx_jlfp.h"

struct task_rtp {
  // static params updated by user
  u64 period;
  u64 relative_deadline;
  bool is_periodic;
};

// per scheduler instance arena memory
struct gedf_arena {
  struct jlfp_arena jlfp;
};

#ifdef __BPF__
#include "scx_gedf.bpf.h"
#else
#include "scx_gedf_cli.h"
#endif

#endif
