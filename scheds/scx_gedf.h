#ifndef __SCX_GEDF_H
#define __SCX_GEDF_H

#include "scx_jlfp.h"

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
