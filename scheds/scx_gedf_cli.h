#ifndef __SCX_GEDF_CLI_H
#define __SCX_GEDF_CLI_H

#ifdef __BPF__
#error "This file must not be compiled for BPF"
#endif

#ifndef __SCX_GEDF_H
#error "This file must be included from scx_gedf.h"
#endif

struct gedf_cli_opts {
  struct jlfp_cli_opts jlfp;
};

static inline void gedf_init_opts(struct gedf_cli_opts *opts) {
  jlfp_init_opts(&opts->jlfp);
}

// returns 1 if invalid, 0 if valid, -1 if unknown
static inline int gedf_parse_opt(struct gedf_cli_opts *opts, int opt, const char *arg) {
  return jlfp_parse_opt(&opts->jlfp, opt, arg);
}

static inline void gedf_apply_opts(struct gedf_cli_opts *opts, struct gedf_arena *a) {
  jlfp_apply_opts(&opts->jlfp, &a->jlfp);
}

static inline void gedf_write_cid_stats(FILE *stats_fd, struct gedf_arena *a, uint32_t cid) {
  jlfp_write_cid_stats(stats_fd, &a->jlfp, cid);
}

#endif
