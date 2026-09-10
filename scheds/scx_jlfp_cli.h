#ifndef __SCX_JLFP_CLI_H
#define __SCX_JLFP_CLI_H

#ifdef __BPF__
#error "This file must not be compiled for BPF"
#endif

#ifndef __SCX_JLFP_H
#error "This file must be included from scx_jlfp.h"
#endif

struct jlfp_cli_opts {
  struct base_cli_opts base;
	bool global_search;
};

static inline void jlfp_init_opts(struct jlfp_cli_opts *opts) {
  base_init_opts(&opts->base);
  opts->global_search = false;
}

// returns 1 if invalid, 0 if valid, -1 if unknown
static inline int jlfp_parse_opt(struct jlfp_cli_opts *opts, int opt, const char *arg) {
  int err = base_parse_opt(&opts->base, opt, arg);
  if (err != -1) return err;
  
  switch (opt) {
    case 'g':
      opts->global_search = true;
      return 0;
    default:
      return -1;
  }
}

static inline void jlfp_apply_opts(struct jlfp_cli_opts *opts, struct jlfp_arena *a) {
  base_apply_opts(&opts->base, &a->base);
  a->global_search = opts->global_search;
}

static inline void jlfp_write_cid_stats(FILE *stats_fd, struct jlfp_arena *a, uint32_t cid) {
  struct stats_data *s = &a->stats[cid];

  write_stat(stats_fd, &s->no_op, "no_op", false);
  write_stat(stats_fd, &s->pick_cid_prev, "pick_cid_prev", false);
  write_stat(stats_fd, &s->pick_cid_idle, "pick_cid_idle", false);
  write_stat(stats_fd, &s->pick_cid_search, "pick_cid_search", false);
  write_stat(stats_fd, &s->task_dispatch, "task_dispatch", false);
  write_stat(stats_fd, &s->sub_dispatch, "sub_dispatch", false);
  write_stat(stats_fd, &s->dispatch, "dispatch", false);
  write_stat(stats_fd, &s->sync_porder_update, "sync_porder_update", false);
  write_stat(stats_fd, &s->sync_porder_fail, "sync_porder_fail", false);
  write_stat(stats_fd, &s->sync_porder_cached, "sync_porder_cached", false);
  write_stat(stats_fd, &s->init_task, "init_task", false);
  write_stat(stats_fd, &s->exit_task, "exit_task", false);
  write_stat(stats_fd, &s->select_cid, "select_cid", false);
  write_stat(stats_fd, &s->enqueue, "enqueue", false);
  write_stat(stats_fd, &s->sub_attach, "sub_attach", false);
  write_stat(stats_fd, &s->sub_detach, "sub_detach", false);
  write_stat(stats_fd, &s->cpuctl_weight_update, "cpuctl_weight_update", false);
  write_stat(stats_fd, &s->set_cmask, "set_cmask", false);
  write_stat(stats_fd, &s->running, "running", false);
  write_stat(stats_fd, &s->stopping, "stopping", true);
}

#endif
