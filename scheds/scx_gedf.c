/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <time.h>
#include "scx_gedf.h"

#include "scx_gedf.bpf.skel.h"

#define SUB_CG_BASE "/sys/fs/cgroup/scx_gedf"

const char help_fmt[] =
"A global earliest deadline first sched_ext hierarchical scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [OPTIONS]\n"
"\n"
"General Options:\n"
"  -v, --verbose              Print libbpf debug messages\n"
"  -h, --help                 Display this help and exit\n"
"\n"
"Scheduler Configuration:\n"
"  -c, --cgroup PATH          Attach the scheduler to an existing cgroup located at PATH (default: /sys/fs/cgroup/ i.e. the root cgroup)\n"
"  -g, --global-search        Enable Global Shard Search (by default, jlfp_pick_cid only searches local shard if no idle CPU found)\n"
"  -S, --max-shard-size N         Sets the maximum shard size (i.e. cluster size) to N (default: 8, however each shard must be within a single LLC)\n"
"  -T, --max-tasks N          Sets the maximum number of tasks supported by the scheduler to N (default: 16384, must be at least the tasks in the scheduler's cgroup including non-scx tasks)"
"\n"
"Diagnostics:\n"
"  -t, --trace PATH           Output trace data from the scheduler to PATH continuously during runtime (trace output ignored if not provided)\n"
"  -s, --stats PATH           Output JSON-formatted latency stats to PATH when scheduler exits (discarded if not provided)\n"
;

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
  exit_req = 1;
}

int main(int argc, char **argv)
{
  struct scx_gedf *skel = NULL;
  struct bpf_link *link = NULL;
  #if TRACING
  struct ring_buffer *rb_manager = NULL;
  #endif
  struct gedf_arena *aa = NULL;
  
  struct gedf_cli_opts cli_opts;
  gedf_init_opts(&cli_opts);

  static const struct option long_opts[] = {
    { "cgroup", required_argument, NULL, 'c' },
    { "verbose", no_argument, NULL, 'v' },
    { "global-search", no_argument, NULL, 'g' },
    { "max-shard-size", required_argument, NULL, 'S' },
    { "max-tasks", required_argument, NULL, 'T' },
    { "trace", required_argument, NULL, 't' },
    { "stats", required_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 },
  };
  int opt;
  int ret;
  __u64 ecode;

  libbpf_set_print(libbpf_print_fn);
  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigint_handler);

  // parse arguments
  while ((opt = getopt_long(argc, argv, "c:vgS:T:t:s:h", long_opts, NULL)) != -1) {
    int err = gedf_parse_opt(&cli_opts, opt, optarg);
    if (err == 0) continue;

    if (err == 1) {
      fprintf(stderr, "Invalid value for -%c: %s\n", opt, optarg);
      return 1;
    }
    fprintf(stderr, help_fmt, basename(argv[0]));
    return opt != 'h';
  }
  if (optind < argc) {
    fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
    return 1;
  }
  verbose = cli_opts.jlfp.base.verbose;
  const char *cg_path = cli_opts.jlfp.base.cgroup_path;
  const char *sched_name = cg_path ? cg_path : "<root>";
  const char *trace_path = cli_opts.jlfp.base.trace_path;
  const char *stats_path = cli_opts.jlfp.base.stats_path;
restart:
  // reset resources before each scheduler instance
  skel = NULL;
  link = NULL;
  aa = NULL;
  #if TRACING
  rb_manager = NULL;
  #endif
  ecode = 0;
  ret = 1;

  fprintf(stdout, "Initializing %s\n", sched_name);

  // open trace fd
  trace_fd = NULL;
  start_time = 0;
  if (trace_path) {
    trace_fd = fopen(trace_path, "w");
    if (!trace_fd) {
      fprintf(stderr, "Error: failed to open trace file %s\n", trace_path);
      goto cleanup;
    }
    fprintf(stdout, "Tracing enabled, writing to %s\n", trace_path);
  } else {
    fprintf(stdout, "Tracing disabled\n");
  }

  // open skel
  LIBBPF_OPTS(bpf_object_open_opts, opts,
    .pin_root_path = "/sys/fs/bpf/scx",
  );
  skel = scx_gedf__open_opts(&opts);
  if (!skel) {
    fprintf(stderr, "Error: failed to open skel\n");
    goto cleanup;
  }

  // set struct_ops fields
  if (cli_opts.jlfp.base.cgroup_id) {
    skel->struct_ops.jlfp_ops->sub_cgroup_id = cli_opts.jlfp.base.cgroup_id;
  }
  skel->struct_ops.jlfp_ops->cid_shard_size = cli_opts.jlfp.base.max_shard_size;
  skel->rodata->trace_enabled = trace_path != NULL;
  
  // load scheduler
  SCX_OPS_LOAD(skel, jlfp_ops, scx_gedf, uei);
  aa = &skel->arena->aa;
  gedf_apply_opts(&cli_opts, aa);
  link = SCX_OPS_ATTACH(skel, jlfp_ops, scx_gedf);
  if (!link) {
    fprintf(stderr, "Error: failed to attach scheduler\n");
    goto cleanup;
  }
  
  fprintf(stdout, "Scheduler Attached\n");
  fflush(stdout);

  // setup trace buffer manager and attach trace buffer
  #if TRACING
  struct callback_ctx cb_ctx;
  int tbuff_fd = bpf_map__fd(skel->maps.trace_buff);
  snprintf(cb_ctx.sched_name, sizeof(cb_ctx.sched_name), "%s", sched_name);
  rb_manager = ring_buffer__new(tbuff_fd, handle_event, &cb_ctx, NULL);
  if (!rb_manager) {
    fprintf(stderr, "Failed to create ring buffer manager\n");
    goto cleanup;
  }
  #endif

  ret = 0;

  // sleep while running
  while (!exit_req && !UEI_EXITED(skel, uei)) {
    #if TRACING
    int err = ring_buffer__poll(rb_manager, 100);
    if (err < 0) {
      if (err != -EINTR) {
        fprintf(stderr, "Error polling ring buffer: %d\n", err);
        ret = 1;
      }
      break;
    }
    #else
    usleep(100000);
    #endif
  }

cleanup:

  if (link) {
    bpf_link__destroy(link);
    ecode = UEI_REPORT(skel, uei);
  }

  #if TRACING
  // read exit event
  if (rb_manager) {
    int err = ring_buffer__poll(rb_manager, 100);
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
    }
    ring_buffer__free(rb_manager);
  }
  #endif

  if (stats_path && aa) {
    FILE *stats_fd = fopen(stats_path, "w");
    if (!stats_fd) {
      fprintf(stderr, "Error opening stats output file %s\n", stats_path);
    } else {
      // write stats as json
      fprintf(stats_fd, "[");
      for (__u32 cid = 0; cid < aa->jlfp.base.topo.nr_cids; ++cid) {
        if (cid) fprintf(stats_fd, ",");
        fprintf(stats_fd, "{");
        fprintf(stats_fd, "\"cid\":%u,", cid);
        gedf_write_cid_stats(stats_fd, aa, cid);
        fprintf(stats_fd, "}");
      }
      fprintf(stats_fd, "]");
      fclose(stats_fd);
    }
  }

  if (skel) scx_gedf__destroy(skel);

  if (trace_fd && trace_path) {
    fclose(trace_fd);
  }

  fprintf(stdout, "Scheduler Detached\n");
  fflush(stdout);

  if (UEI_ECODE_RESTART(ecode))
    goto restart;
  return ret;
}
