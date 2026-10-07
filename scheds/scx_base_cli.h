#ifndef __SCX_BASE_CLI_H
#define __SCX_BASE_CLI_H

#ifdef __BPF__
#error "This file must not be compiled for BPF"
#endif

#ifndef __SCX_BASE_H
#error "This file must be included from scx_base.h"
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static inline uint32_t parse_u32(const char *str, bool *err) {
  char *endptr;
  *err = true;
  if (!str || str[0] < '0' || str[0] > '9')
    return 0;
  errno = 0;
  unsigned long value = strtoul(str, &endptr, 10);
  if (errno || *endptr != '\0' || value > UINT32_MAX)
    return 0;
  *err = false;
  return (uint32_t)value;
}

void write_stat(FILE *fd, struct latency_stat *lstat, const char *name, bool last) {
	fprintf(fd, "\"%s\":{", name);
	fprintf(fd, "\"n\":%lu,", lstat->n);
	fprintf(fd, "\"max\":%lu,", lstat->max);
	fprintf(fd, "\"sum\":");

	// since u128 not supported by fprintf, print each char individually
	char u128_str[40] = {};
	size_t di = 0;
	u128 t = lstat->sum;
	while (t) {
		u128_str[di++] = t % 10;
		t /= 10;
	}
	di += di == 0;
	while (di > 0) {
		fprintf(fd, "%d", u128_str[--di]);
	}
	fprintf(fd, "}");
	if (!last) fprintf(fd, ",");
}

struct base_cli_opts {
	bool verbose;
	uint32_t max_shard_size;
	uint32_t max_tasks;
	const char *cgroup_path;
	uint32_t cgroup_id;
	bool trace;
	const char *stats_path;
};

static inline void base_init_opts(struct base_cli_opts *opts) {
  opts->verbose = false;
  opts->cgroup_path = NULL;
  opts->cgroup_id = 0;
  opts->trace = false;
  opts->stats_path = NULL;
  opts->max_shard_size = 8;
  opts->max_tasks = 16384;
}

// returns 1 if invalid, 0 if valid, -1 if unknown
static inline int base_parse_opt(struct base_cli_opts *opts, int opt, const char *arg) {
  bool err;
  switch (opt) {
    case 'v':
      opts->verbose = 1;
      return 0;
    case 'S':
      opts->max_shard_size = parse_u32(arg, &err);
      return err || opts->max_shard_size == 0 || opts->max_shard_size > BASE_MAX_CPUS;
    case 'T':
      opts->max_tasks = parse_u32(arg, &err);
      return err || opts->max_tasks == 0;
    case 'c':
      opts->cgroup_path = arg;
      struct stat st;
      if (stat(arg, &st) < 0) {
        fprintf(stderr, "Error: failed to stat cgroup %s\n", arg);
        return 1;
      }
      opts->cgroup_id = st.st_ino;
      return 0;
    case 't':
      opts->trace = true;
      return 0;
    case 's':
      opts->stats_path = arg;
      return 0;
    default:
      return -1;
  }
}

#define base_report_tracing(opts, skel) \
  base_report_tracing_impl((opts), \
    (skel)->rodata->scxtp_lowfreq_compiled, \
    (skel)->rodata->scxtp_hotpath_compiled)

static inline void base_report_tracing_impl(const struct base_cli_opts *opts,
                                          bool lowfreq_compiled, bool hotpath_compiled) {
  if (!opts->trace) {
    fprintf(stdout, "Tracing Disabled\n");
    return;
  }

  bool module_loaded = access("/sys/module/scxtp", F_OK) == 0;

  if (module_loaded && lowfreq_compiled) {
    fprintf(stdout, "Tracing Enabled: %s events\n", hotpath_compiled ? "all" : "non-hotpath");
  } else {
    fprintf(stdout, "Tracing Disabled: -t/--trace specified but scxtp kernel module not loaded or compiled without tracing\n");
  }

  fprintf(stdout, "Tracing Compilation Flags: SCXTP_TRACING=%d, SCXTP_HOTPATH_TRACING=%d\n",
          lowfreq_compiled, hotpath_compiled);

  fprintf(stdout, "Tracing Loadtime Flags: -t/--trace=%d, scxtp kernel module loaded=%d\n",
          opts->trace, module_loaded);
}

static inline void base_apply_opts(struct base_cli_opts *opts, struct base_arena *a) {
	a->cgroup_id = opts->cgroup_id;
	a->max_tasks = opts->max_tasks;
}

#endif
