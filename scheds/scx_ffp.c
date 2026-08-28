/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
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
#include "scx_ffp.h"

#include "scx_ffp.bpf.skel.h"
#include "scx_ffp.bpf.skel.h"

#define SUB_CG_BASE "/sys/fs/cgroup/scx_ffp"

const char help_fmt[] =
"A clustered job-level fixed priority sched_ext hierarchical scheduler.\n"
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
"  -l, --search-locking       Enable shard locking in pick_cid min priority search (by default, pick_cid does not lock target shard to ensure running priorities are accurate)\n"
"  -g, --global-search        Enable Global Shard Search (by default, pick_cid only searches local shard if no idle CPU found)\n"
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

int main(int argc, char **argv)
{
	struct scx_ffp *skel;
	struct bpf_link *link;
	struct ring_buffer *rb_manager;
	struct bpf_program *syscall_prog = NULL;
	struct ffp_arena *aa = NULL;

	bool search_locking = false;
	bool global_search = false;
	uint32_t max_shard_size = 8;
	uint32_t max_tasks = 16384;

  	const char *cg_path = NULL;
	const char *sched_name = "<root>";
	const char *trace_path = NULL;
	const char *pin_path = "/sys/fs/bpf/update_weight";
	const char *stats_path = NULL;

	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:

	// parse arguments
	while ((opt = getopt(argc, argv, "c:v:t:s:h")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
    	case 'c':
			cg_path = strdup(optarg);
			sched_name = cg_path;
      		break;
		case 'l':
			search_locking = true;
			break;
		case 'g':
			global_search = true;
			break;
		case 'S':
			max_shard_size = strtoul(optarg, NULL, 10);
			break;
		case 'T':
			max_tasks = strtoul(optarg, NULL, 10);
			break;
		case 't':
			trace_path = strdup(optarg);
			break;
		case 's':
			stats_path = strdup(optarg);
			break;
		case 'h':
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
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
	skel = scx_ffp__open();
	if (!skel) {
		fprintf(stderr, "Error: failed to open skel\n");
		goto cleanup;
	}

	// attach cgroup
	if (cg_path) {
		struct stat st;
		if (stat(cg_path, &st) < 0) {
			fprintf(stderr, "Error: failed to stat cgroup %s\n", cg_path);
			goto cleanup;
		}
		skel->struct_ops.ffp_ops->sub_cgroup_id = st.st_ino;
		skel->rodata->cgroup_id = st.st_ino;
	}
	skel->struct_ops.ffp_ops->cid_shard_size = max_shard_size;
	skel->rodata->max_tasks = max_tasks;
	skel->rodata->trace_enabled = trace_path != NULL;
	skel->rodata->lockless = !search_locking;
	skel->rodata->global_search = global_search;
	
	// load scheduler
	SCX_OPS_LOAD(skel, ffp_ops, scx_ffp, uei);
	link = SCX_OPS_ATTACH(skel, ffp_ops, scx_ffp);
	if (!link) {
		fprintf(stderr, "Error: failed to attach scheduler\n");
		goto cleanup;
	}
	aa = &skel->arena->aa;

	// pin syscall program if no prior instances of it exist
	// if (access(pin_path, F_OK)) {
	// 	syscall_prog = bpf_object__find_program_by_name(skel->obj, "update_weight");
	// 	if (!syscall_prog) {
	// 		fprintf(stderr, "Error: failed to find update_weight program\n");
	// 		goto cleanup;
	// 	}
	// 	if (bpf_program__pin(syscall_prog, pin_path) < 0) {
	// 		fprintf(stderr, "Error: failed to pin update_weight program\n");
	// 		goto cleanup;
	// 	}
	// 	fprintf(stdout, "Pinned update_weight program to %s\n", pin_path);
	// }
	
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

	// sleep while running
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		#if TRACING
		int err = ring_buffer__poll(rb_manager, 100);
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		#else
		usleep(100000);
		#endif
	}

cleanup:

	if (syscall_prog) {
		bpf_program__unpin(syscall_prog, pin_path);
	}

	if (link) bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);

	if (stats_path && aa) {
		FILE *stats_fd = fopen(stats_path, "w");
		if (!stats_fd) {
			fprintf(stderr, "Error opening stats output file %s\n", stats_path);
		} else {
			// write stats as json
			fprintf(stats_fd, "[");
			for (__u32 cid = 0; cid < aa->topo.nr_cids; ++cid) {
				if (cid) fprintf(stats_fd, ",");
				fprintf(stats_fd, "{");
				struct stats_data *s = &aa->stats[cid];

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

				fprintf(stats_fd, "}");
			}
			fprintf(stats_fd, "]");
		}
	}

	if (skel) scx_ffp__destroy(skel);

	if (trace_fd && trace_path) {
		fclose(trace_fd);
	}

	fprintf(stdout, "Scheduler Detached\n");
	fflush(stdout);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
