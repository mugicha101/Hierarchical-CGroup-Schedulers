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
#include "trace_events.h"
#include "scx_cgss_helpers.h"

#define NSUB 6
#define TASKS_PER_SUB 4

struct seqlock_global {
	__u64 gen_fin;
	__u64 gen_beg;
};

struct seqlock_local {
	__u64 gen;
};

#include "scx_wrr.bpf.skel.h"
#include "scx_eaf.bpf.skel.h"

#define SUB_CG_BASE "/sys/fs/cgroup/scx_eaf"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
// "  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

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

int task_func(void *arg) {
	volatile unsigned long long counter = 0;
	while (1) {
		counter++;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct scx_wrr *skel;
	struct scx_eaf *sub_skels[NSUB];
	struct bpf_link *link;
	struct bpf_link *sub_links[NSUB];
	pid_t sub_tasks[NSUB * TASKS_PER_SUB];
	struct ring_buffer *rb_manager;
	struct callback_ctx cb_ctx;
	struct callback_ctx sub_cb_ctx[NSUB];

	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		// case 'f':
		// 	skel->rodata->fifo_sched = true;
		// 	break;
		case 'v':
			verbose = true;
			// skel->rodata->cgroup_msgs = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	// open trace fd
	trace_fd = fopen("trace_output.txt", "w");
	if (!trace_fd) {
		fprintf(stderr, "Error: failed to open trace file\n");
		goto cleanup;
	}
	start_time = 0;

	// create root cgroup
	char cg_path[256];
	// snprintf(cg_path, sizeof(cg_path), "%s", ROOT_CG);
	// if (create_cgroup(cg_path)) {
	// 	fprintf(stderr, "Error: failed to create cgroup %s\n", cg_path);
	// 	goto cleanup;
	// }
	// 
	// load wrr as root
	skel = scx_wrr__open();
	if (!skel) {
		fprintf(stderr, "Error: failed to open wrr\n");
		goto cleanup;
	}
	// if (prep_root(skel, cg_path) < 0) {
	// 	fprintf(stderr, "Error: failed to prep wrr\n");
	// 	goto cleanup;
	// }
	SCX_OPS_LOAD(skel, wrr_ops, scx_wrr, uei);
	link = SCX_OPS_ATTACH(skel, wrr_ops, scx_wrr);
	if (!link) {
		fprintf(stderr, "Error: failed to attach wrr\n");
		goto cleanup;
	}
	fprintf(stdout, "Root WRR Scheduler Attached\n");

	// setup trace buffer manager and attach root trace buffer
	int root_fd = bpf_map__fd(skel->maps.trace_buff);
	snprintf(cb_ctx.sched_name, sizeof(cb_ctx.sched_name), "root_wrr");
	rb_manager = ring_buffer__new(root_fd, handle_event, &cb_ctx, NULL);
	if (!rb_manager) {
		fprintf(stderr, "Failed to create ring buffer manager\n");
		goto cleanup;
	}

	// load and attach subschedulers
	for (int i = 0; i < NSUB; ++i) {
		// create cgroup
		snprintf(cg_path, sizeof(cg_path), "%s%d", SUB_CG_BASE, i);
		if (create_cgroup(cg_path)) {
			fprintf(stderr, "Error: failed to create cgroup %s\n", cg_path);
			goto cleanup;
		}

		// load and attach scheduler
		sub_skels[i] = scx_eaf__open();
		if (!sub_skels[i]) {
			fprintf(stderr, "Error: failed to open sub %d\n", i);
			goto cleanup;
		}
		struct stat st;
		if (stat(cg_path, &st) < 0) {
			fprintf(stderr, "Error: failed to stat cgroup %s\n", cg_path);
			goto cleanup;
		}
		sub_skels[i]->struct_ops.eaf_ops->sub_cgroup_id = st.st_ino;
		sub_skels[i]->rodata->cgroup_id = st.st_ino;
		SCX_OPS_LOAD(sub_skels[i], eaf_ops, scx_eaf, uei);
		sub_links[i] = SCX_OPS_ATTACH(sub_skels[i], eaf_ops, scx_eaf);
		if (!sub_links[i]) {
			fprintf(stderr, "Error: failed to attach sub %d\n", i);
			goto cleanup;
		}

		// get trace buffer
		int fd = bpf_map__fd(sub_skels[i]->maps.trace_buff);
		snprintf(sub_cb_ctx[i].sched_name, sizeof(sub_cb_ctx[i].sched_name), "sub%d_eaf", i);
		if (ring_buffer__add(rb_manager, fd, handle_event, &sub_cb_ctx[i]) < 0) {
			fprintf(stderr, "Error: failed to add ring buffer for sub %d\n", i);
			goto cleanup;
		}

		// set cgroup weight
		// note: if fails, likely need to run: echo "+cpu" | sudo tee /sys/fs/cgroup/cgroup.subtree_control
		// note: does not trigger cgroup_set_weight if does not change weight
		char w_path[256];
		FILE *fp;
		snprintf(w_path, sizeof(w_path), "%s/cpu.weight", cg_path);
		fp = fopen(w_path, "w");
		if (!fp || fprintf(fp, "%d\n", (i+1) * 25) < 0) {
			fprintf(stderr, "Error: could not write to file %s\n", w_path);
			if (fp) fclose(fp);
			goto cleanup;
		}
		fclose(fp);
		fprintf(stdout, "Subscheduler %d Attached\n", i);

		// add indefinite tasks
		usleep(1000 * 500);
		for (int j = 0; j < TASKS_PER_SUB; ++j) {
			sub_tasks[i*TASKS_PER_SUB + j] = add_task_clone3(cg_path, task_func, NULL);
			if (sub_tasks[i*TASKS_PER_SUB + j] < 0) {
				fprintf(stderr, "Error: failed to create task %d\n", i);
				goto cleanup;
			}
		}
		fprintf(stdout, "Task %d Attached\n", sub_tasks[i]);
	}

	// sleep while running
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		int err = ring_buffer__poll(rb_manager, 100);
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:

	for (int i = 0; i < NSUB; i++) {
		if (sub_links[i]) bpf_link__destroy(sub_links[i]);
		if (sub_skels[i]) scx_eaf__destroy(sub_skels[i]);
		for (int j = 0; j < TASKS_PER_SUB; j++) {
			if (sub_tasks[i * TASKS_PER_SUB + j] > 0) {
				kill(sub_tasks[i * TASKS_PER_SUB + j], SIGKILL);
			}
		}
	}

	if (link) bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	if (skel) scx_wrr__destroy(skel);

	fclose(trace_fd);

	fprintf(stdout, "WRR Scheduler Detached\n");

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
