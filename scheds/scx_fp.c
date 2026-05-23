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

struct seqlock_global {
	__u64 gen_fin;
	__u64 gen_beg;
};

struct seqlock_local {
	__u64 gen;
};

#include "scx_fp.bpf.skel.h"
#include "scx_fp.bpf.skel.h"

#define SUB_CG_BASE "/sys/fs/cgroup/scx_fp"

const char help_fmt[] =
"A fixed priority sched_ext hierarchical scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-v] [-c CGROUP_PATH]] [-t TRACE_PATH]\n"
"\n"
"  -v              Print libbpf debug messages\n"
"  -c CGROUP_PATH  Attach the scheduler to an existing cgroup (attaches as root otherwise)\n"
"  -t TRACE_PATH   Specify the output file to write the trace to (trace output ignored if not provided)\n"
"  -h              Display this help and exit\n";

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
	struct scx_fp *skel;
	struct bpf_link *link;
	struct ring_buffer *rb_manager;
	struct bpf_program *syscall_prog = NULL;

  const char *cg_path = NULL;
	const char *sched_name = "<root>";
	const char *trace_path = NULL;
	const char *pin_path = "/sys/fs/bpf/update_weight";

	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:

	// parse arguments
	while ((opt = getopt(argc, argv, "c:vt:h")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
    case 'c':
			cg_path = strdup(optarg);
			sched_name = cg_path;
      break;
		case 't':
			trace_path = strdup(optarg);
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
	skel = scx_fp__open();
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
		skel->struct_ops.fp_ops->sub_cgroup_id = st.st_ino;
		skel->rodata->cgroup_id = st.st_ino;
	}
	skel->rodata->trace_enabled = trace_path != NULL;

	// load scheduler
	SCX_OPS_LOAD(skel, fp_ops, scx_fp, uei);
	link = SCX_OPS_ATTACH(skel, fp_ops, scx_fp);
	if (!link) {
		fprintf(stderr, "Error: failed to attach scheduler\n");
		goto cleanup;
	}

	// pin syscall program if no prior instances of it exist
	if (access(pin_path, F_OK)) {
		syscall_prog = bpf_object__find_program_by_name(skel->obj, "update_weight");
		if (!syscall_prog) {
			fprintf(stderr, "Error: failed to find update_weight program\n");
			goto cleanup;
		}
		if (bpf_program__pin(syscall_prog, pin_path) < 0) {
			fprintf(stderr, "Error: failed to pin update_weight program\n");
			goto cleanup;
		}
		fprintf(stdout, "Pinned update_weight program to %s\n", pin_path);
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
	if (skel) scx_fp__destroy(skel);

	if (trace_fd && trace_path) {
		fclose(trace_fd);
	}

	fprintf(stdout, "Scheduler Detached\n");
	fflush(stdout);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
