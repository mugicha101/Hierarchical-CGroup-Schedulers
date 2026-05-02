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

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#define NSUB 2

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

int create_cgroup(const char *path) {
	if (mkdir(path, 0755) && errno != EEXIST) {
		perror("Failed to create cgroup");
		return -1;
	}
	return 0;
}

int prep_sub(struct scx_eaf *skel, const char *cg_path) {
	struct stat st;
	if (stat(cg_path, &st) < 0) {
		perror("stat cgroup");
		return -1;
	}
	skel->struct_ops.eaf_ops->sub_cgroup_id = st.st_ino;
	skel->rodata->cgroup_id = st.st_ino;

	return 0;
}

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

pid_t add_indefinite_task_clone3(const char *cg_path) {
	// when attempting to fork, switch child cgroup to the subscheduler cgroup, and wake up child, was enqueued onto parent instead of child (think this happens on fork)
	// currently don't know of a way to move a process from the parent to a child (probably still WIP)
	// clone3 syscall works though by spawning child into that cgroup directly rather than after forking

	int cg_fd = open(cg_path, O_RDONLY | O_DIRECTORY);
	if (cg_fd < 0) {
			perror("Failed to open cgroup directory");
			exit(1);
	}
	struct clone_args args = {0};
	args.flags = CLONE_INTO_CGROUP;
	args.cgroup = cg_fd;
	pid_t pid = syscall(SYS_clone3, &args, sizeof(args));

	if (pid < 0) {
			perror("clone3 failed");
			close(cg_fd);
			return -1;
	}

	if (pid == 0) {
		// in child
		close(cg_fd);
		pid = getpid();

		// change policy to sched_ext
		struct sched_param sp = {};
    if (sched_setscheduler(0, SCHED_EXT, &sp) < 0) {
        fprintf(stderr, "task: failed to set policy to SCHED_EXT\n");
        exit(1);
    }
		fprintf(stdout, "task spawned on cgroup %s\n", cg_path);

		// spin
		volatile unsigned long long counter = 0;
    while (1) {
      counter++;
    }
		exit(0); 
	}

	// in parent
	close(cg_fd);
	return pid;
}

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

static FILE *trace_fd = NULL;
struct callback_ctx {
	char sched_name[16];
};

static u64 start_time = 0;

int handle_event(void *ctx, void *data, size_t data_sz) {
	struct callback_ctx *cb_ctx = ctx;
	struct sched_trace_event_header *header = data;
	if (start_time == 0) {
		start_time = header->timestamp;
		fprintf(trace_fd, "start time: %lu\n", start_time);
	}
	fprintf(trace_fd, "[%s] [t=%lu:cpu=%d] ", cb_ctx->sched_name, header->timestamp - start_time, header->core);
	switch (header->type) {
		case SCHED_TRACE_FUNC_START: {
			struct sched_trace_event_func_start *event = data;
			fprintf(trace_fd, "FUNC_START: %s\n", event->func_name);
		} break;
		case SCHED_TRACE_FUNC_END: {
			struct sched_trace_event_func_end *event = data;
			fprintf(trace_fd, "FUNC_END: %s %s\n", event->func_name, event->reason);
		} break;
		case SCHED_TRACE_TIMER_START: {
			struct sched_trace_event_timer_start *event = data;
			fprintf(trace_fd, "TIMER_START: timer_addr=%lx duration=%lu\n", event->timer_addr, event->duration);
		} break;
		case SCHED_TRACE_TIMER_CANCEL: {
			struct sched_trace_event_timer_cancel *event = data;
			fprintf(trace_fd, "TIMER_CANCEL: timer_addr=%lx\n", event->timer_addr);
		} break;
		case SCHED_TRACE_CGROUP_INIT_ARGS: {
			struct sched_trace_event_cgroup_init_args *event = data;
			fprintf(trace_fd, "CGROUP_INIT_ARGS: cgrp_id=%lu weight=%lu\n", event->cgrp_id, event->weight);
		} break;
		case SCHED_TRACE_SET_WEIGHT_ARGS: {
			struct sched_trace_event_set_weight_args *event = data;
			fprintf(trace_fd, "SET_WEIGHT_ARGS: cgrp_id=%lu weight=%lu\n", event->cgrp_id, event->weight);
		} break;
		case SCHED_TRACE_ENQUEUE_TASK: {
			struct sched_trace_event_enqueue_task *event = data;
			fprintf(trace_fd, "ENQUEUE_TASK: pid=%lu enq_flags=%lx\n", event->pid, event->enq_flags);
		} break;
		case SCHED_TRACE_DEQUEUE_TASK: {
			struct sched_trace_event_dequeue_task *event = data;
			fprintf(trace_fd, "DEQUEUE_TASK: pid=%lu deq_flags=%lx\n", event->pid, event->deq_flags);
		} break;
		case SCHED_TRACE_SUB_ATTACH_ARGS: {
			struct sched_trace_event_sub_attach_args *event = data;
			fprintf(trace_fd, "SUB_ATTACH_ARGS: cgrp_id=%lu\n", event->cgrp_id);
		} break;
		case SCHED_TRACE_SUB_DETACH_ARGS: {
			struct sched_trace_event_sub_detach_args *event = data;
			fprintf(trace_fd, "SUB_DETACH_ARGS: cgrp_id=%lu\n", event->cgrp_id);
		} break;
		case SCHED_TRACE_RUN_TASK: {
			struct sched_trace_event_run_task *event = data;
			fprintf(trace_fd, "RUN_TASK: pid=%lu\n", event->pid);
		} break;
		case SCHED_TRACE_STOP_TASK: {
			struct sched_trace_event_stop_task *event = data;
			fprintf(trace_fd, "STOP_TASK: pid=%lu\n", event->pid);
		} break;
		case SCHED_TRACE_KICK_CPU: {
			struct sched_trace_event_kick_cpu *event = data;
			fprintf(trace_fd, "KICK_CPU: cpu=%d\n", event->cpu);
		} break;
		default:
			fprintf(trace_fd, "UNKNOWN_EVENT_TYPE\n");
	}
	
	return 0;
}

int main(int argc, char **argv)
{
	struct scx_wrr *skel;
	struct scx_eaf *sub_skels[NSUB];
	struct bpf_link *link;
	struct bpf_link *sub_links[NSUB];
	pid_t sub_tasks[NSUB];
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
		if (prep_sub(sub_skels[i], cg_path) < 0) {
			fprintf(stderr, "Error: failed to prep sub %d\n", i);
			goto cleanup;
		}
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
		if (!fp || fprintf(fp, "%d\n", 25 + i * 25) < 0) {
			fprintf(stderr, "Error: could not write to file %s\n", w_path);
			if (fp) fclose(fp);
			goto cleanup;
		}
		fclose(fp);
		fprintf(stdout, "Subscheduler %d Attached\n", i);

		// add indefinite task
		sleep(1);
		sub_tasks[i] = add_indefinite_task_clone3(cg_path);
		if (sub_tasks[i] < 0) {
			fprintf(stderr, "Error: failed to create task %d\n", i);
			goto cleanup;
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
		if (sub_tasks[i] > 0) kill(sub_tasks[i], SIGKILL);
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
