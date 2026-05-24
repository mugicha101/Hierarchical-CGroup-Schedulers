// helper functions for cgroup subscheduler tests
// TODO: separate into .c, .h

#ifndef SCX_CGSS_HELPERS_H
#define SCX_CGSS_HELPERS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

int create_cgroup(const char *path) {
	if (mkdir(path, 0755) && errno != EEXIST) {
		perror("Failed to create cgroup");
		return -1;
	}
	return 0;
}

// sets cgroup weight,returns true on success
bool set_cgroup_weight(const char *cg_path, u32 weight) {
	char w_path[256];
	snprintf(w_path, sizeof(w_path), "%s/cpu.weight", cg_path);
	FILE *fp = fopen(w_path, "w");
	if (!fp) return false;
	if (fprintf(fp, "%u\n", weight) < 0) {
		fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}

typedef int (*child_func_t)(void *);
pid_t add_task_clone3(const char *cg_path, child_func_t child_func, void *child_arg) {
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
		// fprintf(stdout, "task spawned on cgroup %s\n", cg_path);

		// run func
    int ret = 0;
    if (child_func) {
      ret = child_func(child_arg);
    }
		_exit(ret); 
	}

	// in parent
	close(cg_fd);
	return pid;
}

// handle tracing events
struct callback_ctx {
	char sched_name[32];
};
static FILE *trace_fd = NULL;
static u64 start_time = 0;
int handle_event(void *ctx, void *data, size_t data_sz) {
	if (!trace_fd) return 0;

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
		case SCHED_TRACE_TRY_SUB_DISPATCH: {
			struct sched_trace_try_sub_dispatch *event = data;
			fprintf(trace_fd, "TRY_SUB_DISPATCH: idx=%d success=%d\n", event->idx, event->success);
		} break;
		case SCHED_TRACE_SUB_PARAMS_UPDATE: {
			struct sched_trace_sub_params_update *event = data;
			fprintf(trace_fd, "SUB_PARAMS_UPDATE: idx=%d cgrp_id=%lu weight=%lu\n", event->idx, event->cgrp_id, event->weight);
		} break;
		case SCHED_TRACE_ENABLE_TASK: {
			struct sched_trace_event_enable_task *event = data;
			fprintf(trace_fd, "ENABLE_TASK: pid=%lu\n", event->pid);
		} break;
		case SCHED_TRACE_DISABLE_TASK: {
			struct sched_trace_event_disable_task *event = data;
			fprintf(trace_fd, "DISABLE_TASK: pid=%lu\n", event->pid);
		} break;
		case SCHED_TRACE_SET_TASK_WEIGHT: {
			struct sched_trace_event_set_task_weight *event = data;
			fprintf(trace_fd, "SET_TASK_WEIGHT: pid=%lu weight=%lu\n", event->pid, event->weight);
		} break;
		case SCHED_TRACE_SELF: {
			struct sched_trace_event_self *event = data;
			fprintf(trace_fd, "SELF: cgrp_id=%lu weight=%lu\n", event->cgrp_id, event->weight);
		} break;
		default:
			fprintf(trace_fd, "UNKNOWN_EVENT_TYPE\n");
	}
	
	return 0;
}

#endif