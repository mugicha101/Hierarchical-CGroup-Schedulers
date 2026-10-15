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

#endif