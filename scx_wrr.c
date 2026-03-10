/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
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

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#define NSUB 1

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
	int fd, len;
	char buf[32];

	if (stat(cg_path, &st) < 0) {
		perror("stat cgroup");
		return -1;
	}
	skel->struct_ops.eaf_ops->sub_cgroup_id = st.st_ino;
	skel->rodata->cgroup_id = st.st_ino;

	// patchset-specific prog_aux_priv hack
	fd = open("/sys/module/bpf/parameters/prog_aux_priv", O_RDWR);
	if (fd >= 0) {
		len = snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)st.st_ino);
		if (write(fd, buf, len) != len) {
			perror("write to prog_aux_priv failed");
			close(fd);
			return -1;
		}
		close(fd);
	} else {
		perror("Warning: Could not open prog_aux_priv");
	}

	return 0;
}

pid_t add_indefinite_task(const char *cg_path) {
	pid_t pid = fork();
	if (pid == 0) {
		// change policy to scx
		struct sched_param sp = {};
		if (sched_setscheduler(0, SCHED_EXT, &sp) < 0) {
		fprintf(stderr, "Failed to add task to %s: could not set policy to SCHED_EXT\n", cg_path);
			exit(1);
		}

		// add self to cgroup
		char procs_path[512];
		FILE *fp;
		snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cg_path);
		fp = fopen(procs_path, "w");
		if (fp) {
			fprintf(fp, "%d\n", getpid());
			fclose(fp);
		} else {
		fprintf(stderr, "Failed to add task to %s: could not open cgroup.procs\n", cg_path);
			exit(1);
		}

		// spin indefinitely
		// fprintf(stdout, "Added Task to %s\n", cg_path);
		volatile unsigned long long counter = 0;
		// pid_t pid = getpid();
		while (1) {
				counter++;
				// fprintf(stdout, "Task on %s pid=%d\n", cg_path, pid);
				// sleep(1);
		}
	}

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

int main(int argc, char **argv)
{
	struct scx_wrr *skel;
	struct scx_eaf *sub_skels[NSUB];
	struct bpf_link *link;
	struct bpf_link *sub_links[NSUB];
	pid_t sub_tasks[NSUB];

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

	// load wrr as root
	skel = SCX_OPS_OPEN(wrr_ops, scx_wrr);
	if (!skel) goto cleanup;
	SCX_OPS_LOAD(skel, wrr_ops, scx_wrr, uei);
	link = SCX_OPS_ATTACH(skel, wrr_ops, scx_wrr);
	if (!link) goto cleanup;
	fprintf(stdout, "Root WRR Scheduler Attached\n");

	// load and attach subschedulers
	char cg_path[256];
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
		if (prep_sub(sub_skels[i], cg_path) < 0) goto cleanup;
		SCX_OPS_LOAD(sub_skels[i], eaf_ops, scx_eaf, uei);
		sub_links[i] = SCX_OPS_ATTACH(sub_skels[i], eaf_ops, scx_eaf);
		if (!sub_links[i]) {
			fprintf(stderr, "Error: failed to attach sub %d\n", i);
			goto cleanup;
		}
		sleep(1);

		// set cgroup weight
		// note: if fails, likely need to run: echo "+cpu" | sudo tee /sys/fs/cgroup/cgroup.subtree_control
		char w_path[256];
		FILE *fp;
		snprintf(w_path, sizeof(w_path), "%s/cpu.weight", cg_path);
		fp = fopen(w_path, "w");
		if (!fp || fprintf(fp, "%d\n", 25) < 0) {
			fprintf(stderr, "Error: could not write to file %s\n", w_path);
			if (fp) fclose(fp);
			goto cleanup;
		}
		fclose(fp);
		fprintf(stdout, "Subscheduler %d Attached\n", i);

		// add indefinite task
		sub_tasks[i] = add_indefinite_task(cg_path);
		if (sub_tasks[i] < 0) {
			fprintf(stderr, "Error: failed to create task %d\n", i);
			goto cleanup;
		}
	}

	// sleep while running
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
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

	fprintf(stdout, "WRR Scheduler Detached\n");

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
