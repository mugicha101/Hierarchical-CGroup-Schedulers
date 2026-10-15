// spawns threads with weight = tid

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <time.h>
#include <pthread.h>
#include <wait.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

static volatile int exit_req;
static void sigint_handler(int simple) {
	exit_req = 1;
}

const char *cg_path = "/sys/fs/cgroup/foo";

static void burn_work(uint64_t iterations) {
  for (volatile uint64_t i = 0; i < iterations; ++i);
}

static uint64_t now_ns(clockid_t clock) {
  struct timespec ts;
  if (clock_gettime(clock, &ts)) {
    perror("clock_gettime");
    exit(1);
  }
  return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

struct gedf_worker {
  uint64_t *flags;
  size_t length;
  size_t word;
  uint64_t mask;
};

static int prepare_gedf_worker(struct gedf_worker *worker, uint64_t deadline) {
  int flags_fd = -1, weights_fd = -1, pid_fd = -1, status = 1;
  uint32_t info_size = sizeof(struct bpf_map_info);
  struct bpf_map_info info = {};
  uint64_t tid = syscall(SYS_gettid);
  long page_size = sysconf(_SC_PAGESIZE);

  flags_fd = bpf_obj_get("/sys/fs/bpf/scx/job_completion_flags");
  if (flags_fd < 0) {
    perror("open job_completion_flags");
    goto out;
  }
  if (bpf_obj_get_info_by_fd(flags_fd, &info, &info_size)) {
    perror("get job_completion_flags info");
    goto out;
  }
  uint64_t bytes = (uint64_t)info.max_entries * sizeof(uint64_t);
  if (info.type != BPF_MAP_TYPE_ARRAY || info.key_size != sizeof(uint32_t) ||
      info.value_size != sizeof(uint64_t) || !(info.map_flags & BPF_F_MMAPABLE) ||
      (tid >> 6) >= info.max_entries || page_size <= 0 ||
      bytes > SIZE_MAX - (size_t)page_size + 1) {
    fprintf(stderr, "invalid job_completion_flags map or worker tid outside bitmap\n");
    goto out;
  }
  worker->length = (bytes + page_size - 1) / page_size * page_size;
  // array mmap exposes values at offset zero; kernel metadata is not mapped
  worker->flags = mmap(NULL, worker->length, PROT_READ | PROT_WRITE,
                       MAP_SHARED, flags_fd, 0);
  if (worker->flags == MAP_FAILED) {
    worker->flags = NULL;
    perror("mmap job_completion_flags");
    goto out;
  }
  worker->word = tid >> 6;
  worker->mask = 1ull << (tid & 63);
  __atomic_fetch_and(&worker->flags[worker->word], ~worker->mask, __ATOMIC_SEQ_CST);

  pid_fd = syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
  if (pid_fd < 0) {
    perror("open worker pidfd");
    goto out;
  }
  weights_fd = bpf_obj_get("/sys/fs/bpf/scx/task_weights");
  if (weights_fd < 0) {
    perror("open task_weights");
    goto out;
  }
  uint64_t weight = UINT64_MAX - deadline;
  if (bpf_map_update_elem(weights_fd, &pid_fd, &weight, BPF_ANY)) {
    perror("set initial GEDF deadline");
    goto out;
  }
  status = 0;

out:
  if (flags_fd >= 0) close(flags_fd);
  if (weights_fd >= 0) close(weights_fd);
  if (pid_fd >= 0) close(pid_fd);
  if (status && worker->flags) {
    munmap(worker->flags, worker->length);
    worker->flags = NULL;
  }
  return status;
}

static int test_worker(bool gedf) {
  char request[256], extra;
  uint64_t start, end, period, runtime, phase;
  struct gedf_worker worker = {};
  int status = 0;
  puts("ready");
  fflush(stdout);
  // python installs affinity and scheduler parameters before releasing this task
  if (!fgets(request, sizeof(request), stdin) || strchr(request, '-') ||
      sscanf(request, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %c",
             &start, &end, &period, &runtime, &phase, &extra) != 5 ||
      start > end || (period && (!runtime || runtime >= period || phase >= period)) ||
      (!period && (runtime || phase || gedf)) || phase > UINT64_MAX - start ||
      (gedf && period > UINT64_MAX - (start + phase))) {
    fprintf(stderr, "invalid worker schedule\n");
    return 2;
  }
  if (!period) {
    while (now_ns(CLOCK_MONOTONIC) < end) burn_work(256);
    return 0;
  }
  uint64_t release = start + phase;
  if (gedf && prepare_gedf_worker(&worker, release + period)) return 1;
  while (now_ns(CLOCK_MONOTONIC) < end) {
    uint64_t wake = release < end ? release : end;
    struct timespec deadline = {.tv_sec = wake / 1000000000ull,
                                .tv_nsec = wake % 1000000000ull};
    int err;
    do {
      err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    } while (err == EINTR);
    if (err) {
      fprintf(stderr, "clock_nanosleep: %s\n", strerror(err));
      status = 1;
      break;
    }
    if (now_ns(CLOCK_MONOTONIC) >= end) break;
    uint64_t cpu_start = now_ns(CLOCK_THREAD_CPUTIME_ID);
    // preemption must not consume the budget; end still bounds wall time
    while (now_ns(CLOCK_MONOTONIC) < end &&
           now_ns(CLOCK_THREAD_CPUTIME_ID) - cpu_start < runtime) burn_work(256);
    uint64_t now = now_ns(CLOCK_MONOTONIC);
    if (now >= end) break;
    if (gedf) {
      __atomic_fetch_or(&worker.flags[worker.word], worker.mask, __ATOMIC_SEQ_CST);
    }
    // skip missed releases and wait through the end of the capture
    uint64_t steps = (now - release) / period + 1;
    release = steps > (end - release) / period ? end : release + steps * period;
  }
  if (worker.flags) munmap(worker.flags, worker.length);
  return status;
}

void *thread_func(void *arg) {
  
  fprintf(stdout, "task spawned on cgroup %s\n", cg_path);
  uint64_t tid = syscall(SYS_gettid);


  // set weight before entering sched_ext
  int pid_fd = syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
  if (pid_fd < 0) {
    fprintf(stderr, "Failed to open pidfd for tid %lu: %s\n", tid, strerror(errno));
    // Skip this update if the task died or we don't have permission
    exit(1);
  }

  int file_fd = bpf_obj_get("/sys/fs/bpf/task_weights");
  if (file_fd < 0) {
    fprintf(stderr, "task: failed to open task_weights for writing\n");
    exit(1);
  }

  uint64_t weight = tid;
  int err = bpf_map_update_elem(file_fd, &pid_fd, &weight, BPF_ANY);
  if (err < 0) {
      fprintf(stderr, "Error updating task storage: %d (%s)\n", -err, strerror(-err));
  }
  
  // change policy to sched_ext
  struct sched_param sp = {};
  if (sched_setscheduler(0, SCHED_EXT, &sp) < 0) {
      fprintf(stderr, "task: failed to set policy to SCHED_EXT\n");
      exit(1);
  }
  sched_yield();

  fprintf(stdout, "task %lu running on SCHED_EXT\n", tid);

  while (!exit_req) {
    burn_work(2000000000ull);
  }
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc == 2 && !strcmp(argv[1], "--jlfp-worker")) return test_worker(false);
  if (argc == 2 && !strcmp(argv[1], "--gedf-worker")) return test_worker(true);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

  uint64_t period_ms = argc > 1 ? atoll(argv[1]) : 500;
  int max_threads = argc > 1 ? atoi(argv[2]) : 10;

  // clone3 into cgroup
	int cg_fd = open(cg_path, O_RDONLY | O_DIRECTORY);
	if (cg_fd < 0) {
    perror("Failed to open cgroup directory");
    exit(1);
	}
	struct clone_args args = {0};
	args.flags = CLONE_INTO_CGROUP;
	args.cgroup = cg_fd;
  args.exit_signal = SIGCHLD;
	pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
  close(cg_fd);

	if (pid < 0) {
    perror("clone3 failed");
    return -1;
	}

	if (pid == 0) {
		// in child
		pid = getpid();

    // spawn pthreads with sched_ext policy
    pthread_t threads[max_threads];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_EXT);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    for (int i = 0; i < max_threads; ++i) {
      if (pthread_create(&threads[i], &attr, thread_func, NULL) != 0) {
        fprintf(stderr, "Failed to create thread %d\n", i);
        exit(1);
      }
      usleep(period_ms * 1000);
    }
    for (int i = 0; i < max_threads; ++i) {
      pthread_join(threads[i], NULL);
      fprintf(stdout, "thread %d joined\n", i);
    }
    printf("Cloning Process Exiting Gracefully\n");
    return 0;
	}

  // in parent
  while (!exit_req) {
    usleep(100000);
  }
  kill(pid, SIGTERM); // set exit_req to 1 in child (in case it didn't exit)
  waitpid(pid, NULL, 0); // wait for child to exit gracefully
  printf("System Closed Gracefully\n");
  return 0;
}
