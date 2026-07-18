// goal: change cpumask to trigger migrations, measure using ftrace logging
// ftrace cmd: sudo trace-cmd record -e sched_migrate_task -e sched_switch
// latency between sched_migrate_task and sched_switch is the migration latency

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

int main(int argc, char **argv) {
  int num_cpus = sysconf(_SC_NPROCESSORS_CONF);

  uint64_t loops = 10000;
  if (argc > 1) loops = strtoull(argv[1], NULL, 10);

  int *mig_seq = (int *)malloc(sizeof(int) * (loops+1));
  int curr_cpu = sched_getcpu();
  mig_seq[0] = curr_cpu;
  srand(time(NULL));

  printf("Running mig test for %lu loops\n", loops);
  for (uint64_t i = 1; i <= loops; i++) {
    // migrate to random CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int next_cpu = rand() % (num_cpus-1);
    next_cpu += next_cpu >= curr_cpu;
    CPU_SET(next_cpu, &cpuset);
    mig_seq[i] = next_cpu;
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    assert(sched_getcpu() == next_cpu);
    curr_cpu = next_cpu;
  }
  printf("Finished mig test\n");

  printf("mig seq: ");
  for (uint64_t i = 0; i <= loops; i++) {
    printf("%d ", mig_seq[i]);
  }
  printf("\n");

  free(mig_seq);

  return 0;
}