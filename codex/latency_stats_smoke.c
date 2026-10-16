#include <assert.h>
#include <stdint.h>

typedef uint64_t u64;
#define __BPF__
#define __arena
#define TRACE_EVENTS__EVENTS_BPF_H
#define unlikely(value) (value)

static unsigned calls;
static u64 bpf_ktime_get_ns(void) { return ++calls; }

#include "../scheds/diagnostics.h"

int main(void)
{
  struct latency_ctx context = {.start_time = 123, .pause_start_time = 456};
  struct latency_stat stats = {.n = 7, .sum = 8, .max = 9};
  lstat_start(&context);
  lstat_pause(&context);
  lstat_resume(&context);
  lstat_record(&context, &stats);
#if SCX_LATENCY_STATS
  assert(calls > 0 && stats.n == 8 && stats.sum > 8);
#else
  assert(calls == 0 && stats.n == 7 && stats.sum == 8 && stats.max == 9);
  assert(context.start_time == 123 && context.pause_start_time == 456);
#endif
  return 0;
}
