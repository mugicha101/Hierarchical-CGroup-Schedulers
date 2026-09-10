#ifndef __SCX_BASE_CLI_H
#define __SCX_BASE_CLI_H

#include <stdbool.h>
#include <stdint.h>

struct base_cli_opts {
	bool verbose;
	bool global_search;
	uint32_t max_shard_size;
	uint32_t max_tasks;
	const char *cgroup_path;
	const char *trace_path;
	const char *stats_path;
};

static inline struct base_cli_opts base_cli_default(void)
{
	return (struct base_cli_opts) {
		.max_shard_size = 8,
		.max_tasks = 16384,
	};
}

static inline bool apply_base_opts base_cli_opts()
{
	
}

#endif
