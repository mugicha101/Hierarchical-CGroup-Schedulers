### Description

Derives migration latency stats per CPU pairing

Measures time between sched_migrate_task and sched_switch events

Scheduler should not matter

### Stages:

run `sh mig_latency_test.sh <# of samples>` to run all stages

`mig_program.c`: program that migrates randomly between CPUs

`mig_trace_analyze.py`: parses recorded trace events during `mig_program.c`'s execution to find latency stats per CPU pair

`mig_viz.py`: visualizes results

### Output Files:

`trace.dat` raw bytes of trace

`trace_report.txt` human readable trace events

`mig_latency_results` migration latency stats per CPU pair

`latency_grid.png` heatmap visualization of average migration latencies on each CPU pair
