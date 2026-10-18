# Operation trace analysis utilities

These utilities provide the offline analysis used by E2–E4. The standalone
commands do not run experiments or change tracing. The experiment runners use
`tester/utils/operation_convert.py` to adapt verified target-kernel tracepoint
bindings. Target validation remains pending. Existing `sched_switch`/wakeup
events cannot be converted into operation durations.

```sh
python3 tester/utils/inspect_trace.py TRACE.dat --output NEW_INVENTORY.json
python3 tester/utils/analyse_operations.py CAPTURE_DIR
```

`inspect_trace.py` uses the existing Babeltrace reader and the trace's
`TRACE.dat.metadata.json` sidecar. It checks frozen monotonic capture controls and
zero-loss CPU counters, then reports event names, payload fields, event counts,
CPUs, timestamp ranges and source hashes. It refuses an existing output file.
Use it to inspect actual event schemas before writing an adapter.

`analyse_operations.py` reads `operations.jsonl` and `operations.metadata.json`
from the capture directory. It needs only the Python standard library, no root
or live cgroups. Its default output is a **new** `operation-analysis` directory;
use `--output-dir NEW_DIR` for another analysis. Existing outputs are refused.

## Producer contract

The following is a format example, not measured experiment data. All times are
integer monotonic nanoseconds. Each JSONL line contains one complete JSON object.

`operations.metadata.json`:

```json
{
  "schema_version": 1,
  "producer": "format-example",
  "scheduler": "jlfp",
  "clock": "monotonic",
  "complete": true,
  "record_count": 4,
  "cpus": [9],
  "loss": {"lost_records": 0, "missed_probes": 0},
  "statistics": {"quantile_method": "nearest_rank", "stddev": "population"},
  "expected_operations": [
    {"layer": "class", "operation": "enqueue_task_scx"},
    {"layer": "class", "operation": "yield_task_scx"},
    {"layer": "scx", "operation": "enqueue"}
  ]
}
```

`operations.jsonl`:

```jsonl
{"phase":"enter","timestamp_ns":100,"cpu":9,"context":"task:123","call_id":1,"parent_id":null,"rq_cpu":9,"layer":"class","operation":"enqueue_task_scx"}
{"phase":"enter","timestamp_ns":120,"cpu":9,"context":"task:123","call_id":2,"parent_id":1,"rq_cpu":9,"layer":"scx","operation":"enqueue"}
{"phase":"exit","timestamp_ns":160,"cpu":9,"context":"task:123","call_id":2}
{"phase":"exit","timestamp_ns":200,"cpu":9,"context":"task:123","call_id":1}
```

The producer must meet these conditions:

- `cpu` is the **execution CPU**. `rq_cpu` is the affected runqueue CPU, or `null`
  where unavailable; a remote runqueue is not the execution CPU. Summaries group
  by execution CPU, while exact call records preserve both.
- `context` identifies the execution context, including interrupt nesting when
  relevant. PID alone cannot distinguish a task from an interrupt running over
  that task. The producer must retain the same identifier across a matched call.
- Entry `call_id` values increase strictly per CPU, across all contexts, for the
  entire capture. They may have gaps. `parent_id` identifies the active recorded
  parent in the same CPU/context, or is `null` for a top-level recorded call.
- Records arrive in timestamp order **within each CPU**, with correct entry/exit
  order for ties. Global ordering between CPUs is unnecessary. Calls spanning
  CPUs are unsupported and fail pairing; do not silently move their records.
- Both boundaries of every selected call must be retained. Calls cut by capture
  start/stop are errors. The analyser does not repair nesting, reorder records or
  clip times. The tracepoint adapter records before/after the workload interval,
  selects root calls whose entry falls within it, and retains complete descendants
  and exits after the interval. Leading exits before the interval and unselected
  calls outside it are counted in conversion diagnostics. This selection is
  explicit; unmatched exits at/after the interval start and selected missing exits
  fail conversion.
- `complete`, `record_count` and loss counters must come from the finalized
  producer. `lost_records` covers transport/output loss; `missed_probes` covers
  missed instrumentation, including recursion skips. Unknown counters must not
  be replaced with invented zeros. Metadata may contain extra provenance fields.
- `expected_operations` lists the callbacks actually instrumented. Unexercised
  operations produce zero-sample rows. Omit SCX entries for an E2-only capture;
  uninstrumented callbacks are not reported as costing zero time.

The adapter derives call IDs and parent IDs from each execution CPU/context's
observed tracepoint stack. Context includes current PID, hard/soft IRQ flags and
recorded IRQ-handler nesting. The existing ftrace plugin exposes libtraceevent's
`latency` field instead of raw `common_flags`; its IRQ column is decoded using the
[kernel's documented format](https://www.kernel.org/doc/html/latest/trace/ftrace.html).
Unknown encodings and NMI operations fail. Handler markers do not expose every
possible nested interrupt boundary outside handlers; target validation must check
that the instrumented operations have sufficient context coverage. Calls that
migrate between CPUs are unsupported. `rq_cpu` remains null with the supplied
payloads; execution CPU is never substituted for an unknown runqueue CPU.

`class` denotes actual sched_class methods. A separate `kernel` outer layer
represents verified kernel sched_ext callback wrappers. Both can contain `scx`
intervals, but a wrapper is never silently reported as a class-method measurement.
The kernel binding must declare its scope and numeric operation mapping. Kernel
callback and custom SCX events use the same target-specific `SCX_OP_IDX` IDs and
canonical `struct sched_ext_ops` member names. Historical custom events from
before this change used a separate enum and require their original mapping.
E2 requires class scope.

Exit records may additionally contain `reported_duration_ns`, copied from the
configured kernel exit field (normally `delta_ns`). When present, this supplies
`duration_ns` in paired samples and latency statistics. The timestamp difference
is retained separately as `boundary_duration_ns`. Both values remain available;
no equality or clock-placement assumption is made about them. Custom SCX calls
continue to use their timestamp boundaries.

## Outputs and definitions

`paired-calls.jsonl` retains each completed class/kernel/SCX call, both timestamps,
context, parent, CPUs and exact integer duration. Class calls additionally record
the count, duration sum and duration union of **recorded descendant SCX calls in
the same execution context**, when SCX instrumentation is declared. Nested SCX
calls overlap: their sum can exceed their union. The per-call percentage uses
`100 * union / outer_duration`; a zero duration gives `null`. When kernel-reported
and boundary durations differ, the fraction uses the reported outer duration;
values above 100% are retained for inspection, never clamped or corrected.

Interrupted contexts have separate stacks. Their independent callback records
are not assigned to an interrupted task's class call merely because times overlap.
A callback interval that spans an interrupt still includes that elapsed interrupt
time. Nested class calls can each include the same descendant SCX call; these
per-call measurements must not be summed as total CPU execution time. SCX calls
without a recorded class ancestor are retained and counted explicitly.

`latencies.csv` and `analysis.json` report count, min, max, mean, median, p99,
p99.9 and standard deviation in **nanoseconds**, per operation and execution CPU.
An empty CPU cell in CSV (`null` in JSON) is the pooled operation row, computed
from all its samples. Zero-sample rows have `null` statistics. One sample has
undefined (`null`) sample standard deviation. Quantiles support `nearest_rank`
or `linear`; standard deviation supports `population` or `sample`. These choices
are captured in metadata rather than inferred from the current machine config.
E1 reuses the same exact histogram statistics helper and keeps its existing
microsecond outputs and one-sample validation behavior.

`duration_weighted_scx_percent` is `100 * sum(per-call unions) / sum(class durations)`
for a class-operation row. It is not the unweighted mean of per-call percentages.
The fraction covers only the declared, recorded descendant callbacks. Both the
per-call and aggregate values are `null` when SCX was not instrumented.

All durations are inclusive elapsed time. No interrupt/preemption time or probe
cost is subtracted. Tracing-cost calibration, exclusive execution time and
scientific interpretation remain separate work.

Invalid metadata, loss, count mismatches, malformed records, backwards CPU times,
bad nesting, missing boundaries or zero complete outer calls fail analysis with a
nonzero exit status. Raw inputs are untouched. Diagnostics and any
`paired-calls.partial.jsonl` are retained; failed analyses have `valid: false`.
Input hashes are recorded and checked again after processing. A successful report
means structural analysis passed; it still says `analysis_only: true` and
`experiment_validated: false`, because these utilities cannot validate the
workload, scheduler configuration or completeness of probe coverage.
