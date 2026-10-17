# Operation trace analysis utilities

These utilities prepare the offline analysis needed by E2/E3. They do not run
experiments, attach probes, configure tracing or patch the kernel. A live
fentry/fexit collector or kernel-tracepoint adapter still needs implementing and
validation. Existing `sched_switch`/wakeup events cannot be converted into
operation durations.

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
- Both boundaries must be retained. Calls cut by capture start/stop are errors;
  a future collector needs a consistent gating/draining strategy. The analyser
  does not discard boundary calls, repair nesting, reorder records or clip times.
- `complete`, `record_count` and loss counters must come from the finalized
  producer. `lost_records` covers transport/output loss; `missed_probes` covers
  missed instrumentation, including recursion skips. Unknown counters must not
  be replaced with invented zeros. Metadata may contain extra provenance fields.
- `expected_operations` lists the callbacks actually instrumented. Unexercised
  operations produce zero-sample rows. Omit SCX entries for an E2-only capture;
  uninstrumented callbacks are not reported as costing zero time.

The future adapter must derive these fields from its actual instrumentation.
This document does not prescribe kernel tracepoint names or claim existing
tracepoint/fentry records already contain call IDs or parent IDs.

## Outputs and definitions

`paired-calls.jsonl` retains each completed class/SCX call, both timestamps,
context, parent, CPUs and exact integer duration. Class calls additionally record
the count, duration sum and duration union of **recorded descendant SCX calls in
the same execution context**, when SCX instrumentation is declared. Nested SCX
calls overlap: their sum can exceed their union. The per-call percentage uses
`100 * union / class_duration`; a zero class duration gives `null`.

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
bad nesting, missing boundaries or zero complete class calls fail analysis with a
nonzero exit status. Raw inputs are untouched. Diagnostics and any
`paired-calls.partial.jsonl` are retained; failed analyses have `valid: false`.
Input hashes are recorded and checked again after processing. A successful report
means structural analysis passed; it still says `analysis_only: true` and
`experiment_validated: false`, because these utilities cannot validate the
workload, scheduler configuration or completeness of probe coverage.
