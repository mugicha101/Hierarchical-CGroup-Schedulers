# E5 container policies and overhead

E5 runs Nginx alongside Redis, PostgreSQL or MongoDB on one logical CPU. A JLFP
root prioritizes Nginx's JLFP leaf above the database's JLFP leaf. Nginx tasks use
fixed priorities ordered by configurable nominal periods; database tasks use an
equal priority. These demonstrate different ordering rules using existing
schedulers. They do not implement periodic job releases, exact Linux FIFO or
bandwidth enforcement. No scheduler source changes are required.

The default configuration captures class operations and kernel SCX callbacks
using the same fentry/fexit and tracepoint analysis as E3. The explicit native
mode retains the original SCHED_OTHER capacity baseline.

## Setup and execution

Provision Docker, the configured digest-pinned images, libbpf, clang-22 and
bpftrace externally. Full tracing also needs the target kernel's
`sched_ext:sched_ext_op_enter/exit` events with SCX_OP_IDX and `delta_ns` fields.
Missing instrumentation fails preflight before starting workloads or schedulers.
Unrelated ftrace events and function tracers must be disabled externally.

```sh
python3 -m venv tester/build/e5-venv
tester/build/e5-venv/bin/pip install -r tester/experiments/containers/requirements.txt
sudo tester/build/e5-venv/bin/python tester/experiments/containers/run_e5.py
sudo tester/build/e5-venv/bin/python tester/experiments/containers/run_e5.py --config tester/experiments/debug.json --database postgres
python3 tester/experiments/containers/run_e5.py --analyse-only SUITE_DIR
```

`experiments/run.py e5` provides the same runner; put `--config` before `e5` for
the shared driver. Replay needs only the Python standard library and writes into
the suite directory. Copy root-owned captures to a writable directory if needed.

Set `workload_cgroup` and `controller_cgroup` to existing, disjoint process
groups. The workload subtree must initially be empty and have exactly one logical
CPU, matching the workload sizing experiment. All ancestor CPU quotas must be
unlimited. The controller group supplies client and scheduler-process placement;
the runner restores its original placement afterward. CPU lists come from the
groups, with no separate CPU arguments.

Docker creates its container groups under the existing workload group. Its
systemd driver requires a canonical existing `.slice`; the cgroupfs driver
accepts an existing domain group. Servers inherit that cpuset. The runner never
installs packages, pulls images, creates the prepared parents or changes
isolation/frequency settings. Only owned containers, anonymous volumes and
scheduler instances are removed; the parents remain.

## Configuration and measurement

Shared `duration_s` and `warmup_s` control the measurement window. Measurement
seconds must be whole numbers. `experiments.containers.e5` contains image digests,
memory limits, dataset/response sizes, concurrency, queues, per-pair request
rates, repetitions and capacity screening thresholds.

Its `scheduling` object selects:

- `mode: "scx"`: a root and two leaf JLFP instances, built privately with custom
  trace emissions and latency statistics disabled. Single-CPU shards allow the
  leaves to cover the workload CPU. All observed server threads must use
  SCHED_EXT; clients and scheduler processes stay in the controller group.
- `container_weights`: Nginx must rank above the database. These are JLFP
  priorities, not proportional CPU shares or quotas.
- `nginx_period_ns`: initial worker/master labels are 1 ms/10 ms. A smaller label
  gives a larger task weight (`2^63 - 1 - period_ns`). These labels order existing
  event-loop processes; they do not control arrivals or job completion.
- Database threads use the equal maximum task weight. New database threads
  inherit SCHED_EXT and their absent map entry has the same effective default
  weight. Observed Nginx restarts, priority changes or placement changes fail.
- `trace: true`: require the full E3 capture. Debug configuration sets this to
  `false` for functional sched_ext checks on an unpatched host; no overhead result
  is produced. `mode: "native"` together with `trace: false` runs capacity only.

Fresh servers are seeded, then clients prepare connections before a common start
window. Containers are briefly frozen while leaf schedulers and every existing
thread's policy/weight are configured. This includes PostgreSQL connection
backends. Containers resume before warmup. Policies, affinities, weights and
scheduler identities are checked at setup and each CPU sample; task checks are
retained. Leaves detach before the root and before removing Docker groups.

Nginx uses one worker, keepalive, a static 1 KiB response and no access log.
Database traffic reads uniformly selected indexed records from a hot dataset of
10,000 values, 256 bytes each. Redis persistence is disabled. PostgreSQL and
MongoDB retain their default persistence behavior. Servers bind to loopback with
host networking; clients run outside the workload CPU.

## Results and replay

The suite retains commands, image/build hashes, hierarchy identities, per-thread
checks, raw request timing samples, one-second CPU counters and cleanup evidence.
Replay verifies hashes, exact request accounting, placement and priorities, and
recomputes CPU demand and nearest-rank latency statistics. `results.json` and
`results.csv` retain complete cases that fail screening; cases are not retried to
obtain a passing capacity result. Incomplete captures and changed files reject.

Traced cases additionally retain bpftrace records/counters, miss evidence,
normalized operations and `operation-analysis/` tables and paired calls. Replay
recomputes E3's per-operation class/callback durations, outermost callback
fractions and uncalibrated residuals. Lost events, misses, incomplete calls or
missing nested callback samples invalidate the capture. Generic callback events
identify an operation, not a scheduler instance: attribution aggregates the root
and both leaves. It cannot separate their individual costs. Measurements include
only work executing on the workload CPU; remote waker work is excluded. Probe,
IRQ and preemption costs are not subtracted; tick calibration remains pending.

Capacity screening requires the configured completion percentage, zero errors
or queue drops, mean combined server CPU within its limit and one-second host
busy time within its limit. Latency spans scheduled arrival through response;
service time, admission lag, queue wait and post-window completions remain
visible. CPU headroom does not establish real-time latency bounds. Reports keep
`experiment_validated: false` pending target review.

See [the native sizing measurements](WORKLOAD_SIZING.md) for the original rates
and host limitations. Those measurements did not use sched_ext.
