# E5 container capacity baseline

The runner checks whether Nginx and each configured database can sustain their
offered request rates on one logical CPU. It uses SCHED_OTHER and reports CPU
demand, throughput, errors, queue drops and latency. E5's RM/FIFO/JLFP hierarchy
and E3-style overhead attribution remain pending; no scheduler or tracing is
enabled by this baseline. Fixed-rate HTTP requests do not make Nginx worker
threads periodic RM jobs.

## Setup and execution

Install Docker and provision the images from `experiments.containers.e5.images`
externally. The runner requires those exact images locally and never installs
packages, pulls images, changes isolation or creates the parent cgroups.

```sh
python3 -m venv tester/build/e5-venv
tester/build/e5-venv/bin/pip install -r tester/experiments/containers/requirements.txt
sudo tester/build/e5-venv/bin/python tester/experiments/containers/run_e5.py
sudo tester/build/e5-venv/bin/python tester/experiments/containers/run_e5.py --config tester/experiments/debug.json --database postgres
python3 tester/experiments/containers/run_e5.py --analyse-only SUITE_DIR
```

`tester/experiments/run.py e5` provides the same runner. The driver accepts
`--config` before `e5`; the standalone runner accepts it after the script name.
Offline analysis uses only the Python standard library and needs neither Docker
nor root access. It writes the result tables into the suite directory; copy
root-owned artifacts to a user-writable directory before replaying without root.

Set the shared `workload_cgroup` and `controller_cgroup` to existing, disjoint
process cgroups. For E5 capacity, the workload group must be empty throughout its
subtree and confined to exactly one logical CPU. Parent CPU quotas must be
unlimited. The controller group supplies client/controller placement and is
restored after the suite. No separate CPU lists are configured.

Docker creates its container cgroups under the workload group. With Docker's
systemd driver, that group must be an existing systemd `.slice` at its canonical
hierarchy path; with cgroupfs it may be an existing domain cgroup. Actual container
ancestry, effective cpuset, every observed thread's affinity/policy and quota are
checked before measurement. See Docker's
[cgroup-parent documentation](https://docs.docker.com/reference/cli/dockerd/#default-cgroup-parent).
Docker-created child groups and anonymous data volumes are removed afterward;
the prepared parents are not removed.

## Configuration and measurements

The shared `duration_s` and `warmup_s` control measurement and warmup. E5 requires
whole measurement seconds. `experiments.containers.e5` contains repetitions,
image digests, memory limits, dataset/response sizes, client concurrency, queue
capacity, per-pair request rates and capacity screening thresholds. Debug uses
the same workloads with a shorter duration and one repetition.

Each case starts fresh containers, creates the dataset and prepares all clients
before publishing a common start window. Nginx uses one worker, keepalive and
no access log. Database requests are uniform read-only indexed lookups. Redis
persistence is disabled; PostgreSQL and MongoDB retain their default persistence
behavior. Servers bind to loopback and use the host network; clients execute
outside the workload CPU.

Capacity fits require the configured completion percentage, zero errors/drops,
mean combined server CPU below its configured limit and host CPU busy time below
its limit in each sampled one-second interval. A complete capture can fail these
criteria; its result is retained and the runner exits with status 2 after reporting
the suite. Cases are not retried or discarded to obtain a passing result.

Artifacts use the existing `tester/build/experiments` layout. Each suite retains
its exact matrix, config, image/runtime versions, Docker commands, client logs,
placement, raw nanosecond samples, one-second CPU counters and cleanup evidence.
Replay verifies raw hashes, sample counts, request accounting and placement,
then recomputes CPU demand and exact nearest-rank p99/max values. `results.json`
and `results.csv` include failing cases. Incomplete suites and changed raw files
are rejected. Reports retain `experiment_validated: false` pending target review.

Latency spans scheduled arrival through response, including delayed client
admission and queueing. Actual request duration, admission lag, queue wait,
first/second-half p99 and post-window completions remain visible. CPU headroom
does not establish real-time latency bounds.

See [the original sizing measurements](WORKLOAD_SIZING.md) for the tested rates,
the initial small-queue failure, longer PostgreSQL repeats and host limitations.
