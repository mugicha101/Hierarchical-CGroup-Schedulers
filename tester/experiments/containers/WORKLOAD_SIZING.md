# E5 workload sizing — 19 October 2026

All three final 60-second repeats passed. Nginx at 8,000 HTTP requests/s and PostgreSQL at 4,146 database reads/s shared logical CPU 9, using 61.3–63.7% combined server CPU. This is a capacity check under SCHED_OTHER; the E5 RM/FIFO/JLFP hierarchy and overhead tracing were not run.

## Workloads and placement

- Nginx: one worker, a 1 KiB static response, access logging disabled, HTTP keepalive.
- Databases: 10,000 indexed records with a 256-byte ASCII payload; uniformly random read-only primary-key lookups. Redis persistence disabled; PostgreSQL and MongoDB retain their usual persistence behavior, with no timed writes.
- Two async client processes per service, eight connections each, on controller CPUs 0–7 via a transient systemd scope. Requests use fixed offered rates and a bounded queue; the load generator does not retry failures. Both servers share CPU 9, with no CPU quota.
- Separate 500 requests/s, eight-second calibrations used CPUs 8–15. Each pairing then had four ten-second CPU-9 trials. Each trial has a three-second warmup.
- Initial sizing extrapolated 35% CPU per service. After reviewing all short trials, PostgreSQL was selected for steadier latency than MongoDB here and its fit with the E5 example. One further ten-second tuning trial sought roughly 70% combined CPU.
- Screening criteria: at least 99.5% of offered requests completed, no errors or queue drops, combined mean server CPU at most 80%, and CPU-9 busy time at most 95% in any sampled one-second interval. These are exploratory headroom criteria, not an approved E5 SLA. Failed initial trials remain in the results.

## Highest-rate initial trials

The pairs use different offered rates. This table is not a product performance ranking.

| Pair | HTTP/s | DB reads/s | Nginx CPU | DB CPU | Combined CPU | HTTP p99 | DB p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Nginx + redis | 5,176 | 3,435 | 14.7% | 15.3% | 30.0% | 1.64 ms | 1.44 ms |
| Nginx + postgres | 5,565 | 2,333 | 17.1% | 22.3% | 39.4% | 1.75 ms | 1.49 ms |
| Nginx + mongo | 5,535 | 1,936 | 18.2% | 28.4% | 46.7% | 2.48 ms | 4.25 ms |

## Initial PostgreSQL repeats: queue capacity 64 per client

| Repeat (60 s) | Nginx CPU | PostgreSQL CPU | Combined CPU | CPU-9 mean / peak 1 s | HTTP p99 | DB p99 | Fit |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 24.5% | 41.0% | 65.5% | 63.4% / 75.7% | 2.13 ms | 2.33 ms | pass |
| 2 | 24.3% | 40.2% | 64.5% | 61.9% / 87.0% | 2.77 ms | 3.88 ms | fail |
| 3 | 24.2% | 40.1% | 64.4% | 61.7% / 76.5% | 2.05 ms | 2.12 ms | pass |

## Final PostgreSQL repeats: queue capacity 512 per client

| Repeat (60 s) | Nginx CPU | PostgreSQL CPU | Combined CPU | CPU-9 mean / peak 1 s | HTTP p99 | DB p99 | Fit |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 24.1% | 39.6% | 63.7% | 61.6% / 72.5% | 2.09 ms | 2.16 ms | pass |
| 2 | 23.9% | 37.3% | 61.3% | 58.6% / 80.2% | 3.01 ms | 4.00 ms | pass |
| 3 | 24.4% | 38.3% | 62.7% | 60.0% / 76.5% | 2.00 ms | 2.03 ms | pass |

The initial second repeat dropped 205 HTTP requests at the client queue. Its HTTP service-time p99.9 was 2.70 ms, versus 16.94 ms before the request started. The old queue held only 16 ms of offered arrivals per client. The same rates were repeated with a bounded 512-entry queue (128 ms of HTTP arrivals per client), plus separate admission-lag and queue-wait samples. This avoids treating short controller/queue delays as proof of server CPU saturation; it does not erase those delays from end-to-end latency. The old samples cannot distinguish producer scheduling from queued service backlog.

Final nginx maximum latency ranged from 7.16 to 34.70 ms across repeats. These tails remain visible despite mean CPU headroom.
Final postgres maximum latency ranged from 25.45 to 46.21 ms across repeats. These tails remain visible despite mean CPU headroom.

Replay verified 25 trials and 5,217,215 completed measured requests; errors: 0; queue drops: 205. Final repeats completed 2,186,280 requests, with 0 errors and 0 drops. Counts, exact p99/max values and cgroup CPU deltas were recomputed from retained raw data. No sampled container reported CPU quota throttling. All server threads were checked for SCHED_OTHER and the expected affinity before and after each trial; memory-event counters did not change. CPU-9 cases have effective cpuset 9 and cpu.max=max.

Latency is scheduled client arrival through response, including client scheduling and queueing; it is not pure server processing time. Per-request service durations, per-shard first/second-half p99, post-window completions and one-second CPU counters remain in the artifacts. Requests arriving near the end may complete just afterward; all are counted and the count is retained, rather than discarded.

## Limits and next steps

- This is a short, warmed, read-only capacity screen on the development host (Ryzen 7 7730U). It does not establish write-heavy, disk-bound, larger-dataset or long-duration capacity, and does not replace E5 under its intended policies.
- The host was not isolated for this check. CPU 9 shares a physical core with CPU 8 and uses the existing powersave governor. Background activity, SMT, thermal behavior and client costs remain confounders. No isolation or frequency setting changed.
- MongoDB kept up in its short runs but had larger latency spikes in the highest-rate trial (up to 41.16 ms). This is an observation of this run, not an attribution of cause or a general comparison of databases. Redis and MongoDB have not had the longer repeats.
- Repeat the chosen rates on the final host. Define how Nginx worker jobs receive RM periods/priorities, PostgreSQL FIFO semantics within its container, and the JLFP container weights before implementing the full E5 runner. Fixed-rate clients do not by themselves make server threads periodic real-time tasks.

## Artifacts and reproduction

The committed runner is [run_e5.py](run_e5.py); see [README.md](README.md) for
setup and shared configuration. Its fixed-rate cases promote the sizing workloads;
the exploratory calibration/tuning sequence remains a development tool.

The original development artifacts are retained locally under
`tester/codex/e5-results-20261019T174302Z/`: raw request samples, CPU counters,
configurations, command logs, image digests, source snapshots, the failed trial
and replay diagnostics. This directory and the root-session helper remain
untracked. Do not treat the raw measurements as included in this commit.

The original runs used Docker 29.1.3, containerd 2.2.2, runc 1.4.0 and Python
3.14; client versions and exact images are recorded in the committed requirements
and shared configuration. The promoted runner adds existing-cgroup placement,
client startup gating and suite replay. Its development checks are distinct from
the original 60-second sizing measurements above.

The integrated runner passed one three-second development case for each pair,
using a manually prepared CPU-9 workload slice and a disjoint controller leaf.
Combined CPU demand was 33.1% (Redis), 63.7% (PostgreSQL) and 43.7% (MongoDB),
with all three capacity checks passing. Container ancestry, policy, cpuset,
controller restoration and scoped cleanup were checked. Standalone and shared
driver replay passed from a user-writable copy; modified raw samples and an
incomplete hash manifest were rejected. A complete capture failing a configured
CPU threshold remained a failing result. The 149 existing tests also passed.
Final-host policy experiments remain pending.
