# Qmap verifier investigation

Investigated 2026-10-16. The observed scalar-register rejection is explained by
Clang 21.1.8's missing BPF address-space handling for memory intrinsics. This
diagnoses the first load failure; it does not establish that the whole scheduler
will load after recompilation. The investigation initially changed no production
source or system setting; the subsequent compiler update is recorded below.

## Evidence

- Failed attempt: `tester/build/experiments/smoke-qmap-20261016T053401*/attempt-01/`.
  The verifier rejects `qmap_dequeue` at parent `scx_qmap.bpf.c:341`:
  `R7 invalid mem access 'scalar'`.
- An unprivileged recompile of unchanged qmap using the existing generated
  headers and original BPF flags reproduces that function's disassembly exactly.
  Parent source SHA256 remains
  `6f315fa439bf425c77ce379d29202192893ab7ca862edb8caca543979ed63acd`.
- The three adjacent NULL assignments to `q_next`, `q_prev` and `fifo` become
  `llvm.memset.p1.i64(..., 0, 24, false)`. LLVM's address-space pass in 21.1.8
  handles loads/stores/atomics but skips this intrinsic. Later expansion emits
  stores through uncast R7, although earlier arena reads use cast pointer R8.
- The original IR has arena memory intrinsics in `qmap_dequeue`, `qmap_dispatch`
  and `qmap_init_task`. Adding only `-fno-builtin-memset` removes all three;
  dequeue's zero stores now use an arena-cast register. The BPF object, stable
  linked objects, generated skeleton and native loader all build successfully.
- `qmap_arena_zero.c` reproduces the same failure mechanism without qmap,
  kernel headers, BPF loading or privileges. Default compilation emits arena
  reads through a cast pointer and zero stores through the original scalar;
  the flag makes those stores use a cast pointer too.

## Upstream confirmation

[LLVM PR #160025](https://github.com/llvm/llvm-project/pull/160025), merged as
`94f290fffd80bd7c7d65db1df78cdacab633aab4`, fixes BPF address-space handling for
memset/memcpy/memmove intrinsics. Its description links the same failure pattern
in a Linux arena selftest. The fix is absent from
[LLVM 21.1.8](https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/lib/Target/BPF/BPFCheckAndAdjustIR.cpp)
and present in
[LLVM 22.1.0](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.0/llvm/lib/Target/BPF/BPFCheckAndAdjustIR.cpp).

This supports a compiler diagnosis for the observed rejection, rather than an
outdated kernel verifier. It does not justify relaxing verifier checks.

## Reproduce the compiler issue

Run from the cgs repository root; these commands only write assembly artifacts:

```sh
clang-21 -O2 -target bpf -mcpu=v3 -S tester/codex/qmap_arena_zero.c -o tester/build/qmap-arena-default.s
clang-21 -O2 -target bpf -mcpu=v3 -fno-builtin-memset -S tester/codex/qmap_arena_zero.c -o tester/build/qmap-arena-workaround.s
```

The saved full-qmap comparison is under
`tester/build/experiments/qmap-investigation-20261016T054536Z/`: compiler arguments,
IR, dequeue disassemblies, upstream source snapshots and PR metadata. The private
candidate loader is `flag-workaround-build/scx_qmap`; `commands.json` and
`result.json` there retain build commands/hashes and explicitly say it was not
loaded or attached. Diagnostic builds reuse the previous private libbpf/headers.

## Recommended next action

Prefer a compiler containing the upstream fix (verified in the 22.1.0 source),
and record/use the selected toolchain consistently across scheduler comparisons.
The initial investigation had only Clang 21 installed. Alternatively, evaluate a qmap BPF
build flag `-fno-builtin-memset`; source barriers are another upstream workaround
but would edit scheduler source and are unnecessary for this investigation.

The initial builder hardcoded `clang-21`. The private flag-workaround binary has
not been loaded. Further verifier/runtime issues must be checked before calling
qmap unblocked; no scheduler or kernel patch is part of the compiler fix.

## Compiler update and next rejection (2026-10-16)

At the user's request, installed Ubuntu Clang 22.1.2 through the restricted root
helper's fixed `install-clang` action. Apt added clang-22 and six dependencies,
without upgrades or removals. The experiment builder/preflight and local scheduler
Makefile now select clang-22; manifests record compiler path/version. The original
Clang 21 installation remains available, and no global compiler alternatives changed.

The minimal reproducer emits cast-based arena stores with Clang 22 and no extra
flags. Private qmap/simple and JLFP/GEDF off/hotpath builds pass. JLFP trace-free
and simple traced live setup checks pass; the simple capture parses with zero
reported loss. A real partial-switch qmap
attempt gets past the scalar-store rejection but fails in `qmap_init_cids`:

```text
R1 arena pointer requires a program with an associated arena
processed 0 insns
```

All three attempts fail before attachment and clean up completely. Artifacts:
`tester/build/experiments/smoke-qmap-20261016T055446.940502Z-79350320/`;
build: `build-qmap-off-20261016T055431.151175Z-639fa52a/`.

Unlike several other qmap callbacks, `qmap_init_cids` contains no reference to
the arena map (confirmed by its object relocations). The existing
`QMAP_TOUCH_ARENA()` helper documents precisely this association requirement.
Adding an arena reference there is a focused candidate for separate scheduler
review; it has not been applied or tested. Later failures, including PREEMPT_RT
BPF timer support, can still be masked by this rejection. Kernel and scheduler
sources remain unchanged.
The user requested keeping the development cgroup for subsequent checks. It is
retained empty at `/sys/fs/cgroup/cgs-experiments-dev`, effective CPUs 8-15,
memory node 0; root's cpuset controller remains enabled. EXT is disabled and
`workload_cgroup` is restored to null for final-host configuration.
