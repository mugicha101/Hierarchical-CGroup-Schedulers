# Qmap verifier investigation

Investigated 2026-10-16. The observed scalar-register rejection is explained by
Clang 21.1.8's missing BPF address-space handling for memory intrinsics. This
diagnoses the first load failure; it does not establish that the whole scheduler
will load after recompilation. No production source or system setting changed.

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
Only Clang 21 is installed here. Alternatively, evaluate a documented qmap BPF
build flag `-fno-builtin-memset`; source barriers are another upstream workaround
but would edit scheduler source and are unnecessary for this investigation.

The experiment builder currently hardcodes `clang-21`; adopting a new compiler
requires an explicit build/documentation update. No such change, package install,
kernel rebuild or scheduler patch has been made. The root helper is stopped, so
neither candidate has a new live verification/attachment check. Validate a bounded
partial-switch lifecycle before calling qmap unblocked; further verifier/runtime
issues, including this PREEMPT_RT kernel's BPF timer support, remain untested.
