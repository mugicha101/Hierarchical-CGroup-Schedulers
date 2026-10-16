"""Build private artifacts without loading BPF or changing existing builds."""

import difflib

from ..build_jlfp_cyclictest import guard_header
from .common import (REPO, controller_affinity, cpu_set, repository_state,
                     run_attempts, sha256, write_json)

RT_TESTS_URL = "https://git.kernel.org/pub/scm/utils/rt-tests/rt-tests.git"
RT_TESTS_REVISION = "62da2befac98f811af8e56f2b7992fb09faa33d6"


def patch_once(text, before, after):
  if text.count(before) != 1:
    raise ValueError(f"upstream cyclictest patch context changed: {before!r}")
  return text.replace(before, after, 1)


def patch_cyclictest(checkout):
  patches = []
  source = checkout / "src/cyclictest/cyclictest.c"
  original = source.read_text()
  modified = patch_once(original, "static char *policyname(int policy);",
      "#ifndef SCHED_EXT\n#define SCHED_EXT 7\n#endif\n\nstatic char *policyname(int policy);")
  context = '\telse if (strncasecmp(polname, "rr", 2) == 0)\n\t\tpolicy = SCHED_RR;\n'
  modified = patch_once(modified, context, context +
      '\telse if (strncasecmp(polname, "ext", 3) == 0)\n\t\tpolicy = SCHED_EXT;\n')
  modified = patch_once(modified, "\tcase SCHED_BATCH:\n",
      '\tcase SCHED_EXT:\n\t\tpolicystr = "ext";\n\t\tbreak;\n\tcase SCHED_BATCH:\n')
  modified = patch_once(modified, "of: other, normal, batch, idle, fifo or rr.",
                        "of: other, normal, batch, idle, fifo, rr or ext.")
  header = checkout / "src/cyclictest/rt_numa.h"
  for path, before, after in ((source, original, modified),
                              (header, header.read_text(), guard_header(header.read_text()))):
    name = str(path.relative_to(checkout))
    patches.extend(difflib.unified_diff(before.splitlines(keepends=True),
                                       after.splitlines(keepends=True),
                                       fromfile="a/" + name, tofile="b/" + name))
    path.write_text(after)
  return "".join(patches)


def build(config, target, trace="off"):
  def action(directory, processes):
    timeout = config["build_timeout_s"]
    metadata = {"target": target, "trace_profile": trace, "latency_statistics": False}

    def run(command, cwd=REPO):
      write_json(directory / "build.json", metadata)
      processes.run(command, cwd=cwd, timeout=timeout)

    if target == "worker":
      binary = directory / "jlfp_worker"
      metadata["source_sha256"] = {"tester/work.c": sha256(REPO / "tester/work.c")}
      run(["cc", "-O2", "-pthread", "-DSCHED_EXT=7", "tester/work.c", "-lbpf", "-o", binary])
    elif target == "jlfp":
      output = directory / "scheds"
      flags = {"SCXTP_TRACING": int(trace != "off"),
               "SCXTP_HOTPATH_TRACING": int(trace == "hotpath"), "SCX_LATENCY_STATS": 0}
      metadata["flags"] = flags
      watched = list((REPO / "scheds").glob("*.h")) + list((REPO / "scheds").glob("*.c"))
      watched += list((REPO / "scheds/trace").glob("*.h")) + [REPO / "scheds/Makefile"]
      metadata["source_sha256"] = {str(p.relative_to(REPO)): sha256(p) for p in watched}
      run(["make", "-C", REPO / "scheds", "-j2", f"BUILD={output}", "CLANG=clang-21",
           *(f"{key}={value}" for key, value in flags.items()), "all"])
      binary = output / "scx_jlfp"
      metadata["gedf_binary_sha256"] = sha256(output / "scx_gedf")
    elif target in ("qmap", "simple"):
      metadata["kernel_source"] = repository_state(REPO.parent)
      watched = [REPO.parent / f"scx_{target}{suffix}" for suffix in (".c", ".bpf.c")]
      metadata["source_sha256"] = {str(p): sha256(p) for p in watched}
      output = directory / "upstream"
      output.mkdir()
      run(["make", "-C", REPO.parent, "-j2", f"O={output}",
           "CLANG=clang-21", "VMLINUX_BTF=/sys/kernel/btf/vmlinux", f"scx_{target}"])
      binary = directory / f"upstream/build/bin/scx_{target}"
      # these schedulers have no project latency-statistics instrumentation
      metadata["latency_statistics"] = "not applicable"
    else:
      checkout = directory / "rt-tests"
      metadata.update(upstream=RT_TESTS_URL, revision=RT_TESTS_REVISION)
      run(["git", "clone", "--no-checkout", RT_TESTS_URL, checkout])
      run(["git", "checkout", "--detach", RT_TESTS_REVISION], cwd=checkout)
      (directory / "cyclictest.patch").write_text(patch_cyclictest(checkout))
      run(["make", "-j2", "cyclictest"], cwd=checkout)
      binary = checkout / "cyclictest"
      metadata["patched_source_sha256"] = sha256(checkout / "src/cyclictest/cyclictest.c")
    metadata.update(binary=str(binary), binary_sha256=sha256(binary))
    write_json(directory / "build.json", metadata)
    return metadata

  with controller_affinity(cpu_set(config["controller_cpus"])):
    return run_attempts(config, f"build-{target}-{trace}", action)
