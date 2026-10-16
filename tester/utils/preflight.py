"""Read the prepared environment without changing it."""

import importlib.util
import os
from pathlib import Path
import shutil

from .common import (BPF_CLANG, CGROUP_ROOT, REPO, cgroup_cpus, configured_cgroup,
                     cpu_set, current_cgroup)


def inspect(config, *, traced=False, basic=False):
  checks = []

  def check(name, ok, detail, *, required=True):
    checks.append({"name": name, "ok": bool(ok), "required": required, "detail": detail})

  for tool in ("cc", "make", BPF_CLANG, "bpftool", "git", "pkg-config", "stress-ng"):
    path = shutil.which(tool)
    check(tool, path is not None, path or "not found in PATH")
  for path in (REPO / "scheds/include/scx/common.bpf.h",
               REPO / "scheds/setup.sh",
               Path("/sys/kernel/btf/vmlinux")):
    check(str(path), path.is_file(), "required source/BTF")
  groups = {}
  for role in ("workload", "controller"):
    try:
      path = configured_cgroup(config, f"{role}_cgroup")
      groups[role] = cgroup_cpus(path)
      check(f"{role} cgroup", True, {"path": str(path), "cpus": sorted(groups[role])})
      check(f"{role} placement permission", os.access(path / "cgroup.procs", os.W_OK),
            str(path / "cgroup.procs"))
    except (OSError, ValueError) as error:
      check(f"{role} cgroup", False, str(error))
  cpus = groups.get("workload", set())
  controller_cpus = groups.get("controller", set())
  check("separate workload/controller cpusets", cpus and controller_cpus and not cpus & controller_cpus,
        "effective cpusets must be nonempty and disjoint")
  check("cyclictest CPU in workload cpuset", config["cyclictest_cpu"] in cpus, config["cyclictest_cpu"])
  try:
    online = cpu_set(Path("/sys/devices/system/cpu/online").read_text().strip())
    check("cgroup CPUs online", (cpus | controller_cpus) <= online, sorted(online))
  except (OSError, ValueError) as error:
    check("cgroup CPUs online", False, str(error))
  try:
    original = current_cgroup()
    check("controller restore permission", os.access(original / "cgroup.procs", os.W_OK), str(original))
  except (OSError, ValueError) as error:
    check("controller restore permission", False, str(error))
  for name in ("user.slice", "system.slice", "machine.slice"):
    path = CGROUP_ROOT / name
    if not path.exists():
      check(name, True, "absent; no workloads in this slice")
      continue
    try:
      actual = cpu_set((path / "cpuset.cpus.effective").read_text().strip())
      check(name, actual <= controller_cpus, sorted(actual), required=not basic)
    except (OSError, ValueError) as error:
      check(name, False, str(error), required=not basic)
  try:
    state = Path("/sys/kernel/sched_ext/state").read_text().strip()
    check("sched_ext available and detached", state == "disabled", state)
  except OSError as error:
    check("sched_ext available and detached", False, str(error))
  try:
    value = Path("/proc/sys/kernel/bpf_stats_enabled").read_text().strip()
    check("BPF runtime statistics disabled", value == "0", value)
  except OSError as error:
    check("BPF runtime statistics disabled", False, str(error))
  check("live execution privilege", os.geteuid() == 0,
        "live checks currently require root; builds and planning do not")
  frequencies = {}
  for cpu in sorted(cpus):
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    try:
      frequencies[cpu] = {name: (base / name).read_text().strip() for name in
                          ("scaling_governor", "scaling_min_freq", "scaling_max_freq")}
    except OSError as error:
      frequencies[cpu] = {"error": str(error)}
  check("frequency snapshot", True, frequencies, required=False)
  if traced:
    check("trace-cmd", shutil.which("trace-cmd"), "required for traced cases")
    check("bt2", importlib.util.find_spec("bt2") is not None, "offline trace parser")
    plugin = REPO / "tester/build/bt2-ftrace-to-ctf/build/babeltrace-plugin-ftrace.so"
    check("ftrace plugin", plugin.is_file(), str(plugin))
    path = Path("/sys/kernel/tracing/instances")
    check("private tracing permission", os.access(path, os.W_OK | os.X_OK), str(path))
    check("scxtp module", Path("/sys/kernel/btf/scxtp").exists(),
          "required for custom emissions; class-only captures do not need it",
          required=False)
  return {"ok": all(c["ok"] for c in checks if c["required"]), "checks": checks,
          "kernel": os.uname().release, "changes_applied": False,
          "housekeeping_isolation_required": not basic}
