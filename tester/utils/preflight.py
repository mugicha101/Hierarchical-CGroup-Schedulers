"""Read the prepared environment without changing it."""

import importlib.util
import os
from pathlib import Path
import shutil

from .common import BPF_CLANG, CGROUP_ROOT, REPO, cpu_set


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
  cpus = cpu_set(config["test_cpus"])
  try:
    online = cpu_set(Path("/sys/devices/system/cpu/online").read_text().strip())
    check("test CPUs online", cpus <= online, sorted(online))
  except (OSError, ValueError) as error:
    check("test CPUs online", False, str(error))
  check("controller affinity", os.sched_getaffinity(0) & cpu_set(config["controller_cpus"]),
        sorted(os.sched_getaffinity(0)))
  cgroup = config["workload_cgroup"]
  if cgroup is None:
    check("workload cgroup", False, "set workload_cgroup in config.json to a prepared leaf")
  else:
    cgroup = Path(cgroup)
    try:
      actual = cpu_set((cgroup / "cpuset.cpus.effective").read_text().strip())
      check("workload cpuset", actual == cpus, sorted(actual))
      controllers = (cgroup / "cgroup.subtree_control").read_text().strip()
      check("workload leaf", not controllers, controllers or "no child controllers")
      kind = (cgroup / "cgroup.type").read_text().strip()
      check("process cgroup", kind == "domain", kind)
      check("workload placement permission", os.access(cgroup / "cgroup.procs", os.W_OK),
            str(cgroup / "cgroup.procs"))
    except (OSError, ValueError) as error:
      check("workload cgroup", False, str(error))
  for name in ("user.slice", "system.slice", "machine.slice"):
    path = CGROUP_ROOT / name
    if not path.exists():
      check(name, True, "absent; no workloads in this slice")
      continue
    try:
      actual = cpu_set((path / "cpuset.cpus.effective").read_text().strip())
      check(name, actual <= cpu_set(config["controller_cpus"]), sorted(actual), required=not basic)
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
