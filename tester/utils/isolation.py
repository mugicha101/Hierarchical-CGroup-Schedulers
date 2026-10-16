"""Optional controller, background-task and bandwidth isolation with restoration."""

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import subprocess
import time

from . import common
from .trace_helpers import CGROUP_ROOT, defer_trace_interrupts

PF_KTHREAD = 0x00200000
SCHED_DEBUG = Path("/sys/kernel/debug/sched")
SYS_NET = Path("/sys/class/net")
SYS_MODULE = Path("/sys/module")


@contextmanager
def controller_affinity(worker_cpus):
  original = os.sched_getaffinity(0)
  reserved = original - set(worker_cpus)
  if not reserved:
    raise RuntimeError("At least one CPU outside the worker shard is required for the controller")
  os.sched_setaffinity(0, reserved)
  try:
    yield
  finally:
    os.sched_setaffinity(0, original)


@contextmanager
def isolated_root_tasks(state_path):
  with temporary_wifi_isolation(state_path.with_name("wifi_isolation.json")):
    with _isolated_root_tasks(state_path) as state:
      yield state


def wifi_devices():
  devices = []
  for interface in sorted(SYS_NET.iterdir()):
    if not (interface / "wireless").is_dir() and not (interface / "phy80211").exists():
      continue
    candidates = (interface / "device/driver/module", interface / "phy80211/device/driver/module")
    module = next((path.resolve().name for path in candidates if path.exists()), None)
    devices.append({"interface": interface.name, "module": module})
  return devices


def wifi_command(command):
  try:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30,
                            env={**os.environ, "LC_ALL": "C"})
  except (OSError, subprocess.SubprocessError) as error:
    detail = getattr(error, "stderr", None) or str(error)
    raise RuntimeError(f"Wi-Fi isolation command {' '.join(command)} failed: {detail.strip()}") from error
  return result.stdout.strip()


@contextmanager
def temporary_wifi_isolation(state_path):
  devices = wifi_devices()
  modules = sorted({device["module"] for device in devices if device["module"] is not None})
  state = {"enabled": bool(devices), "interfaces": devices, "original_radio": None,
           "current_radio": None, "radio_restored": None, "removed_modules": [],
           "modules": {module: {"original_loaded": (SYS_MODULE / module).exists(),
                                 "current_loaded": (SYS_MODULE / module).exists(), "restored": False}
                       for module in modules},
           "setup_complete": False, "cleanup_complete": False, "restored": False}
  state_path.write_text(json.dumps(state, indent=2) + "\n")
  radio_touched = False
  try:
    if devices:
      if os.geteuid() != 0:
        raise PermissionError("root is required to isolate Wi-Fi")
      unsupported = [device["interface"] for device in devices if device["module"] is None]
      if unsupported:
        raise RuntimeError("Cannot isolate Wi-Fi: no removable driver module for " +
                           ", ".join(unsupported) + " (built-in or unmanaged driver)")
      original = wifi_command(["nmcli", "-t", "radio", "wifi"])
      if original not in ("enabled", "disabled"):
        raise RuntimeError(f"Cannot determine NetworkManager Wi-Fi radio state: {original!r}")
      state["original_radio"] = state["current_radio"] = original
      state_path.write_text(json.dumps(state, indent=2) + "\n")
      common.report_progress("Disabling Wi-Fi and unloading driver modules: " + ", ".join(modules) + "...")
      with defer_trace_interrupts():
        radio_touched = True
        wifi_command(["nmcli", "radio", "wifi", "off"])
        state["current_radio"] = wifi_command(["nmcli", "-t", "radio", "wifi"])
        if state["current_radio"] != "disabled":
          raise RuntimeError("Wi-Fi radio did not disable")
        for module in modules:
          if not state["modules"][module]["original_loaded"]:
            raise RuntimeError(f"Wi-Fi driver module {module} disappeared before isolation")
          try:
            wifi_command(["rmmod", module])
          finally:
            loaded = (SYS_MODULE / module).exists()
            state["modules"][module]["current_loaded"] = loaded
            if not loaded:
              state["removed_modules"].append(module)
          if loaded:
            raise RuntimeError(f"Wi-Fi driver module {module} did not unload")
          state_path.write_text(json.dumps(state, indent=2) + "\n")
    state["setup_complete"] = True
    state_path.write_text(json.dumps(state, indent=2) + "\n")
    yield state
  except BaseException as error:
    state["error"] = str(error) or type(error).__name__
    raise
  finally:
    with defer_trace_interrupts():
      errors = []
      if radio_touched:
        common.report_progress("Restoring Wi-Fi driver modules and radio state...")
      for module in reversed(state["removed_modules"]):
        try:
          wifi_command(["modprobe", module])
          if not (SYS_MODULE / module).exists():
            raise RuntimeError(f"Wi-Fi driver module {module} did not reload")
        except (OSError, RuntimeError) as error:
          errors.append(str(error))
      for module, saved in state["modules"].items():
        saved["current_loaded"] = (SYS_MODULE / module).exists()
        saved["restored"] = saved["current_loaded"] == saved["original_loaded"]
      if radio_touched:
        try:
          wifi_command(["nmcli", "radio", "wifi", "on" if state["original_radio"] == "enabled" else "off"])
          state["current_radio"] = wifi_command(["nmcli", "-t", "radio", "wifi"])
          state["radio_restored"] = state["current_radio"] == state["original_radio"]
          if not state["radio_restored"]:
            raise RuntimeError("Wi-Fi radio state did not restore")
        except (OSError, RuntimeError) as error:
          errors.append(str(error))
      pending = {device["interface"] for device in devices
                 if device["module"] in state["removed_modules"]}
      deadline = time.monotonic() + 5
      while pending:
        pending = {name for name in pending if not (SYS_NET / name).exists()}
        if not pending or time.monotonic() >= deadline:
          break
        time.sleep(.05)
      state["interfaces_restored"] = not pending
      if pending:
        errors.append("Wi-Fi interfaces did not reappear: " + ", ".join(sorted(pending)))
      state["cleanup_complete"] = True
      state["restored"] = all(saved["restored"] for saved in state["modules"].values()) and \
          (not radio_touched or state["radio_restored"] is True) and state["interfaces_restored"]
      if errors:
        state["cleanup_errors"] = errors
      try:
        state_path.write_text(json.dumps(state, indent=2) + "\n")
      except OSError as error:
        errors.append(f"Failed to save Wi-Fi restoration state: {error}")
      if errors:
        raise RuntimeError("Failed to restore Wi-Fi isolation: " + "; ".join(errors))


@contextmanager
def _isolated_root_tasks(state_path):
  root_procs = CGROUP_ROOT / "cgroup.procs"
  other = CGROUP_ROOT / "other"
  other_procs = other / "cgroup.procs"
  state = {"other_cpus": (other / "cpuset.cpus").read_text().strip(),
           "moved_pids": [], "skipped_kernel_pids": []}
  state_path.write_text(json.dumps(state, indent=2) + "\n")
  skip = {0, 1, os.getpid()}
  try:
    common.report_progress(f"Moving root processes to other on CPUs {state['other_cpus']}...")
    with defer_trace_interrupts():
      while True:
        moved = 0
        for pid in map(int, root_procs.read_text().split()):
          if pid in skip:
            continue
          try:
            # leave kernel threads in root, including those bound to worker CPUs
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[6]) & PF_KTHREAD:
              skip.add(pid)
              state["skipped_kernel_pids"].append(pid)
              continue
            other_procs.write_text(f"{pid}\n")
          except OSError as error:
            if error.errno in (errno.ESRCH, errno.ENOENT):
              continue
            raise
          moved += 1
          state["moved_pids"].append(pid)
        if not moved:
          break
      state_path.write_text(json.dumps(state, indent=2) + "\n")
    yield state
  finally:
    with defer_trace_interrupts():
      common.report_progress("Returning processes from other to root...")
      errors = []
      failed = set()
      while True:
        moved = 0
        for pid in map(int, other_procs.read_text().split()):
          if pid <= 1 or pid in failed:
            continue
          try:
            root_procs.write_text(f"{pid}\n")
          except OSError as error:
            if error.errno not in (errno.ESRCH, errno.ENOENT):
              failed.add(pid)
              errors.append(f"PID {pid}: {error}")
            continue
          moved += 1
        if not moved:
          break
      state_path.write_text(json.dumps(state, indent=2) + "\n")
      if errors:
        raise RuntimeError("Failed to restore root processes: " + "; ".join(errors))


@contextmanager
def disabled_bandwidth_servers(cpus, state_path):
  saved = {}
  state = {"disabled": True, "cpus": sorted(cpus), "original": {}}
  for server in ("fair_server", "ext_server"):
    state["original"][server] = {}
    for cpu in sorted(cpus):
      path = SCHED_DEBUG / server / f"cpu{cpu}" / "runtime"
      saved[path] = path.read_text()
      state["original"][server][str(cpu)] = {
          "runtime_ns": int(saved[path]),
          "period_ns": int(path.with_name("period").read_text()),
      }
  # retain the originals even if setup fails before run.json is written
  state_path.write_text(json.dumps(state, indent=2) + "\n")
  changed = []
  try:
    common.report_progress(f"Disabling FAIR and SCX bandwidth servers on CPUs {sorted(cpus)}...")
    with defer_trace_interrupts():
      for path, runtime in saved.items():
        if int(runtime):
          changed.append(path)
          path.write_text("0\n")
        if int(path.read_text()) != 0:
          raise RuntimeError(f"Bandwidth server did not disable: {path}")
    yield state
  finally:
    # a second interrupt must not skip restoration of the remaining CPUs
    with defer_trace_interrupts():
      common.report_progress("Restoring bandwidth server runtimes...")
      errors = []
      for path in changed:
        try:
          path.write_text(saved[path])
          if int(path.read_text()) != int(saved[path]):
            raise RuntimeError("runtime did not restore")
        except (OSError, ValueError, RuntimeError) as error:
          errors.append(f"{path}: {error}")
      if errors:
        raise RuntimeError("Failed to restore bandwidth servers: " + "; ".join(errors))
