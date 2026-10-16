#!/usr/bin/env python3
"""Manually enable or restore driver/noise isolation; never change cgroups or cpusets."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common
from tester.utils.trace_helpers import defer_trace_interrupts

STATE = Path("/run/cgs-tester-isolation.json")
SCHED_DEBUG = Path("/sys/kernel/debug/sched")
SYS_NET = Path("/sys/class/net")
SYS_MODULE = Path("/sys/module")
SERVERS = ("fair_server", "ext_server")


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
    raise RuntimeError(f"Wi-Fi command {' '.join(command)} failed: {detail.strip()}") from error
  return result.stdout.strip()


def enable(cpus):
  if STATE.exists():
    raise FileExistsError(f"isolation state already exists: {STATE}; restore it first")
  devices = wifi_devices()
  if any(device["module"] is None for device in devices):
    raise RuntimeError("a Wi-Fi interface has no removable driver module")
  modules = sorted({device["module"] for device in devices})
  if any(not (SYS_MODULE / module).exists() for module in modules):
    raise RuntimeError("a Wi-Fi module disappeared before isolation")
  radio = wifi_command(["nmcli", "-t", "radio", "wifi"]) if devices else None
  if radio is not None and radio not in ("enabled", "disabled"):
    raise RuntimeError(f"unknown Wi-Fi radio state: {radio!r}")
  state = {"cpus": sorted(cpus), "devices": devices, "modules": modules, "radio": radio,
           "bandwidth": {str(cpu): {server: (SCHED_DEBUG / server / f"cpu{cpu}" / "runtime").read_text()
                                      for server in SERVERS} for cpu in sorted(cpus)}}
  # save all originals before the first host change; refuse to overwrite a pending restore
  with STATE.open("x") as output:
    os.fchmod(output.fileno(), 0o600)
    json.dump(state, output, indent=2)
    output.write("\n")
  try:
    with defer_trace_interrupts():
      if devices:
        wifi_command(["nmcli", "radio", "wifi", "off"])
        if wifi_command(["nmcli", "-t", "radio", "wifi"]) != "disabled":
          raise RuntimeError("Wi-Fi radio did not disable")
      for module in modules:
        wifi_command(["rmmod", module])
        if (SYS_MODULE / module).exists():
          raise RuntimeError(f"Wi-Fi driver {module} did not unload")
      for cpu, servers in state["bandwidth"].items():
        for server, saved in servers.items():
          path = SCHED_DEBUG / server / f"cpu{cpu}" / "runtime"
          if int(saved):
            path.write_text("0\n")
          if int(path.read_text()) != 0:
            raise RuntimeError(f"bandwidth runtime did not disable: {path}")
  except BaseException:
    disable()
    raise


def disable():
  state = json.loads(STATE.read_text())
  errors = []
  with defer_trace_interrupts():
    for cpu, servers in state["bandwidth"].items():
      for server in SERVERS:
        try:
          saved = servers[server]
          path = SCHED_DEBUG / server / f"cpu{int(cpu)}" / "runtime"
          if int(saved):
            path.write_text(saved)
          if int(path.read_text()) != int(saved):
            raise RuntimeError(f"bandwidth runtime did not restore: {path}")
        except (OSError, ValueError, RuntimeError) as error:
          errors.append(str(error))
    for module in state["modules"]:
      try:
        if not (SYS_MODULE / module).exists():
          wifi_command(["modprobe", module])
        if not (SYS_MODULE / module).exists():
          raise RuntimeError(f"Wi-Fi driver {module} did not reload")
      except (OSError, RuntimeError) as error:
        errors.append(str(error))
    if state["radio"] is not None:
      try:
        wifi_command(["nmcli", "radio", "wifi", "on" if state["radio"] == "enabled" else "off"])
        if wifi_command(["nmcli", "-t", "radio", "wifi"]) != state["radio"]:
          raise RuntimeError("Wi-Fi radio state did not restore")
      except (OSError, RuntimeError) as error:
        errors.append(str(error))
    pending = {device["interface"] for device in state["devices"]}
    deadline = time.monotonic() + 5
    while pending:
      pending = {name for name in pending if not (SYS_NET / name).exists()}
      if not pending or time.monotonic() >= deadline:
        break
      time.sleep(.05)
    if pending:
      errors.append("Wi-Fi interfaces did not return: " + ", ".join(sorted(pending)))
    if errors:
      raise RuntimeError(f"restore incomplete; state retained at {STATE}: " + "; ".join(errors))
    STATE.unlink()


def main():
  args = arguments.parse_isolation(__doc__)
  try:
    if args.command == "status":
      print(STATE.read_text() if STATE.exists() else "manual isolation is not enabled")
      return 0
    if os.geteuid() != 0:
      raise PermissionError("root is required for Wi-Fi driver and bandwidth runtime changes")
    if args.command == "enable":
      config = common.load_config(args.config)
      cgroup = common.workload_cgroup(config, leaf=False)
      enable(common.cgroup_cpus(cgroup))
      print(f"Manual noise isolation enabled; restore with {sys.executable} {Path(__file__).resolve()} disable")
    else:
      disable()
      print("Original driver, radio and bandwidth runtimes restored")
    return 0
  except (OSError, ValueError, RuntimeError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
