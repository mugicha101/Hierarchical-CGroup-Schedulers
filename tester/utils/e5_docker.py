"""Owned Docker containers below the configured existing workload cgroup."""

import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import uuid

from . import common, lifecycle

CLIENT = Path(__file__).with_name("e5_client.py")


class Docker:
  def __init__(self, directory, timeout):
    self.directory = Path(directory)
    self.timeout = timeout
    self.history = []

  def run(self, *args):
    command = ["docker", *map(str, args)]
    record = {"command": command, "started_ns": time.monotonic_ns()}
    self.history.append(record)
    try:
      result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
      record.update(return_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
      if result.returncode:
        raise RuntimeError(f"Docker command failed; see {self.directory / 'docker-commands.json'}")
      return result.stdout.strip()
    except subprocess.TimeoutExpired:
      record["error"] = "command timed out"
      raise
    finally:
      common.write_json(self.directory / "docker-commands.json", self.history)


def parent_argument(workload, driver):
  if driver == "cgroupfs":
    return "/" + str(workload.relative_to(common.CGROUP_ROOT))
  if driver != "systemd" or not workload.name.endswith(".slice"):
    raise ValueError("Docker's systemd driver requires workload_cgroup to name an existing slice")
  parts = workload.name.removesuffix(".slice").split("-")
  expected = common.CGROUP_ROOT.joinpath(*("-".join(parts[:i]) + ".slice" for i in range(1, len(parts) + 1)))
  if workload != expected:
    raise ValueError("workload_cgroup does not match its systemd slice hierarchy")
  return workload.name


def prepare(config, directory, cases):
  workload, controller = common.placement(config, hierarchy=True)
  cpus = common.cgroup_cpus(workload)
  if len(cpus) != 1:
    raise ValueError("E5 capacity requires an existing workload cgroup confined to one logical CPU")
  if any(path.read_text().strip() for path in workload.rglob("cgroup.procs")):
    raise ValueError("E5 workload cgroup and its descendants must initially be empty")
  for parent in (workload, *workload.parents):
    if parent == common.CGROUP_ROOT:
      break
    if not (parent / "cpu.max").read_text().startswith("max "):
      raise ValueError(f"E5 capacity requires unlimited CPU quota at {parent}")
  state = lifecycle.root_state()
  if state["state"] != "disabled" or state["ops"] is not None:
    raise ValueError("E5 capacity requires the SCX root scheduler to be detached")
  docker = Docker(directory, config["process_timeout_s"])
  info = json.loads(docker.run("info", "--format", "{{json .}}"))
  if info["CgroupVersion"] != "2":
    raise ValueError("E5 requires Docker on cgroup v2")
  parent = parent_argument(workload, info["CgroupDriver"])
  services = {"nginx", *(case["database"] for case in cases)}
  settings = config["experiments"]["containers"]["e5"]
  images = {name: json.loads(docker.run("image", "inspect", settings["images"][name]))[0]
            for name in sorted(services)}
  packages = {"aiohttp"}
  packages.update({"redis": "redis", "postgres": "psycopg", "mongo": "pymongo"}[name]
                  for name in services - {"nginx"})
  report = {"workload_cgroup": str(workload), "controller_cgroup": str(controller),
            "cpu": next(iter(cpus)), "cgroup_parent": parent, "initial_scx": state,
            "docker": {key: info[key] for key in ("ServerVersion", "CgroupDriver", "CgroupVersion")},
            "images": images, "python": sys.version,
            "packages": {name: importlib.metadata.version(name) for name in sorted(packages)}}
  common.write_json(directory / "preflight.json", report)
  return report


def free_port():
  with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    return listener.getsockname()[1]


class Pair:
  def __init__(self, config, directory, database, prepared):
    self.config, self.directory, self.prepared = config, Path(directory), prepared
    self.settings = config["experiments"]["containers"]["e5"]
    self.docker = Docker(directory, config["process_timeout_s"])
    self.owner = uuid.uuid4().hex
    self.services = {name: {"service": name, "port": free_port(),
                           "name": f"cgs-e5-{self.owner}-{name}"} for name in ("nginx", database)}
    while len({item["port"] for item in self.services.values()}) != 2:
      self.services[database]["port"] = free_port()
    self.password = secrets.token_urlsafe(24)

  def client_settings(self, name):
    item = self.services[name]
    return {"service": name, "port": item["port"], "password": self.password,
            **{key: self.settings[key] for key in ("records", "payload_bytes", "response_bytes",
                "connections_per_shard", "queue_capacity", "request_timeout_s")}}

  def start(self):
    path = self.directory / "nginx.conf"
    path.write_text("worker_processes 1; error_log /dev/stderr warn; pid /tmp/nginx.pid;\n"
        "events { worker_connections 1024; }\nhttp { access_log off; keepalive_timeout 65; server { "
        f"listen 127.0.0.1:{self.services['nginx']['port']}; location / {{ return 200 \"" +
        "x" * self.settings["response_bytes"] + "\"; } } }\n")
    for name, item in self.services.items():
      memory = f"{self.settings['memory_mb'][name]}m"
      args = ["run", "-d", "--pull=never", "--name", item["name"], "--label", "cgs.e5.owner=" + self.owner,
              "--cgroup-parent", self.prepared["cgroup_parent"], "--network", "host", "--pids-limit", "256",
              "--memory", memory, "--memory-swap", memory]
      image = self.prepared["images"][name]["Id"]
      if name == "nginx":
        args += ["--mount", f"type=bind,src={path},dst=/etc/nginx/nginx.conf,readonly", image]
      elif name == "redis":
        args += [image, "redis-server", "--bind", "127.0.0.1", "--port", item["port"],
                 "--save", "", "--appendonly", "no"]
      elif name == "postgres":
        connections = self.settings["shards"] * self.settings["connections_per_shard"] + 2
        args += ["-e", "POSTGRES_USER=e5", "-e", "POSTGRES_DB=e5", "-e", "POSTGRES_PASSWORD=" + self.password,
                 image, "postgres", "-c", "listen_addresses=127.0.0.1", "-p", item["port"],
                 "-c", "shared_buffers=32MB", "-c", f"max_connections={max(32, connections)}"]
      else:
        args += [image, "mongod", "--bind_ip", "127.0.0.1", "--port", item["port"],
                 "--wiredTigerCacheSizeGB", ".25"]
      self.docker.run(*args)
    for name, item in self.services.items():
      deadline = time.monotonic() + self.config["process_timeout_s"]
      while True:
        state = json.loads(self.docker.run("inspect", "--format", "{{json .State}}", item["name"]))
        if not state["Running"]:
          raise RuntimeError(f"{name} exited during startup")
        try:
          with socket.create_connection(("127.0.0.1", item["port"]), timeout=.5):
            break
        except OSError:
          if time.monotonic() >= deadline:
            raise TimeoutError(f"{name} startup timed out")
          time.sleep(.1)
      item["pid"] = state["Pid"]
      relative = Path(f"/proc/{state['Pid']}/cgroup").read_text().strip().split("::", 1)[1].lstrip("/")
      item["cgroup"] = common.CGROUP_ROOT / relative
      if not item["cgroup"].is_relative_to(Path(self.prepared["workload_cgroup"])):
        raise ValueError(f"{name} is outside the configured workload cgroup")
      request = self.directory / f"{name}-seed.json"
      common.write_json(request, self.client_settings(name))
      command = [sys.executable, str(CLIENT), "seed", str(request)]
      common.write_json(self.directory / f"{name}-seed-command.json", command)
      with request.with_suffix(".log").open("xb") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                       timeout=self.config["process_timeout_s"], check=True)

  def placement(self):
    result = {}
    for name, item in self.services.items():
      state = json.loads(self.docker.run("inspect", "--format", "{{json .State}}", item["name"]))
      if not state["Running"] or state["OOMKilled"]:
        raise RuntimeError(f"{name} stopped or was OOM-killed")
      path = item["cgroup"]
      policies, affinities = set(), set()
      for tid in (path / "cgroup.threads").read_text().split():
        try:
          policies.add(os.sched_getscheduler(int(tid)))
          affinities.add(tuple(sorted(os.sched_getaffinity(int(tid)))))
        except ProcessLookupError:
          pass
      if policies != {os.SCHED_OTHER} or affinities != {(self.prepared["cpu"],)}:
        raise ValueError(f"{name} policy/affinity differs from the native single-CPU baseline")
      result[name] = {"cgroup": str(path), "policies": sorted(policies), "affinities": sorted(affinities),
                      "cpus": (path / "cpuset.cpus.effective").read_text().strip(),
                      "cpu_max": (path / "cpu.max").read_text().strip(),
                      "memory_events": (path / "memory.events").read_text()}
      if result[name]["cpus"] != str(self.prepared["cpu"]) or not result[name]["cpu_max"].startswith("max "):
        raise ValueError(f"{name} cpuset/quota differs from the capacity baseline")
    return result

  def close(self):
    ids = self.docker.run("ps", "-aq", "--filter", "label=cgs.e5.owner=" + self.owner).split()
    errors, log_errors = [], []
    for identity in ids:
      try:
        self.docker.run("logs", identity)
      except Exception as error:
        log_errors.append(str(error))
    try:
      if ids:
        self.docker.run("rm", "-fv", *ids)
      remaining = self.docker.run("ps", "-aq", "--filter", "label=cgs.e5.owner=" + self.owner).split()
      if remaining:
        errors.append(f"owned containers remain: {remaining}")
    except Exception as error:
      errors.append(str(error))
    common.write_json(self.directory / "cleanup.json", {"complete": not errors, "errors": errors,
                                                        "log_errors": log_errors})
    if errors:
      raise common.CleanupError("; ".join(errors))
