#!/usr/bin/env python3
"""Temporary local root access for experiment preflight and smoke checks."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
TEST_CGROUP = Path("/sys/fs/cgroup/cgs-experiments-dev")


def cgroup_command(request, created):
  targets = {"test": TEST_CGROUP, "root-control": TEST_CGROUP.parent / "cgroup.subtree_control",
             "root-mems": TEST_CGROUP.parent / "cpuset.mems.effective",
             "cpus": TEST_CGROUP / "cpuset.cpus", "mems": TEST_CGROUP / "cpuset.mems",
             "effective": TEST_CGROUP / "cpuset.cpus.effective",
             "members": TEST_CGROUP / "cgroup.procs"}
  operation, target = request["operation"], request["target"]
  path = targets[target]
  if operation == "read" and target != "test":
    return path.read_text(), created
  if operation == "mkdir" and target == "test":
    path.mkdir()
    return f"created {path}", True
  if operation == "rmdir" and target == "test" and created:
    path.rmdir()
    return f"removed {path}", False
  if operation == "write":
    value = request["value"]
    allowed = {"root-control": {"+cpuset", "-cpuset"}, "cpus": {"8-15"},
               "mems": {targets["root-mems"].read_text().strip()}}
    if target in allowed and value in allowed[target]:
      if target != "root-control" and not created:
        raise ValueError("test cgroup was not created by this session")
      path.write_text(value + "\n")
      return f"wrote {value} to {path}", created
  raise ValueError("manual cgroup operation is outside the development setup")


def receive(connection):
  data = bytearray()
  while not data.endswith(b"\n"):
    chunk = connection.recv(65536)
    if not chunk:
      raise RuntimeError("connection closed before response")
    data.extend(chunk)
    if len(data) > 4 * 1024 * 1024:
      raise ValueError("session message too large")
  return json.loads(data)


def command(request):
  action = request["action"]
  traced = request.get("traced", False)
  if type(traced) is not bool:
    raise ValueError("invalid tracing selection")
  if action == "preflight":
    args = ["preflight"]
  elif action == "smoke" and request.get("scheduler") in ("none", "jlfp", "qmap", "simple"):
    args = ["smoke", request["scheduler"]]
  else:
    raise ValueError("only status, preflight and setup smoke checks are allowed")
  if traced:
    args.append("--traced")
  if request.get("basic", False):
    if action != "smoke" or type(request["basic"]) is not bool:
      raise ValueError("basic checks apply only to setup smoke runs")
    args.append("--basic")
  return [sys.executable, str(REPO / "tester/experiments/run.py"), *args]


def serve():
  if os.geteuid() != 0 or "SUDO_UID" not in os.environ:
    raise RuntimeError("start the server with sudo from your normal user account")
  uid = int(os.environ["SUDO_UID"])
  directory = Path(f"/run/cgs-root-session-{uid}")
  directory.mkdir(mode=0o711)
  path = directory / "control.sock"
  child = None
  created_cgroup = False
  try:
    with socket.socket(socket.AF_UNIX) as listener:
      listener.bind(str(path))
      os.chown(path, uid, -1)
      os.chmod(path, 0o600)
      listener.listen(1)
      listener.settimeout(1800)
      print(f"Root session ready: {path}\nKeep this terminal open; Ctrl-C closes the session.",
            flush=True)
      while True:
        with listener.accept()[0] as peer:
          peer.settimeout(10)
          _, peer_uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET,
                                                           socket.SO_PEERCRED, 12))
          if peer_uid != uid:
            continue
          try:
            request = receive(peer)
            if request["action"] == "status":
              response = {"return_code": 0, "output": f"root session active: uid={os.geteuid()}"}
            elif request["action"] == "cgroup":
              output, created_cgroup = cgroup_command(request, created_cgroup)
              print(output, flush=True)
              response = {"return_code": 0, "output": output}
            else:
              args = command(request)
              print("Running:", " ".join(args), flush=True)
              child = subprocess.Popen(args, cwd=REPO, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, start_new_session=True)
              output, _ = child.communicate()
              response = {"return_code": child.returncode, "output": output}
              child = None
            peer.sendall((json.dumps(response) + "\n").encode())
          except (KeyError, ValueError, RuntimeError, OSError) as error:
            peer.sendall((json.dumps({"return_code": 2, "output": str(error)}) + "\n").encode())
  finally:
    if child is not None and child.poll() is None:
      os.killpg(child.pid, signal.SIGTERM)
      # the experiment runner performs bounded workload/scheduler/recorder cleanup
      child.wait()
    path.unlink(missing_ok=True)
    directory.rmdir()


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  commands = parser.add_subparsers(dest="action", required=True)
  commands.add_parser("serve")
  commands.add_parser("status")
  commands.add_parser("preflight").add_argument("--traced", action="store_true")
  smoke = commands.add_parser("smoke")
  smoke.add_argument("scheduler", choices=("none", "jlfp", "qmap", "simple"))
  smoke.add_argument("--traced", action="store_true")
  smoke.add_argument("--basic", action="store_true")
  cgroup = commands.add_parser("cgroup", help="manual development-cgroup operations only")
  cgroup.add_argument("operation", choices=("read", "write", "mkdir", "rmdir"))
  cgroup.add_argument("target", choices=("test", "root-control", "root-mems", "cpus", "mems",
                                         "effective", "members"))
  cgroup.add_argument("value", nargs="?")
  args = parser.parse_args()
  if args.action == "serve":
    serve()
    return 0
  path = f"/run/cgs-root-session-{os.getuid()}/control.sock"
  with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(3600)
    client.connect(path)
    client.sendall((json.dumps(vars(args)) + "\n").encode())
    response = receive(client)
  print(response["output"], end="\n")
  return response["return_code"]


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    raise SystemExit(130)
  except (OSError, RuntimeError, ValueError) as error:
    print(f"Root session: {error}", file=sys.stderr)
    raise SystemExit(2)
