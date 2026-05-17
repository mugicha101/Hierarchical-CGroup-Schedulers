# script to launch/manage a hierarchy of sched_ext schedulers attached to cgroups
# parses the provided config json file and launches the schedulers accordingly
# also provides a simple CLI to interact with the schedulers

import json
import argparse
import shlex
import subprocess
import signal
import sys
import cmd
import os
import traceback
import readline
import threading
import selectors
import time
from typing import Dict, Any
from pathlib import Path

SCX_BUILD_PATH = None
CGROUP_PATH = Path("/sys/fs/cgroup").resolve(strict=True)

def cgname(cgroup):
  return cgroup if cgroup is not None else "<root>"

class Scheduler:
  def __init__(self, config: Dict[str, Any]):
    self.policy = config.get("policy", None)
    self.cgroup = config.get("cgroup", None)
    self.trace_path = config.get("trace_path", None)
    self.process: subprocess.Popen = None
    self.attached = False # set to true once monitor reads ack_output

  def popen(self):
    # runs command to launch scheduler process for this cgroup, using the provided config
    # after returning, stdout is handled by a separate thread within SchedManager
    # dont need to block until thread starts, just need to ensure the process is launched with piped output
    raise NotImplementedError("launch_scheduler must be implemented by subclasses.")

  def ack_output(self):
    # string to look for in scheduler output to determine if scheduler finished attaching
    # determining whether scheduler failed is done by checking if process exits before acking
    # note: scheduler must flush output after acking
    return NotImplementedError("ack_output must be implemented by subclasses.")

  def is_running(self) -> bool:
    return self.process is not None and self.process.poll() is None
  
  def is_attached(self) -> bool:
    return self.attached and self.is_running()

  def start(self):
    if self.is_running():
      raise ValueError(f"Scheduler for cgroup {cgname(self.cgroup)} is already running.")

    if self.trace_path:
      Path(self.trace_path).parent.mkdir(parents=True, exist_ok=True)
    self.popen()
    if not self.is_running():
      raise RuntimeError(f"Failed to start scheduler for cgroup {cgname(self.cgroup)}")

  def stop(self):
    if not self.is_running():
      raise ValueError(f"Scheduler for cgroup {cgname(self.cgroup)} is not running.")
    
    self.attached = False
    self.process.terminate()
    try:
      self.process.wait(timeout=3)
    except subprocess.TimeoutExpired:
      print(f"WARNING: Scheduler for cgroup {cgname(self.cgroup)} did not terminate gracefully, killing it.")
      self.process.kill()
    self.process = None

  def __del__(self):
    if self.is_running():
      self.stop()

  def status(self):
    s = f"{self.policy} [{'ON' if self.is_attached() else 'OFF'}]"
    if self.trace_path is not None:
      s += f" [TRACE: {self.trace_path}]"
    else:
      s += " [NO TRACE]"
    return s

class ScxFP(Scheduler):
  def popen(self):
    cmd = [f"{SCX_BUILD_PATH}/bin/scx_fp"]
    if self.cgroup:
      cmd += ["-c", self.cgroup]
    if self.trace_path:
      cmd += ["-t", self.trace_path]
    self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

  def ack_output(self):
    return "Scheduler Attached"

class ScxWRR(Scheduler):
  def popen(self):
    cmd = [f"{SCX_BUILD_PATH}/bin/scx_wrr"]
    if self.cgroup:
      cmd += ["-c", self.cgroup]
    if self.trace_path:
      cmd += ["-t", self.trace_path]
    self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

  def ack_output(self):
    return "Scheduler Attached"

class ScxEAF(Scheduler):
  def popen(self):
    cmd = [f"{SCX_BUILD_PATH}/bin/scx_eaf"]
    if self.cgroup:
      cmd += ["-c", self.cgroup]
    if self.trace_path:
      cmd += ["-t", self.trace_path]
    self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

  def ack_output(self):
    return "Scheduler Attached"

POLICIES = {
  "scx_fp": ScxFP,
  "scx_wrr": ScxWRR,
  "scx_eaf": ScxEAF
}

class CgroupManager:
  def __init__(self, path: Path):
    self.subs = {} # cgroup name -> CgroupManager
    self.sched = None # attached scheduler
    self.path = path

  # add sub
  # returns sub cgroup manager
  def add_sub(self, name: str):
    path = (self.path / name).resolve(strict=False)
    if path.parent != self.path:
      raise ValueError(f"Cgroup {name} is not a direct child of the parent cgroup path {self.path}.")
    self.subs[name] = CgroupManager(path)
    return self.subs[name]

  # removes sub
  def remove_sub(self, name: str):
    if name not in self.subs:
      raise ValueError(f"Cgroup {name} is not a sub-cgroup of {self.path}.")
    if name in self.subs:
      del self.subs[name]

  # get sub, returns None if doesn't exist
  def get_sub(self, name: str):
    return self.subs.get(name, None)

  # check if exists
  # if is root, check if any attached cgroups exist
  def exists(self):
    if self.path == CGROUP_PATH:
      return any(sub.exists() for sub in self.subs.values())
    return self.path.exists()

  # create cgroup for self
  # if subtree, also creates cgroup for all in subtree
  def create(self, subtree=True):
    self.path.mkdir(exist_ok=True)
    with open(self.path / "cgroup.subtree_control", "w") as f:
      f.write("+cpu")
    if subtree:
      for sub in self.subs.values():
        sub.create(subtree=True)

  # delete cgroup for self and subs
  # if fails to delete, returns false
  # can fail if tasks still in cgroup
  def delete(self):
    if not self.path.exists():
      return True
    succ = True
    sub_names = list(self.subs.keys())
    for name in sub_names:
      try:
        self.remove_sub(name)
      except Exception as e:
        print(f"ERROR: Failed to remove sub-cgroup {name} of {self.path}: {e}")
        succ = False
    try:
      self.detach_sched()
    except Exception as e:
      print(f"ERROR: Failed to detach scheduler from cgroup {self.path}: {e}")
      succ = False
    if succ and self.path != CGROUP_PATH:
      # move tasks to parent
      for pid in self.get_tasks(scx_only=False, is_process=True):
        try:
          with open(self.path.parent / "cgroup.procs", "a") as f:
            f.write(f"{pid}\n")
        except ProcessLookupError:
          pass # process already gone
        except Exception as e:
          print(f"ERROR: Failed to move process {pid} from cgroup {self.path} to parent {self.path.parent}: {e}")

      # delete cgroup
      try:
        self.path.rmdir()
      except Exception as e:
        print(f"ERROR: Failed to delete cgroup {self.path}: {e}")
        succ = False
    return succ

  def __del__(self):
    self.delete()

  def add_task(self, tid: int, is_process=False):
    tasks_file = self.path / ("cgroup.procs" if is_process else "cgroup.threads")
    if not tasks_file.exists():
      raise ValueError(f"Cgroup {self.path} does not support adding { 'processes' if is_process else 'threads' }.")
    with open(tasks_file, "a") as f:
      f.write(f"{tid}\n")

  def get_tasks(self, scx_only=True, is_process=False):
    if is_process and scx_only:
      raise ValueError("Cannot filter for scx when looking for processes.")
    tasks_file = self.path / ("cgroup.procs" if is_process else "cgroup.threads")
    if not tasks_file.exists():
      return []
    with open(tasks_file, "r") as f:
      threads = [int(line.strip()) for line in f if line.strip().isdigit()]
    def is_scx(tid):
      try:
        return os.sched_getscheduler(tid) == getattr(os, "SCHED_EXT", 7)
      except ProcessLookupError:
        return False # thread deleted in time it took to read comm
    return [ tid for tid in threads if is_scx(tid) ] if scx_only else threads

  def get_weight(self):
    weight_file = self.path / "cpu.weight"
    if not weight_file.exists():
      return None
    with open(weight_file, "r") as f:
      return int(f.read().strip())

  def set_weight(self, weight: int):
    if not self.exists():
      raise ValueError(f"Cgroup {self.path} does not exist.")
    weight_file = self.path / "cpu.weight"
    if not weight_file.exists():
      raise ValueError(f"Cgroup {self.path} does not support cpu.weight.")
    with open(weight_file, "w") as f:
      f.write(str(weight))
    
  def subtree_status(self, indent=0):
    sched_str = self.sched.status() if self.sched else "<No Scheduler>"
    weight = self.get_weight()
    weight = f" (weight: {weight}) " if weight is not None else ""
    cgroup = self.path.relative_to(CGROUP_PATH) if self.path != CGROUP_PATH else "<root>"
    print(f"{' ' * indent}{cgroup}{weight}: {sched_str} num tasks: {len(self.get_tasks(scx_only=False, is_process=False))}")
    
    for sub in self.subs.values():
      sub.subtree_status(indent=indent+2)

  # attach scheduler to this cgroup, raises error if already attached
  def attach_sched(self, sched: Scheduler):
    if self.sched is not None:
      raise ValueError(f"Cgroup already has a scheduler attached.")
    self.sched = sched

  # detach scheduler if exists
  def detach_sched(self, recursive=False):
    if recursive:
      for sub in self.subs.values():
        sub.detach_sched(recursive=True)
    if self.sched is None:
      return
    if self.sched.is_running():
      self.sched.stop()
    self.sched = None

class SchedManager(cmd.Cmd):
  intro = "Hierarchical Cgroup sched_ext Scheduler Manager. Type help or ? to list commands.\n"
  prompt = f"{Path.cwd()} (sched_manager) "
  
  def __init__(self):
    super().__init__()
    delims = readline.get_completer_delims()
    delims = delims.replace('/', '')
    delims = delims.replace('-', '')
    readline.set_completer_delims(delims)
    self.root_cgroup = CgroupManager(CGROUP_PATH)
    self.root_cgroup.create(subtree=False)
    self.selector = selectors.DefaultSelector()
    self.print_monitor = False
    self.monitor_thread = threading.Thread(target=self.monitor_thread_func, daemon=True)
    self.monitor_thread.start()

  def monitor_thread_func(self):
    while True:
      events = self.selector.select(timeout=0.5)
      written = False
      for key, mask in events:
        pipe = key.fileobj
        sched = key.data
        while True:
          line = pipe.readline()
          if not line:
            break
        
          written = True
          if sched.is_running() and not sched.attached and sched.ack_output() in line:
            sched.attached = True
          if self.print_monitor:
            print(f"[{cgname(sched.cgroup)}]: {line}", end="", flush=False)
      if written:
        print("", end="", flush=True)

  def validate_cgroup_path(self, path: Path):
    abs_path = (CGROUP_PATH / path).resolve(strict=False)
    if not abs_path.is_relative_to(CGROUP_PATH):
      raise ValueError(f"{path} not a valid cgroup path")
    return abs_path.relative_to(CGROUP_PATH)

  # adds cgroup manager to hierarchy if doesn't exist
  # if create, also creates the cgroup(s) on the filesystem
  def add_cgroup(self, path: Path, create=False) -> CgroupManager:
    path = self.validate_cgroup_path(path)
    cgroup = self.root_cgroup
    for part in path.parts:
      if part == '..' or part == '.':
        raise ValueError(f"Invalid cgroup path: {cgroup_path}")
      sub = cgroup.get_sub(part)
      if sub is None:
        sub = cgroup.add_sub(part)
      if create:
        sub.create(subtree=False)
      cgroup = sub
    return cgroup

  # gets cgroup manager for path, returns None if doesn't exist
  def get_cgroup(self, path: Path) -> CgroupManager:
    path = self.validate_cgroup_path(path)
    cgroup = self.root_cgroup
    for part in path.parts:
      sub = cgroup.get_sub(part)
      if sub is None:
        return None
      cgroup = sub
    return cgroup

  # delete cgroup
  # return True on success, False on failure or partial deletion
  def delete_cgroup(self, path: Path):
    cgroup = self.get_cgroup(path)
    if cgroup is None:
      return True
    if cgroup.path == CGROUP_PATH:
      return cgroup.delete()
    parent = self.get_cgroup(path.parent)
    try:
      parent.remove_sub(path.name)
      return True
    except:
      return False

  # helper to parse args for CLI commands
  def parse_args(self, parser: argparse.ArgumentParser, arg: str):
    try:
      return parser.parse_args(shlex.split(arg))
    except SystemExit:
      print()
      parser.print_help()
      return None
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()
      return None

  # helper to load list of (scheduler config, relative cgroup path)
  def load_configs(self, configs, basepath: Path = Path(), force=False):
    base_cgroup = self.add_cgroup(basepath)
    success = False
    try:
      if not force:
        if base_cgroup.exists():
          raise ValueError(f"Cgroup {basepath} already exists. Use --force to overwrite.")

      for config, rel_path in configs:
        cgroup_path = basepath / rel_path
        cgroup = self.add_cgroup(cgroup_path, create=True)
        if cgroup.sched is not None:
          raise ValueError(f"Cgroup {cgroup_path} already has a scheduler attached.")
          
        config["cgroup"] = str(cgroup.path)
        policy = config.get("policy", None)
        sched = None
        match policy:
          case None:
            sched = None
          case _ if policy in POLICIES:
            sched = POLICIES[policy](config)
          case _:
            raise ValueError(f"Unsupported scheduler type: {policy}")
        if sched is None:
          return
        
        weight = config.get("weight", None)
        if weight is not None:
          cgroup.set_weight(weight)
        cgroup.attach_sched(sched)
        sched.start()
        os.set_blocking(sched.process.stdout.fileno(), False)
        self.selector.register(sched.process.stdout, selectors.EVENT_READ, data=sched)
        while sched.is_running() and not sched.is_attached():
          time.sleep(0.1)
        if not sched.is_attached():
          raise RuntimeError(f"Failed to attach scheduler for cgroup {cgname(sched.cgroup)}.")
      success = True

    finally:
      if not success:
        print("FAILED")
        base_cgroup.delete() # undo any created cgroups on failure

  def find_cgroup_completions(self, path: str):
    try:
      parent_path = self.validate_cgroup_path(Path(path) if path.endswith("/") else Path(path).parent)
      prefix = "" if path.endswith("/") else Path(path).name
      cgroup = self.get_cgroup(parent_path)
      if cgroup is None:
        return []
      return [str(parent_path / name).removeprefix("./") for name in cgroup.subs.keys() if name.startswith(prefix)]
    except Exception as e:
      print(e)
      return []

  # CLI Commands

  def do_status(self, arg):
    'List status of cgroups managed by this program.'
    parser = argparse.ArgumentParser(
      prog="ls",
      description="List cgroups.",
      add_help=True
    )
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      self.root_cgroup.subtree_status()
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def do_monitor(self, arg):
    'Toggle live output from scheduler programs.'
    parser = argparse.ArgumentParser(
      prog="monitor",
      description="Print output from scheduler programs.",
      add_help=True
    )
    parser.add_argument("value", help="1 to turn on, 0 to turn off, -1 to toggle", nargs="?", default=-1)
    args = self.args = self.parse_args(parser, arg)
    if args is None:
      return

    if args.value == "1":
      self.print_monitor = True
    elif args.value == "0":
      self.print_monitor = False
    else:
      self.print_monitor = not self.print_monitor
    print(f"Scheduler Output: {'ON' if self.print_monitor else 'OFF'}")

  def do_tasks(self, arg):
    'List tasks (sched_ext threads) in a cgroup.'
    parser = argparse.ArgumentParser(
      prog="tasks",
      description="List tasks in a cgroup.",
      add_help=True
    )
    parser.add_argument("cgroup_path", help="Path to the cgroup relative to the root cgroup.", nargs="?", default="")
    parser.add_argument("-a", "--all", help="List all threads, not just those using sched_ext.", action="store_true")
    parser.add_argument("-r", "--raw", help="Print raw status info.", action="store_true")
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      cgroup = self.get_cgroup(args.cgroup_path)
      if cgroup is None:
        print(f"ERROR: Cgroup {args.cgroup_path} does not exist.")
        return
      threads = cgroup.get_tasks(scx_only=not args.all, is_process=False)
      
      thread_info = [{} for _ in threads]
      for tid, tinfo in zip(threads, thread_info):
        tinfo['alive'] = True
        try:
          with open(f"/proc/{str(tid)}/status", 'r') as f:
            for line in f:
              # Split only on the first colon
              parts = line.split(":", 1)
              if len(parts) == 2:
                  key = parts[0].strip()
                  value = parts[1].strip()
                  tinfo[key] = value
          tinfo['Policy'] = os.sched_getscheduler(tid)
        except (FileNotFoundError, ProcessLookupError):
          tinfo["alive"] = False
          continue # thread exited
      thread_info = [tinfo for tinfo in thread_info if tinfo.get("alive", False)]
      thread_info.sort(key=lambda t: t.get("Pid", -1))
      print(f"num tasks: {len(thread_info)}")
      for tinfo in thread_info:
        if args.raw:
          print(tinfo)
        else:
          print(f"pid={tinfo.get('Tgid', -1)} tid={tinfo['Pid']} name={tinfo.get('Name', '???')} state={tinfo.get('State', '???')} policy={tinfo.get('Policy', '???')}")
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def do_move(self, arg):
    'Move a thread or process to a cgroup.'
    parser = argparse.ArgumentParser(
      prog="move",
      description="Move a thread to a cgroup.",
      add_help=True
    )
    parser.add_argument("tid", help="TID of the thread to move.")
    parser.add_argument("cgroup_path", help="Path to the cgroup relative to the root cgroup (default is root).", nargs="?", default="")
    parser.add_argument("-p", "--process", help="Indicates that the provided TID is actually a PID, and all threads in the process should be moved.", action="store_true")
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      tid = int(args.tid)
      cgroup = self.get_cgroup(args.cgroup_path)
      if cgroup is None:
        print(f"ERROR: Cgroup {args.cgroup_path} does not exist.")
        return
      cgroup.add_task(tid, is_process=args.process)
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def complete_move(self, text, line, begidx, endidx):
    args = shlex.split(line[:begidx])
    if len(args) == 1:
      return [str(tid) for tid in os.listdir("/proc") if tid.isdigit() and tid.startswith(text)]
    if len(args) == 2:
      return self.find_cgroup_completions(text)
    return []

  def do_detach(self, arg):
    'Detach a scheduler from a cgroup.'
    parser = argparse.ArgumentParser(
      prog="detach",
      description="Detach a scheduler from a cgroup.",
      add_help=True
    )
    parser.add_argument("cgroup_path", help="Path to the cgroup relative to the root cgroup.", nargs="?", default="")
    parser.add_argument("-r", "--recursive", help="Remove all sub-schedulers as well.", action="store_true")
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      cgroup = self.get_cgroup(args.cgroup_path)
      if cgroup is None:
        print(f"ERROR: Cgroup {args.cgroup_path} does not exist.")
        return
      cgroup.detach_sched(recursive=args.recursive)
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def do_delete(self, arg):
    'Delete a cgroup, its scheduler, and all sub-cgroups.'
    parser = argparse.ArgumentParser(
      prog="delete",
      description="Delete a cgroup and its scheduler.",
      add_help=True
    )
    parser.add_argument("cgroup_path", help="Path to the cgroup relative to the root cgroup (default is root).", nargs="?", default="")
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      if not self.delete_cgroup(args.cgroup_path):
        print(f"ERROR: Failed to fully delete cgroup {args.cgroup_path}. It may still exist with some threads or sub-cgroups.")
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def do_attach(self, arg):
    'Attach a sched_ext scheduler to a cgroup or as root.'
    parser = argparse.ArgumentParser(
      prog="attach",
      description="Attach a scheduler to a cgroup.",
      add_help=True
    )
    parser.add_argument("policy", help=f"Type of scheduler to add ({', '.join(POLICIES.keys())}).")
    parser.add_argument("cgroup_path", help="Path to the cgroup relative to the root cgroup (default is root).", nargs="?", default="")
    parser.add_argument("-t", "--trace_dir", help="Directory to write scheduler trace output to (default is no tracing).", default=None)
    parser.add_argument("-f", "--force", action="store_true", help="If cgroup already exists, overwrite it.")
    args = self.parse_args(parser, arg)
    if args is None:
      return
    
    try:
      config = {
        "policy": args.policy
      }
      if args.trace_dir is not None:
        config["trace_dir"] = args.trace_dir
      self.load_configs([(config, Path())], basepath=Path(args.cgroup_path), force=args.force)
    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def complete_attach(self, text, line, begidx, endidx):
    args = shlex.split(line[:begidx])
    if len(args) == 1:
      return [p for p in POLICIES.keys() if p.startswith(text)]
    if len(args) == 2:
      return self.find_cgroup_completions(text)
    return []

  def complete_detach(self, text, line, begidx, endidx):
    args = shlex.split(line[:begidx])
    if len(args) == 1:
      return self.find_cgroup_completions(text)
    return []

  def complete_delete(self, text, line, begidx, endidx):
    args = shlex.split(line[:begidx])
    if len(args) == 1:
      return self.find_cgroup_completions(text)
    return []

  def complete_tasks(self, text, line, begidx, endidx):
    args = shlex.split(line[:begidx])
    if len(args) == 1:
      return self.find_cgroup_completions(text)
    return []

  def do_load_config(self, arg):
    'Load a hierarchy of schedulers from a config JSON file.'
    parser = argparse.ArgumentParser(
      prog="load_config",
      description="Load hierarchy from a config file.",
      add_help=True
    )
    parser.add_argument("config_path", help="Path to the config JSON file")
    parser.add_argument("-r", "--relative-to", help="Load config relative to a specific cgroup path (default is root)", default="")
    parser.add_argument("-f", "--force", action="store_true", help="If cgroups already exist, overwrite them.")
    args = self.parse_args(parser, arg)
    if args is None:
      return

    try:
      basepath = Path(args.relative_to)

      args.config_path = Path(args.config_path).resolve(strict=True)
      if not args.config_path.is_file():
        print(f"ERROR: Config file {args.config_path} does not exist.")
        return
      
      with open(args.config_path, "r") as f:
        root_config = json.load(f)
      
      # get list of configs
      configs = [(root_config, Path())]
      i = 0
      while i < len(configs):
        config, rel_path = configs[i]
        i += 1
        cgroup_path = rel_path / config.get("cgroup", "")
        cgroup = self.add_cgroup(cgroup_path, create=False)
        trace = config.get("trace", False)

        # add trace path
        trace_dir = None
        if "trace_dir" in config:
          trace_dir = Path(config["trace_dir"]).expanduser().resolve(strict=False)
        if "trace_path" in config:
          del config["trace_path"]
        if trace and trace_dir is not None:
          config["trace_path"] = str((Path(trace_dir) / ("__".join(cgroup_path.parts))).with_suffix(".trace"))
        
        # add subs
        subs = config.get("subs", {})
        for name, sub_config in subs.items():
          if trace_dir is not None and trace and "trace_dir" not in sub_config:
            sub_config["trace_dir"] = str(trace_dir)
          configs.append((sub_config, cgroup_path / name))

      # load configs
      self.load_configs(configs, basepath, force=args.force)

    except Exception as e:
      print(f"ERROR: {e}")
      traceback.print_exc()

  def complete_load_config(self, text, line, begidx, endidx):
    os.path.expanduser(text)
    dirname = os.path.dirname(text)
    basename = os.path.basename(text)
    if not dirname:
      dirname = "."

    try:
      entries = os.listdir(dirname)
    except OSError:
      return []

    matches = []
    for entry in entries:
      if entry == "." or entry == "..":
        continue
      if not entry.startswith(basename):
        continue

      entry = os.path.join(dirname, entry)
      if os.path.isdir(entry):
        entry += os.path.sep
      matches.append(entry)
    return matches

  def do_exit(self, arg):
    'Exit the scheduler manager, cleaning up any created cgroups and stopping schedulers.'
    signal_handler(None, None)
    return True

def signal_handler(sig, frame):
  if sig == signal.SIGINT:
    print("\nSIGINT caught")
  print("Cleaning up cgroups and exiting...")
  try:
    if 'manager' in globals():
      manager.delete_cgroup("")
  except Exception as e:
    print(f"ERROR during cleanup: {e}")
    traceback.print_exc()
  sys.exit(0)

def main():
  parser = argparse.ArgumentParser(description="Manage sched_ext schedulers attached to cgroups.")
  parser.add_argument("scx_build_path", help="Path to the sched_ext build directory containing the scheduler binaries.")
  args = parser.parse_args()

  global SCX_BUILD_PATH
  SCX_BUILD_PATH = args.scx_build_path

  global manager
  manager = SchedManager()
  signal.signal(signal.SIGINT, signal_handler)

  try:
    manager.cmdloop()
  except KeyboardInterrupt:
    signal_handler(signal.SIGINT, None)
    for sched in scheds:
      if sched.is_running():
        try:
          print(f"Stopping scheduler for cgroup {cgname(sched.cgroup)}...")
          sched.stop()
        except Exception as e:
          print(f"ERROR: Failed to stop scheduler for cgroup {cgname(sched.cgroup)}: {e}")

if __name__ == "__main__":
  main()