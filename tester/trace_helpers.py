# mostly AI written ftrace helpers for test scripts
# - TraceSession starts a private sched_manager process and accepts ftrace events.
# - call start_trace(path), load_config(config), run the test, detach_all(), then
#   stop_trace(). recording starts before attachment so initialization is saved.
# - use a context manager or close() to detach, delete owned cgroups, and finalize
#   on success or failure. __del__ is a fallback; stop test workloads before cleanup.
# - config trace flags still control scheduler emissions; no flags are overridden.
# - TraceParser reads the finalized .dat offline. analysis stays in test scripts.
# - after parsing, cleanup_trace(path) or session.cleanup_trace() deletes capture files.

from pathlib import Path
from contextlib import contextmanager
import bt2
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings

REPO_DIR = Path(__file__).resolve().parents[1]
ROOT_OPS = Path("/sys/kernel/sched_ext/root/ops")
CGROUP_ROOT = Path("/sys/fs/cgroup")
TRACE_INSTANCES = Path("/sys/kernel/tracing/instances")

@contextmanager
def defer_trace_interrupts():
  # raising from bt2 callbacks or destructors can leave native references invalid
  interrupted = False
  def interrupt(*_):
    nonlocal interrupted
    interrupted = True
  def check_interrupt():
    if interrupted:
      raise KeyboardInterrupt

  handlers = {}
  try:
    if threading.current_thread() is threading.main_thread():
      for signum in (signal.SIGINT, signal.SIGTERM):
        handler = signal.getsignal(signum)
        signal.signal(signum, interrupt)
        handlers[signum] = handler
    yield check_interrupt
    check_interrupt()
  finally:
    for signum, handler in handlers.items():
      signal.signal(signum, handler)

def _root_attached():
  try:
    ROOT_OPS.stat()
  except FileNotFoundError:
    return False
  return True

# delete a stopped capture and its recorder log / per-cpu temporary files
def cleanup_trace(trace_path):
  trace_path = Path(trace_path).absolute()
  files = [trace_path, trace_path.with_name(trace_path.name + ".log")]
  cpu_file = re.compile(re.escape(trace_path.name) + r"\.(?:scxtp-[0-9a-f]{32}\.)?cpu[0-9]+")
  if trace_path.parent.exists():
    files.extend(path for path in trace_path.parent.iterdir() if cpu_file.fullmatch(path.name))
  for path in files:
    path.unlink(missing_ok=True)

# class to manage ftrace and schedulers for a test
# uses SchedManager to setup schedulers and trace-cmd to record ftrace events
class TraceSession:
  # start scheduler manager
  def __init__(self, *, events=("scxtp:*", "bpf_trace:bpf_trace_printk"),
               scx_build_path=None, timeout=30, monitor=False):
    self._manager = None
    self._trace = None
    self._trace_log = None
    self._instance_path = None
    self._pending = b""
    self._manager_failed = False
    self._root_loaded = False
    self._closed = False
    self.manager_output = []
    self.events = (events,) if isinstance(events, str) else tuple(events)
    self.timeout = timeout
    self.trace_path = None
    self._owns_trace = False
    if not self.events or timeout <= 0:
      raise ValueError("Events must be nonempty and timeout must be positive")
    try:
      if _root_attached():
        raise RuntimeError("A root scheduler is already attached")
      build = Path(scx_build_path) if scx_build_path is not None else REPO_DIR / "scheds/build"
      self._manager = subprocess.Popen(
          [sys.executable, "-u", str(REPO_DIR / "tools/sched_manager.py"), str(build.resolve())],
          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
          bufsize=0, start_new_session=True)
      self._command("ack 1")
      self._command(f"monitor {int(monitor)}")
    except BaseException as error:
      self._close_after_error(error)
      raise

  # stop scheduler manager and cleanup
  def __del__(self):
    if not getattr(self, "_closed", True):
      try:
        self.close()
      except Exception as error:
        warnings.warn(f"TraceSession cleanup failed: {error}", ResourceWarning)

  # use the CLI's ACK/ERR responses, as cgroup_server does
  def _command(self, command):
    if self._closed or self._manager is None or self._manager_failed:
      raise RuntimeError("Scheduler manager is unavailable")
    self._manager.stdin.write((command + "\n").encode())
    self._manager.stdin.flush()
    deadline = time.monotonic() + self.timeout
    errors = []
    while True:
      if b"\n" in self._pending:
        raw, self._pending = self._pending.split(b"\n", 1)
        line = raw.decode(errors="replace").strip()
        self.manager_output.append(line)
        if "ERR:" in line:
          raise RuntimeError(line)
        if "ERROR:" in line:
          errors.append(line)
        # the CLI prompt can precede a response on the same line
        if line.endswith("ACK"):
          if errors:
            raise RuntimeError("\n".join(errors))
          return
        continue
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        self._manager_failed = True
        raise TimeoutError(f"Scheduler manager timed out: {command}")
      ready, _, _ = select.select([self._manager.stdout], [], [], remaining)
      if ready:
        chunk = os.read(self._manager.stdout.fileno(), 65536)
        if not chunk:
          self._manager_failed = True
          raise RuntimeError("Scheduler manager exited: " + "\n".join(self.manager_output))
        self._pending += chunk

  # start ftrace recording
  # should be before schedulers attached
  # store trace output in trace_path
  def start_trace(self, trace_path):
    if self._closed or self._trace is not None:
      raise RuntimeError("Session is closed or recording is already active")
    try:
      self._owns_trace = False
      self.trace_path = Path(trace_path).resolve()
      if self.trace_path.exists():
        raise FileExistsError(self.trace_path)
      self.trace_path.parent.mkdir(parents=True, exist_ok=True)
      self._trace_log = self.trace_path.with_suffix(self.trace_path.suffix + ".log").open("x")
      self._owns_trace = True
      instance = "scxtp-" + uuid.uuid4().hex
      self._instance_path = TRACE_INSTANCES / instance
      args = ["trace-cmd", "record", "-q", "-B", instance, "-C", "mono",
              "-o", str(self.trace_path)]
      for event in self.events:
        args.extend(["-e", event])
      # trace-cmd launches this command only after recording is ready
      with tempfile.TemporaryDirectory(prefix="scxtp-ready-") as directory:
        ready = Path(directory) / "ready"
        args.extend([sys.executable, "-c",
                     "import signal, sys; from pathlib import Path; "
                     "signal.signal(signal.SIGINT, lambda *_: sys.exit(0)); "
                     "Path(sys.argv[1]).touch(); signal.pause()", str(ready)])
        self._trace = subprocess.Popen(args, stdout=self._trace_log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + self.timeout
        while not ready.exists():
          if self._trace.poll() is not None:
            raise RuntimeError(f"Recorder exited; see {self._trace_log.name}")
          if time.monotonic() >= deadline:
            raise TimeoutError(f"Recorder startup timed out; see {self._trace_log.name}")
          time.sleep(0.05)
    except BaseException as error:
      self._close_after_error(error)
      raise

  # load sched_manager config
  # this attaches schedulers
  def load_config(self, config_path):
    try:
      if self._trace is None or self._trace.poll() is not None:
        raise RuntimeError("Start recording before loading scheduler config")
      config_path = Path(config_path).resolve(strict=True)
      configs = [(json.loads(config_path.read_text()), Path())]
      # the manager's failed-load rollback must not delete existing cgroups
      for config, relative in configs:
        base = (CGROUP_ROOT / relative / config.get("cgroup", "")).resolve()
        if not base.is_relative_to(CGROUP_ROOT):
          raise ValueError(f"Invalid cgroup path: {base}")
        for parent in (base, *base.parents):
          if parent == CGROUP_ROOT:
            break
          if parent.exists():
            raise FileExistsError(parent)
        for name, child in config.get("subs", {}).items():
          path = (base / name).resolve()
          if not path.is_relative_to(CGROUP_ROOT) or path == CGROUP_ROOT:
            raise ValueError(f"Invalid cgroup path: {path}")
          configs.append((child, path.relative_to(CGROUP_ROOT)))
      self._command("load_config " + shlex.quote(str(config_path)))
      self._root_loaded = configs[0][0].get("policy") in ("scx_jlfp", "scx_gedf")
    except BaseException as error:
      self._close_after_error(error)
      raise

  # detach all schedulers
  def detach_all(self):
    if not self._closed and self._manager is not None and self._manager.poll() is None:
      self._command("detach -r")
      deadline = time.monotonic() + self.timeout
      while self._root_loaded and _root_attached():
        if time.monotonic() >= deadline:
          raise TimeoutError("Root scheduler did not detach")
        time.sleep(0.05)
      self._root_loaded = False

  # interrupt owned process groups, then escalate and reap if shutdown stalls
  def _finish_process(self, process, *, interrupt=True):
    if interrupt:
      try:
        os.killpg(process.pid, signal.SIGINT)
      except ProcessLookupError:
        pass
    try:
      return process.wait(timeout=self.timeout)
    except subprocess.TimeoutExpired:
      for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
          os.killpg(process.pid, sig)
        except ProcessLookupError:
          pass
        try:
          process.wait(timeout=self.timeout)
          break
        except subprocess.TimeoutExpired:
          continue
      raise TimeoutError("Forced process shutdown; trace or cgroup cleanup may be incomplete")

  # stop trace recording
  def stop_trace(self):
    process, self._trace = self._trace, None
    errors = []
    try:
      if process is not None:
        # allow deferred BPF cleanup before trace-cmd reads kallsyms
        time.sleep(1)
        status = self._finish_process(process)
        if status != 0:
          raise RuntimeError(f"Recorder exited with status {status}; see {self._trace_log.name}")
    except Exception as error:
      errors.append(error)
    finally:
      if self._trace_log is not None:
        self._trace_log.close()
        self._trace_log = None
      if self._instance_path is not None:
        try:
          self._instance_path.rmdir()
        except FileNotFoundError:
          pass
        except OSError as error:
          errors.append(error)
        self._instance_path = None
    if errors:
      for error in errors[1:]:
        errors[0].add_note(str(error))
      raise errors[0]

  # explicitly discard capture files after recording and parsing are finished
  def cleanup_trace(self):
    if self._trace is not None:
      raise RuntimeError("Stop trace recording before deleting capture files")
    if self._owns_trace:
      cleanup_trace(self.trace_path)
      self._owns_trace = False

  def _stop_manager(self):
    if self._manager is None:
      return
    try:
      if self._manager.poll() is None:
        self._command("exit")
    finally:
      process, self._manager = self._manager, None
      try:
        status = self._finish_process(process, interrupt=self._manager_failed or process.poll() is not None)
        if status != 0:
          raise RuntimeError(f"Scheduler manager exited with status {status}")
      finally:
        process.stdin.close()
        process.stdout.close()

  def close(self):
    if self._closed:
      return
    errors = []
    for cleanup in (self.detach_all, self._stop_manager, self.stop_trace):
      try:
        cleanup()
      except Exception as error:
        errors.append(error)
    self._closed = True
    if errors:
      raise RuntimeError("Session cleanup failed: " + "; ".join(map(str, errors))) from errors[0]

  def _close_after_error(self, error):
    try:
      self.close()
    except Exception as cleanup_error:
      error.add_note(str(cleanup_error))
    if self.trace_path is not None:
      try:
        self.trace_path.with_name("scheduler.log").write_text("\n".join(self.manager_output) + "\n")
      except OSError as log_error:
        error.add_note(f"Failed to save scheduler output: {log_error}")

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    if exc_value is None:
      self.close()
    else:
      self._close_after_error(exc_value)

# class to parse ftrace output via babeltrace2
# run ./setup_bt2_ftrace.sh to build the plugin first
# plugin repo: https://github.com/siemens/bt2-ftrace-to-ctf
class TraceParser:
  # open a trace file for parsing
  def __init__(self, trace_path, *, lttng=False):
    plugin_path = Path(__file__).resolve().parent / "build/bt2-ftrace-to-ctf/build/babeltrace-plugin-ftrace.so"
    self._plugin = bt2.find_plugins_in_path(str(plugin_path), fail_on_load_error=True)[0]
    # retain native ftrace names/fields unless LTTng semantics are requested
    source = bt2.ComponentSpec(self._plugin.source_component_classes["tracedat"],
                              {"inputs": [str(Path(trace_path).resolve())], "lttng": lttng})
    self.messages = bt2.TraceCollectionMessageIterator([source])

  # read next event
  def read_event(self):
    if self.messages is None:
      raise ValueError("TraceParser is closed")
    for message in self.messages:
      if isinstance(message, bt2._EventMessageConst):
        return message
    return None

  def __iter__(self):
    return self

  def __next__(self):
    message = self.read_event()
    if message is None:
      raise StopIteration
    return message

  def close(self):
    self.messages = None
    self._plugin = None

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.close()
