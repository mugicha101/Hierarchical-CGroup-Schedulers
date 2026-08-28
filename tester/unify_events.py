# script to unify the event sources of running sched_ext tasks into a single stream of events
# must run before the scheduler is attached
# will exit when the root scheduler is detached

# event sources:
#  - kernel sched_switch events during runtime using lttng + babeltrace
#  - userspace BPF_MAP_UPDATE_ELEM syscalls to task_weights map (only captures which thread called it, actual weight must be derived from trace output)
#  - trace output from the userspace schedulers (captures low-frequency scx events)

from collections import deque
from email import parser
import re
import bt2
import os
import sched
import signal
import socket
import subprocess
import sys
import time
import argparse
from pathlib import Path

TRACE_PATH = "/sys/kernel/tracing"
TASK_WEIGHTS_MAP = "/sys/fs/bpf/task_weights"
ROOT_OPS = Path("/sys/kernel/sched_ext/root/ops")
SESSION_NAME = "scx_events"
BPF_MAP_UPDATE_ELEM_CMD = 2
POLL_PERIOD_S = 0.5
SCX_TRACE_RE = re.compile(
    r"^\[(?P<cgroup>[^\]]+)\]\s+"
    r"\[t=(?P<ts>\d+):cid=(?P<cid>\d+)\]\s+"
    r"(?P<type>[^:\s]+):"
    r"(?:\s+(?P<fields>.*))?$"
)
input_args = None

def cmd(*args, check=True):
    if input_args.verbose:
        print("cmd:", *args)
    p = subprocess.run(args, text=True, capture_output=True)
    if input_args.verbose:
        print("return code:", p.returncode, flush=True)
        if p.stdout:
            print("stdout:", p.stdout, flush=True)
        if p.stderr:
            print("stderr:", p.stderr, flush=True)
    if check and p.returncode:
        err = f"command failed: {' '.join(args)}\n{p.stderr}"
        print(err, flush=True)
        raise RuntimeError(err)
    return p

def pkill(name):
    cmd("pkill", name, check=False)
    while True:
        time.sleep(POLL_PERIOD_S)
        p = cmd("pgrep", "-x", name, check=False)
        if p.returncode != 0:
            return

def check_root_sched():
    try:
        return ROOT_OPS.read_text().strip()
    except FileNotFoundError:
        return None

class Event:
    def __init__(self, ts, name, data):
        self.ts = ts
        self.name = name
        self.data = data

class SourceStream:
    def __init__(self):
        self.pending = deque()

    def poll(self):
        raise NotImplementedError("poll() must be implemented by subclasses")

    def front_ts(self) -> int:
        if len(self.pending) == 0:
            return None
        return self.pending[0].ts

class BTStream(SourceStream):
    def __init__(self):
        super().__init__()
        url = f"net://localhost/host/{socket.gethostname()}/{SESSION_NAME}"
        spec = bt2.ComponentSpec.from_named_plugin_and_component_class(
            "ctf",
            "lttng-live",
            {
                "inputs": [url],
                "session-not-found-action": "continue",
            },
        )
        self.bt = bt2.TraceCollectionMessageIterator(spec)

    def handle_msg(self, msg):
        if not isinstance(msg, bt2._EventMessageConst):
            return

        event = msg.event
        output = {}
        match event.name:
            case "sched_switch":
                data = event.payload_field
                output = {
                    "cpu_id": int(event["cpu_id"]),
                    "prev_tid": int(data["prev_tid"]),
                    "next_tid": int(data["next_tid"]),
                    "prev_comm": str(data["prev_comm"]),
                    "next_comm": str(data["next_comm"])
                }
            case "syscall_entry_bpf":
                data = event.payload_field
                if int(data["cmd"]) != BPF_MAP_UPDATE_ELEM_CMD:
                    return

                ctx = event.common_context_field
                output = {
                    "pid": int(ctx["pid"]),
                    "tid": int(ctx["tid"])
                }
            case "syscall_entry_sched_setscheduler":
                ctx = event.common_context_field
                data = event.payload_field
                output = {
                    "pid": int(ctx["pid"]),
                    "tid": int(ctx["tid"]),
                    "target_tid": int(data["pid"]),
                    "policy": int(data["policy"])
                }
            case _:
                return
        self.pending.append(Event(msg.default_clock_snapshot.ns_from_origin, event.name, output))

    def poll(self):
        try:
            for msg in self.bt:
                self.handle_msg(msg)
        except bt2.TryAgain:
            pass

class TraceStream(SourceStream):
    def __init__(self, path: Path):
        super().__init__()
        self.stream = path.open("r")
        self.start_time = 0

    def __del__(self):
        self.stream.close()

    def handle_line(self, line):
        line = line.strip()
        if line.startswith("start time:"):
            self.start_time = int(line.split(":")[-1])
            return
        
        match = SCX_TRACE_RE.match()
        if not match:
            return
        
        fields = {}
        fields_str = match.group("fields")
        if fields_str:
            for item in fields_str.split():
                if "=" not in item:
                    return
                key, value = item.split("=", 1)
                try:
                    value = int(value, 0)
                except ValueError:
                    pass
                fields[key] = value
        self.ts = int(self.start_time + match.group("ts"))
        self.name = match.group("type")
        self.data = {
            "cgroup": match.group("cgroup"),
            "cid": int(match.group("cid")),
            **fields
        }

    def poll(self):
        while True:
            line = self.stream.readline()
            if not line:
                break

            self.handle_line(line)

class EventRecorder:
    def __init__(self):
        self.active = False
        self.err = ""
        self.bt = None
        self.streams = None
        self.output = None

    def __del__(self):
        self.stop()

    def start(self):
        if self.active:
           return
        self.active = True
        
        # cleanup daemons in case of lttng crash
        print("Killing LTTNG daemons...")
        pkill("lttng-sessiond")
        pkill("lttng-relayd")

        # setup lttng
        print(f"creating live LTTNG session: {SESSION_NAME}")
        cmd("lttng-relayd", "--daemonize",
            "--control-port=tcp://127.0.0.1:5342",
            "--data-port=tcp://127.0.0.1:5343",
            "--live-port=tcp://127.0.0.1:5344"
        )
        cmd("lttng", "create", SESSION_NAME, "--live=100000", "--set-url=net://127.0.0.1")
        cmd("lttng", "enable-event", "--kernel", "sched_switch",
            "--session", SESSION_NAME
        )
        cmd("lttng", "enable-event", "--kernel", "--syscall", "bpf",
            "--session", SESSION_NAME
        )
        cmd("lttng", "enable-event", "--kernel", "--syscall", "sched_setscheduler",
            "--session", SESSION_NAME
        )
        cmd("lttng", "add-context", "--kernel", "--session", SESSION_NAME, "--type=tid", "--type=pid", "--type=procname")

        # setup input streams
        self.streams = [BTStream(), *[TraceStream(path) for path in input_args.trace_files]]

        # start lttng
        cmd("lttng", "start", SESSION_NAME)

    def stop(self):
        if not self.active:
           return

        if self.streams:
            self.update(final=True)
            self.streams = None
        
        # stop lttng
        cmd("lttng", "stop", SESSION_NAME, check=False)
        cmd("lttng", "destroy", SESSION_NAME, check=False)

        self.bt = None
        self.active = False

    def update(self, final=False):
        for stream in self.streams:
            stream.poll()

    def run(self):
        # setup
        self.start()

        # wait for root to attach
        root_sched = None
        self.pending = deque()
        print("waiting for root...")
        while root_sched is None:
            self.update()
            time.sleep(POLL_PERIOD_S)
            root_sched = check_root_sched()
            if input_args.verbose:
                print("waiting for root...")
        print(f"root scx scheduler attached: {root_sched}")

        while check_root_sched() is not None:
            self.update()
            time.sleep(POLL_PERIOD_S)

        print("root scx scheduler detached, exiting")

        # cleanup
        self.stop()
        
recorder = None
def signal_handler(sig, frame):
    print("Interrupt detected, exiting gracefully", flush=True)
    if recorder:
        recorder.stop()
    sys.exit(0)

def main():
    global input_args, recorder

    if os.geteuid() != 0:
        print("This script must be run with sudo/root.")
        return

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose output",
    )
    parser.add_argument(
        "-c",
        "--cpu",
        type=int,
        default=None,
        help="pin recorder process to this CPU",
    )
    parser.add_argument(
        "trace_files",
        nargs="*",
        type=Path,
        help="one or more scheduler trace files",
    )
    input_args = parser.parse_args()
    if input_args.cpu is not None:
        os.sched_setaffinity(0, {input_args.cpu})
        print(f"pinned process to cpu {input_args.cpu}")
    
    recorder = EventRecorder()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        recorder.run()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        recorder.stop()
        return 0 if len(recorder.err) == 0 else -1

if __name__ == "__main__":
    main()