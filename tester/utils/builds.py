"""Build private artifacts without loading BPF or changing existing builds."""

import difflib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import subprocess
import sys

from .common import (BPF_CLANG, REPO, CleanupError, controller_placement, new_run,
                     repository_state, run_attempts, sha256, write_json)

RT_TESTS_URL = "https://git.kernel.org/pub/scm/utils/rt-tests/rt-tests.git"
RT_TESTS_REVISION = "62da2befac98f811af8e56f2b7992fb09faa33d6"


def linux_pin():
  script = (REPO / "scheds/setup.sh").read_text()
  values = {}
  for key in ("REPO", "REF"):
    match = re.search(rf"^LINUX_{key}=(.+)$", script, re.MULTILINE)
    words = shlex.split(match[1]) if match else []
    if len(words) != 1:
      raise ValueError(f"scheds/setup.sh must define a literal LINUX_{key}")
    values[key.lower()] = words[0]
  return values


def checkout_linux(path, pin, run):
  run(["git", "-c", "init.defaultBranch=main", "init", path])
  run(["git", "remote", "add", "origin", pin["repo"]], cwd=path)
  run(["git", "sparse-checkout", "init", "--cone"], cwd=path)
  run(["git", "sparse-checkout", "set", "tools/sched_ext", "tools/build", "tools/scripts",
       "tools/include", "tools/lib", "tools/bpf/bpftool", "tools/arch", "include", "scripts",
       "kernel/bpf"], cwd=path)
  run(["git", "fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin", pin["ref"]],
      cwd=path)
  run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=path)


def patch_once(text, before, after):
  if text.count(before) != 1:
    raise ValueError(f"upstream patch context changed: {before!r}")
  return text.replace(before, after, 1)


def patch_cyclictest(checkout):
  patch = REPO / "tester/patches/cyclictest.patch"
  for options in (("--check",), ()):
    result = subprocess.run(["git", "apply", *options, str(patch)], cwd=checkout,
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
      raise ValueError(f"cyclictest patch failed: {result.stderr.strip()}")
  return patch.read_text()


def simple_loader(source):
  text = patch_once(source, 'Usage: %s [-f] [-v]', 'Usage: %s [-f] [-p] [-v]')
  text = patch_once(text, '"  -v            Print libbpf debug messages\\n"',
      '"  -p            Switch only tasks using SCHED_EXT\\n"\n'
      '"  -v            Print libbpf debug messages\\n"')
  text = patch_once(text, 'getopt(argc, argv, "fvh")', 'getopt(argc, argv, "fpvh")')
  return patch_once(text, "\t\tcase 'v':\n",
      "\t\tcase 'p':\n"
      "\t\t\tskel->struct_ops.simple_ops->flags |= SCX_OPS_SWITCH_PARTIAL;\n"
      "\t\t\tbreak;\n\t\tcase 'v':\n")


def result(root):
  for path in sorted(root.glob("attempt-*/status.json"), reverse=True):
    status = json.loads(path.read_text())
    if status["status"] == "succeeded":
      return status["result"]
  raise RuntimeError(f"no successful build in {root}")


def user_build(config, target, trace):
  uid = int(os.environ.get("SUDO_UID", "0"))
  if uid == 0:
    raise ValueError("root builds require the original user in SUDO_UID")
  account = pwd.getpwuid(uid)
  directory = new_run(config, f"build-dispatch-{target}")
  settings = directory / "config.json"
  write_json(settings, config)
  source = """import signal, sys
from tester.utils import builds
from tester.utils.common import load_config
def interrupt(*_):
  raise KeyboardInterrupt
signal.signal(signal.SIGTERM, interrupt)
print('BUILD_RESULT=' + str(builds.build(load_config(sys.argv[1]), sys.argv[2], sys.argv[3])),
      flush=True)
"""
  args = [sys.executable, "-c", source, str(settings), target, trace]
  write_json(directory / "command.json", {"command": args, "uid": uid, "gid": account.pw_gid})
  process = subprocess.Popen(args, cwd=REPO, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, start_new_session=True,
                             user=uid, group=account.pw_gid, extra_groups=[])
  try:
    output, _ = process.communicate(timeout=config["build_timeout_s"] *
                                    config["max_attempts"] * 4 + 60)
  except BaseException:
    try:
      os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
      pass
    try:
      output, _ = process.communicate(timeout=config["process_timeout_s"] * 4 + 5)
      (directory / "build.log").write_text(output)
    except subprocess.TimeoutExpired as error:
      raise CleanupError("unprivileged builder did not finish cleanup") from error
    raise
  (directory / "build.log").write_text(output)
  if process.returncode:
    raise RuntimeError(f"unprivileged build failed; see {directory / 'build.log'}")
  roots = [line.removeprefix("BUILD_RESULT=") for line in output.splitlines()
           if line.startswith("BUILD_RESULT=")]
  if len(roots) != 1:
    raise RuntimeError("unprivileged builder did not return one artifact directory")
  root = Path(roots[0]).resolve(strict=True)
  if root.parent != directory.parent:
    raise RuntimeError("builder returned an unexpected artifact directory")
  print(output, end="", flush=True)
  return root


def build(config, target, trace="off"):
  if os.geteuid() == 0:
    with controller_placement(config):
      return user_build(config, target, trace)
  def action(directory, processes):
    timeout = config["build_timeout_s"]
    metadata = {"target": target, "trace_profile": trace, "latency_statistics": False}
    if target in ("jlfp", "qmap", "simple"):
      compiler = shutil.which(BPF_CLANG)
      if compiler is None:
        raise FileNotFoundError(f"{BPF_CLANG} is required for BPF scheduler builds")
      version = subprocess.run([compiler, "--version"], check=True, capture_output=True,
                               text=True, timeout=config["process_timeout_s"])
      metadata["bpf_compiler"] = {"path": str(Path(compiler).resolve()),
                                  "version": version.stdout.strip()}

    def run(command, cwd=REPO):
      write_json(directory / "build.json", metadata)
      processes.run(command, cwd=cwd, timeout=timeout)

    if target == "worker":
      binary = directory / "jlfp_worker"
      metadata["source_sha256"] = {"tester/work.c": sha256(REPO / "tester/work.c")}
      run(["cc", "-O2", "-pthread", "-DSCHED_EXT=7", "tester/work.c", "-lbpf", "-o", binary])
    elif target == "jlfp":
      metadata.update(partial_switch=True, launch_args=[])
      output = directory / "scheds"
      flags = {"SCXTP_TRACING": int(trace != "off"),
               "SCXTP_HOTPATH_TRACING": int(trace == "hotpath"), "SCX_LATENCY_STATS": 0}
      metadata["flags"] = flags
      watched = list((REPO / "scheds").glob("*.h")) + list((REPO / "scheds").glob("*.c"))
      watched += list((REPO / "scheds/trace").glob("*.h")) + [REPO / "scheds/Makefile"]
      metadata["source_sha256"] = {str(p.relative_to(REPO)): sha256(p) for p in watched}
      run(["make", "-C", REPO / "scheds", "-j2", f"BUILD={output}", f"CLANG={BPF_CLANG}",
           *(f"{key}={value}" for key, value in flags.items()), "all"])
      binary = output / "scx_jlfp"
      metadata["gedf_binary_sha256"] = sha256(output / "scx_gedf")
    elif target in ("qmap", "simple"):
      pin = linux_pin()
      checkout = directory / "linux"
      metadata["kernel_source"] = {**pin, "setup_sha256": sha256(REPO / "scheds/setup.sh")}
      checkout_linux(checkout, pin, run)
      metadata["kernel_source"].update(repository_state(checkout))
      upstream = checkout / "tools/sched_ext"
      watched = [upstream / f"scx_{target}{suffix}" for suffix in (".c", ".bpf.c")]
      metadata["source_sha256"] = {str(p.relative_to(checkout)): sha256(p) for p in watched}
      output = directory / "upstream"
      output.mkdir()
      run(["make", "-C", upstream, "-j2", f"O={output}",
           f"CLANG={BPF_CLANG}", "VMLINUX_BTF=/sys/kernel/btf/vmlinux", f"scx_{target}"])
      binary = directory / f"upstream/build/bin/scx_{target}"
      metadata.update(partial_switch=True, launch_args=["-p"])
      if target == "simple":
        original = (upstream / "scx_simple.c").read_text()
        modified = simple_loader(original)
        source = output / "scx_simple.c"
        source.write_text(modified)
        patch = difflib.unified_diff(original.splitlines(keepends=True),
                                    modified.splitlines(keepends=True),
                                    fromfile="a/scx_simple.c", tofile="b/scx_simple.c")
        (directory / "simple-partial.patch").write_text("".join(patch))
        includes = [output / "build/include", checkout / "include/generated",
                    checkout / "tools/lib", checkout / "tools/include",
                    checkout / "tools/include/uapi", upstream / "include"]
        run(["cc", "-g", "-O2", "-rdynamic", "-pthread", "-Wall", "-Werror",
             *(f"-I{p}" for p in includes), source, "-o", binary,
             output / "build/obj/libbpf/libbpf.a", "-lelf", "-lz", "-lpthread"])
        metadata["loader_sha256"] = sha256(source)
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
      metadata["e1_startup_gate"] = True
      metadata["deadline_support"] = {"parameters": "explicit nanoseconds per worker",
                                      "reservation_readback": True}
      metadata["patch_sha256"] = sha256(REPO / "tester/patches/cyclictest.patch")
    metadata.update(binary=str(binary), binary_sha256=sha256(binary))
    write_json(directory / "build.json", metadata)
    return metadata

  with controller_placement(config):
    return run_attempts(config, f"build-{target}-{trace}", action)
