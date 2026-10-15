#!/usr/bin/env python3
"""Fetch and build a separate SCHED_EXT cyclictest that preserves worker affinity."""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO_DIR = Path(__file__).resolve().parents[1]
RT_TESTS_REPO = "https://git.kernel.org/pub/scm/utils/rt-tests/rt-tests.git"
RT_TESTS_REVISION = "fd45df830803dd7f26d2ca8bdcf05fd7e0d62ae8"
MODIFIED_SOURCE = REPO_DIR / "cyclictest/modified_cyclictest.c"
HEADER = Path("src/cyclictest/rt_numa.h")
SOURCE = Path("src/cyclictest/cyclictest.c")


def clone_source(source):
  source.parent.mkdir(parents=True, exist_ok=True)
  with tempfile.TemporaryDirectory(prefix=".rt-tests-", dir=source.parent) as directory:
    checkout = Path(directory) / "rt-tests"
    subprocess.run(["git", "clone", "--no-checkout", RT_TESTS_REPO, str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "checkout", "--detach", RT_TESTS_REVISION],
                   check=True)
    checkout.rename(source)


def guard_header(text):
  context = ("static void rt_numa_set_numa_run_on_node(int node, int cpu)\n{\n"
             "\tint res;\n\tres = numa_run_on_node(node);\n")
  if text.count(context) != 1:
    raise ValueError("expected unmodified cyclictest NUMA CPU-binding function")
  guarded = ("static void rt_numa_set_numa_run_on_node(int node, int cpu)\n{\n"
             "\t/* keep the inherited cpu mask for unpinned measurement threads */\n"
             "\tif (cpu == -1)\n\t\treturn;\n\n"
             "\tint res;\n\tres = numa_run_on_node(node);\n")
  return text.replace(context, guarded)


def sha256(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_copy(source, output):
  source, output = source.resolve(), output.absolute()
  if output.exists():
    raise FileExistsError(output)
  if output.resolve().is_relative_to(source):
    raise ValueError("output directory must be outside the rt-tests source")
  if not source.exists():
    clone_source(source)
  original = (source / HEADER).read_text()
  modified = guard_header(original)
  watched = [HEADER, SOURCE]
  if (source / "cyclictest").is_file():
    watched.append(Path("cyclictest"))
  metadata = {"source_directory": str(source),
              "source_sha256": {str(path): sha256(source / path) for path in watched},
              "cyclictest_source": str(MODIFIED_SOURCE),
              "cyclictest_source_sha256": sha256(MODIFIED_SOURCE),
              "change": "apply repository SCHED_EXT cyclictest; skip NUMA CPU rebinding when cpu == -1",
              "command": ["make", "-j2", "cyclictest"],
              "output_binary": str(output / "cyclictest")}
  def ignore(directory, names):
    return set(names) & {".git", "bld", "cyclictest"} if Path(directory) == source else set()
  output.parent.mkdir(parents=True, exist_ok=True)
  shutil.copytree(source, output, ignore=ignore)
  shutil.copyfile(MODIFIED_SOURCE, output / SOURCE)
  (output / HEADER).write_text(modified)
  patch = difflib.unified_diff(original.splitlines(keepends=True),
                               modified.splitlines(keepends=True),
                               fromfile="a/" + str(HEADER), tofile="b/" + str(HEADER))
  (output / "numa-affinity.patch").write_text("".join(patch))
  (output / "build-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
  return metadata


def build(source, output):
  metadata = prepare_copy(source, output)
  with (output / "build.log").open("w") as log:
    result = subprocess.run(metadata["command"], cwd=output, stdout=log,
                            stderr=subprocess.STDOUT)
  metadata["build_return_code"] = result.returncode
  metadata["source_unchanged_after_build"] = all(
      sha256(source / path) == digest for path, digest in metadata["source_sha256"].items())
  if result.returncode == 0:
    metadata["built_cyclictest_sha256"] = sha256(output / "cyclictest")
  (output / "build-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
  if not metadata["source_unchanged_after_build"]:
    raise RuntimeError("source files changed during the build; inspect build metadata")
  if result.returncode:
    raise RuntimeError(f"cyclictest build failed; see {output / 'build.log'}")
  return output / "cyclictest"


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--source-dir", type=Path, default=REPO_DIR / "cyclictest/rt-tests",
                      help="rt-tests checkout; cloned at a pinned revision if missing")
  parser.add_argument("--output-dir", type=Path, required=True,
                      help="new directory outside the original rt-tests checkout")
  args = parser.parse_args()
  try:
    print(build(args.source_dir, args.output_dir))
    return 0
  except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(main())
