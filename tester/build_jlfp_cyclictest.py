#!/usr/bin/env python3
"""Build a separate cyclictest that preserves unpinned workers' CPU affinity."""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO_DIR = Path(__file__).resolve().parents[1]
HEADER = Path("src/cyclictest/rt_numa.h")
SOURCE = Path("src/cyclictest/cyclictest.c")


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
  source, output = source.resolve(strict=True), output.absolute()
  original = (source / HEADER).read_text()
  modified = guard_header(original)
  if "SCHED_EXT" not in (source / SOURCE).read_text():
    raise ValueError("source cyclictest lacks the repository's SCHED_EXT support")
  if output.exists():
    raise FileExistsError(output)
  if output.resolve().is_relative_to(source):
    raise ValueError("output directory must be outside the rt-tests source")
  watched = [HEADER, SOURCE]
  if (source / "cyclictest").is_file():
    watched.append(Path("cyclictest"))
  metadata = {"source_directory": str(source),
              "source_sha256": {str(path): sha256(source / path) for path in watched},
              "change": "skip NUMA CPU rebinding when cpu == -1; pinned handling unchanged",
              "command": ["make", "-j2", "cyclictest"],
              "output_binary": str(output / "cyclictest")}
  def ignore(directory, names):
    return set(names) & {".git", "bld", "cyclictest"} if Path(directory) == source else set()
  output.parent.mkdir(parents=True, exist_ok=True)
  shutil.copytree(source, output, ignore=ignore)
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
  parser.add_argument("--source-dir", type=Path, default=REPO_DIR / "cyclictest/rt-tests")
  parser.add_argument("--output-dir", type=Path, required=True,
                      help="new directory outside the original rt-tests checkout")
  args = parser.parse_args()
  try:
    print(build(args.source_dir.resolve(strict=True), args.output_dir.absolute()))
    return 0
  except (OSError, ValueError, RuntimeError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(main())
