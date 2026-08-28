# mostly ai gen stat merger script
# merge all cids data into single object
# list each source

import argparse
import json
from pathlib import Path
import re
import sys
import traceback

def merge_json(path, data, cidset):
    assert(isinstance(data, list))
    merged = {"path": path}
    for obj in data:
        assert(isinstance(obj, dict))
    for cid, cid_data in enumerate(data):
        if not included_cid(cidset, cid):
            continue
        
        assert("path" not in cid_data)
        for key, stat in cid_data.items():
            assert(stat.keys() == {"n", "max", "sum"})
            if key not in merged:
                merged[key] = {"n": 0, "max": 0, "sum": 0}
            merged[key]["n"] += stat["n"]
            merged[key]["max"] = max(merged[key]["max"], stat["max"])
            merged[key]["sum"] += stat["sum"]
    for key, stat in merged.items():
        if key == "path":
            continue

        stat["avg"] = None if stat["n"] == 0 else float(stat["sum"]) / float(stat["n"])
    return merged

def parse_cidset(cidset):
    itvs = re.split(r'[;,]\s*', cidset.strip())
    invalid = False
    res = []
    for itv in itvs:
        if not itv:
            continue

        if not re.match(r"\d*(-\d*)?", cidset):
            print(f"Error: Invalid cidset: {itv}")
            invalid = True
            continue

        if '-' in itv:
            if len(itv) == 1:
                res.append([0, None])
            elif itv[0] == '-':
                res.append([0, int(itv[1:])])
            elif itv[-1] == '-':
                res.append([int(itv[:-1]),None])
            else:
                first, last = map(int, itv.split('-'))
                if first > last:
                    print(f"Error: Invalid cidset: {itv}")
                    invalid = True
                else:
                    res.append([first, last])
        else:
            cpu = int(itv)
            res.append(range(cpu, cpu+1))
    return None if invalid else res

def included_cid(cidset: list[range], cid):
    if len(cidset) == 0:
        return True

    return any(cid >= itv[0] and (itv[1] is None or cid >= itv[1]) for itv in cidset)

def main():
    parser = argparse.ArgumentParser(description="Merge JSON files.")
    
    # Positional argument accepting one or more source globs
    parser.add_argument("sources", type=str, nargs='+', help="One or more glob patterns for source JSON files (e.g., '*.json' 'other_dir/*.json')")
    
    # Optional flag for the output path, with a default value
    parser.add_argument("-o", "--output", type=str, default="merged_stats.json", help="Path for the output merged JSON file (default: merged_stats.json)")

    # Optional flag for only including specific cids
    parser.add_argument("-c", "--cidset", type=str, default="-", help="CIDs to include stats from (default: all cids, format: , or ; seperate list of a-b where a or b is an optional non-negative integer)")
    
    args = parser.parse_args()

    cidset = parse_cidset(args.cidset)
    if cidset is None:
        return
    
    dest_path = Path(args.output).resolve()
    merged_data = []
    processed_files = set()

    # Iterate through all provided glob patterns
    for source_glob in args.sources:
        for file_path in Path.cwd().glob(source_glob):
            resolved_path = file_path.resolve()
            
            # Skip the output file if it is in the glob match
            if resolved_path == dest_path:
                continue
                
            # Prevent processing the same file twice if globs overlap
            if resolved_path in processed_files:
                continue
                
            processed_files.add(resolved_path)

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    merged_data.append(merge_json(str(file_path), data, cidset))
                        
            except json.JSONDecodeError:
                print(f"Error reading {file_path.name}: Invalid JSON format.")
                return 1
            except Exception as e:
                print(f"Error reading {file_path.name}: {e}")
                traceback.print_exc()
                return 1

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    merged_json = {
        "cmd": " ".join(sys.orig_argv),
        "cidset": cidset,
        "data": merged_data
    }

    try:
        with open(dest_path, 'w', encoding='utf-8') as f:
            json.dump(merged_json, f, indent=4)
        print(f"Successfully merged data into {dest_path}")
    except IOError as e:
        print(f"Failed to write to {dest_path}: {e}")

if __name__ == "__main__":
    main()