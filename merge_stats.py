# mostly ai gen stat merger script
# merge all cids data into single object
# list each source

import argparse
import json
from pathlib import Path

def merge_json(path, data):
    assert(isinstance(data, list))
    merged = {"path": path}
    for obj in data:
        assert(isinstance(obj, dict))
    for cid_data in data:
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
    

def main():
    parser = argparse.ArgumentParser(description="Merge JSON files.")
    
    # Positional argument accepting one or more source globs
    parser.add_argument("sources", type=str, nargs='+', help="One or more glob patterns for source JSON files (e.g., '*.json' 'other_dir/*.json')")
    
    # Optional flag for the output path, with a default value
    parser.add_argument("-o", "--output", type=str, default="merged_stats.json", help="Path for the output merged JSON file (default: merged_stats.json)")
    
    args = parser.parse_args()

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
                    merged_data.append(merge_json(str(file_path), data))
                        
            except json.JSONDecodeError:
                print(f"Skipping {file_path.name}: Invalid JSON format.")
            except Exception as e:
                print(f"Error reading {file_path.name}: {e}")

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(dest_path, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, indent=4)
        print(f"Successfully merged data into {dest_path}")
    except IOError as e:
        print(f"Failed to write to {dest_path}: {e}")

if __name__ == "__main__":
    main()