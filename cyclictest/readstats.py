# AI generated script (Gemini) to read the stats from scx_ffp
# NOTE: /sys/fs/bpf/ffp_cpu_stats must be deleted in order to reset stats between tests

import subprocess
import json
import struct
import sys

# --- CONFIGURATION ---
MAP_PATH = "/sys/fs/bpf/ffp_cpu_stats"

# Define your struct fields here! 
# The script assumes all fields are u64 (8 bytes).
# It will dynamically calculate the struct size and column headers based on this list.
FIELDS = [
    "Select",
    "Dispatch",
    "Enqueue",
    "Pick",
    "LDSQ",
    "GDSQ",
    "Kicks",
    "Kick WCET",
    "Pick WCET",
    "Disp WCET",
    "Search WCET",
    "TskDisp WCET"
]
# ---------------------

def main():
    print(f"Dumping BPF map from {MAP_PATH}...\n")
    
    try:
        cmd = ["sudo", "bpftool", "-j", "map", "dump", "pinned", MAP_PATH]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Error: Could not read the BPF map. Is the scheduler running and the map pinned?")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: bpftool is not installed or not in PATH.")
        sys.exit(1)

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print("Error: Failed to parse bpftool JSON output.")
        sys.exit(1)

    if not data:
        print("Map is empty (null). The scheduler has not initialized the stats yet.")
        sys.exit(0)

    # 1. Dynamically calculate struct constraints based on the FIELDS list
    num_fields = len(FIELDS)
    expected_bytes = num_fields * 8
    unpack_format = '<' + ('Q' * num_fields)
    headers = ["CPU"] + FIELDS

    # 2. Extract and parse all rows into memory
    per_cpu_data = data[0].get("values", [])
    parsed_rows = []

    for cpu_entry in per_cpu_data:
        cpu_id = cpu_entry.get("cpu", 0)
        hex_array = cpu_entry.get("value", [])
        byte_data = bytes([int(x, 16) for x in hex_array])

        # Safely slice and unpack based on our dynamically calculated size
        if len(byte_data) >= expected_bytes:
            unpacked = struct.unpack(unpack_format, byte_data[:expected_bytes])
            # Convert everything to strings for length measurement
            row_strs = [str(cpu_id)] + [str(val) for val in unpacked]
            parsed_rows.append(row_strs)

    if not parsed_rows:
        print(f"Error: No valid struct data found. Ensure the map values are at least {expected_bytes} bytes.")
        sys.exit(1)

    # 3. Auto-scale: Calculate the maximum width for each column
    col_widths = [len(h) for h in headers]
    for row in parsed_rows:
        for i, val_str in enumerate(row):
            if len(val_str) > col_widths[i]:
                col_widths[i] = len(val_str)

    # 4. Build the dynamic row formatter (e.g., "{:<3} | {:<8} | ...")
    row_format = " | ".join([f"{{:<{w}}}" for w in col_widths])
    
    # Calculate the total separator width
    total_width = sum(col_widths) + (len(col_widths) - 1) * 3 

    # 5. Print the dynamically formatted table
    print(row_format.format(*headers))
    print("-" * total_width)

    for row in parsed_rows:
        print(row_format.format(*row))

if __name__ == "__main__":
    main()