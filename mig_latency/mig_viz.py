import re
import matplotlib.pyplot as plt
import seaborn as sns
import math

def show_grid(grid, n):
  max_val = max(max([x for x in row if not math.isnan(x)]) for row in grid)
  min_val = min(min([x for x in row if not math.isnan(x)]) for row in grid)

  ax = sns.heatmap(grid, linewidth=0.5, annot=True, fmt=".0f", cmap="Reds", cbar_kws={'label': 'Latency (ns)'}, vmin=min_val, vmax=max_val, square=True, cbar=True, annot_kws={"size": 5})
  ax.invert_yaxis()
  ax.set_title(f"Mean Migration Latency Heatmap (ns) n={n}")
  ax.set_xlabel("Destination CPU")
  ax.set_ylabel("Source CPU")
  
  plt.savefig("latency_grid.png", dpi=300, bbox_inches="tight")
  
def main():
  with open("mig_latency_results.txt", "r") as f:
    lines = f.readlines()
  
  line_rg = re.compile(r'^CPU\s+(?P<src_cpu>\d+)=>(?P<dst_cpu>\d+):(?P<kvps>.*)$')
  
  vals = {}
  max_cpu = -1
  n = 0
  
  for line in lines:
    match = line_rg.match(line)
    assert match, f"Line does not match expected format: {line}"
    src_cpu = int(match.group('src_cpu'))
    dest_cpu = int(match.group('dst_cpu'))
    max_cpu = max(max_cpu, src_cpu, dest_cpu)
    kvps = match.group('kvps')
    fields = dict(kvp.split('=') for kvp in kvps.split())
    vals[(src_cpu, dest_cpu)] = float(fields['avg'].removesuffix('ns'))
    n += int(fields['cnt'])
  
  grid = [[float('nan')] * (max_cpu + 1) for _ in range(max_cpu + 1)]
  for (src_cpu, dest_cpu), avg_latency in vals.items():
    grid[src_cpu][dest_cpu] = avg_latency
  show_grid(grid, n)

if __name__ == "__main__":
  main()