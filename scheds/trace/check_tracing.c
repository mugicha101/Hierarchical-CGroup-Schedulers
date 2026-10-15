#include <stdio.h>
#include <string.h>
#include <scx/common.h>
#include "../scx_gedf.h"
#include "scx_jlfp.bpf.skel.h"
#include "scx_gedf.bpf.skel.h"

int main(int argc, char **argv)
{
  bool tracing;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s scx_jlfp|scx_gedf\n", argv[0]);
    return 1;
  }

  // read the compiled BPF settings without loading a scheduler
  if (!strcmp(argv[1], "scx_jlfp")) {
    struct scx_jlfp *skel = scx_jlfp__open();
    if (!skel) {
      fprintf(stderr, "Failed to open JLFP skeleton\n");
      return 1;
    }
    tracing = skel->rodata->scxtp_lowfreq_compiled;
    scx_jlfp__destroy(skel);
  } else if (!strcmp(argv[1], "scx_gedf")) {
    struct scx_gedf *skel = scx_gedf__open();
    if (!skel) {
      fprintf(stderr, "Failed to open GEDF skeleton\n");
      return 1;
    }
    tracing = skel->rodata->scxtp_lowfreq_compiled;
    scx_gedf__destroy(skel);
  } else {
    fprintf(stderr, "Unknown scheduler: %s\n", argv[1]);
    return 1;
  }

  printf("%d\n", tracing);
  return 0;
}
