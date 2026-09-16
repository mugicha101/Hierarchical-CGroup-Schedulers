// TODO: this file AI written, need to validate

#ifndef __RTP_FIFO_H
#define __RTP_FIFO_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RTP_FIFO_NAME "task_realtime_params"

struct rtp_fifo {
  int dir_fd;
  int fd;
  bool created;
  bool discard;
  size_t used;
  char line[256];
  char path[PATH_MAX];
};

typedef int (*rtp_fifo_update_fn)(void *ctx, pid_t tid, uint64_t period,
                                uint64_t deadline, bool periodic);

static inline void rtp_fifo_close(struct rtp_fifo *fifo)
{
  if (fifo->created)
    unlinkat(fifo->dir_fd, RTP_FIFO_NAME, 0);
  if (fifo->fd >= 0)
    close(fifo->fd);
  if (fifo->dir_fd >= 0)
    close(fifo->dir_fd);
  *fifo = (struct rtp_fifo){ .dir_fd = -1, .fd = -1 };
}

// traverse using directory fds so paths in /tmp cannot redirect the daemon
static inline int rtp_fifo_enter(int parent, const char *name)
{
  if (mkdirat(parent, name, 0700) && errno != EEXIST)
    return -errno;
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return -errno;
  struct stat st;
  if (fstat(fd, &st)) {
    int err = -errno;
    close(fd);
    return err;
  }
  if (st.st_uid != geteuid() || (st.st_mode & 0022)) {
    close(fd);
    return -EACCES;
  }
  return fd;
}

static inline int rtp_fifo_open(struct rtp_fifo *fifo, const char *cgroup_path)
{
  const char *root = "/sys/fs/cgroup";
  char resolved[PATH_MAX];
  *fifo = (struct rtp_fifo){ .dir_fd = -1, .fd = -1 };
  if (!realpath(cgroup_path ? cgroup_path : root, resolved))
    return -errno;
  size_t len = strlen(root);
  if (strncmp(resolved, root, len) || (resolved[len] && resolved[len] != '/'))
    return -EINVAL;
  const char *relative = resolved + len;
  int n = snprintf(fifo->path, sizeof(fifo->path), "/tmp/scx%s/%s",
                   relative, RTP_FIFO_NAME);
  if (n < 0 || (size_t)n >= sizeof(fifo->path))
    return -ENAMETOOLONG;

  int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent < 0)
    return -errno;
  int fd = rtp_fifo_enter(parent, "scx");
  close(parent);
  if (fd < 0)
    return fd;
  fifo->dir_fd = fd;
  char *save = NULL;
  for (char *part = strtok_r(resolved + len, "/", &save); part;
       part = strtok_r(NULL, "/", &save)) {
    fd = rtp_fifo_enter(fifo->dir_fd, part);
    if (fd < 0) {
      rtp_fifo_close(fifo);
      return fd;
    }
    close(fifo->dir_fd);
    fifo->dir_fd = fd;
  }

  int err;
  // keep the directory inode for locking across FIFO replacement and restarts
  if (flock(fifo->dir_fd, LOCK_EX | LOCK_NB)) {
    err = -errno;
    goto fail;
  }
  struct stat st;
  if (!fstatat(fifo->dir_fd, RTP_FIFO_NAME, &st, AT_SYMLINK_NOFOLLOW)) {
    if (!S_ISFIFO(st.st_mode) || st.st_uid != geteuid()) {
      err = -EACCES;
      goto fail;
    }
    if (unlinkat(fifo->dir_fd, RTP_FIFO_NAME, 0)) {
      err = -errno;
      goto fail;
    }
  } else if (errno != ENOENT) {
    err = -errno;
    goto fail;
  }
  if (mkfifoat(fifo->dir_fd, RTP_FIFO_NAME, 0600)) {
    err = -errno;
    goto fail;
  }
  fifo->created = true;
  // Linux permits O_RDWR on FIFOs; hold a writer to avoid idle EOF
  fifo->fd = openat(fifo->dir_fd, RTP_FIFO_NAME,
                    O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
  if (fifo->fd < 0) {
    err = -errno;
    goto fail;
  }
  return 0;
fail:
  rtp_fifo_close(fifo);
  return err;
}

static inline int rtp_fifo_invalid(int err)
{
  fprintf(stderr, "Expected format: <tid> <period> <relative_deadline> <is_periodic>\n"
          "  tid: positive integer; is_periodic: 0 or 1\n"
          "  times: positive integers with optional s, ms, us, or ns suffix (default: ns)\n"
          "  example: 1234 100ms 80ms 1\n");
  return err;
}

// one newline-terminated request; convert timing suffixes to nanoseconds
static inline int rtp_fifo_request(char *line, rtp_fifo_update_fn update, void *ctx)
{
  uint64_t values[4];
  char *p = line;
  for (int i = 0; i < 4; i++) {
    while (isspace((unsigned char)*p))
      p++;
    if (!isdigit((unsigned char)*p))
      return rtp_fifo_invalid(-EINVAL);
    errno = 0;
    char *end;
    unsigned long long value = strtoull(p, &end, 10);
    if (errno == ERANGE || value > UINT64_MAX)
      return rtp_fifo_invalid(-ERANGE);
    uint64_t scale = 1;
    if (i == 1 || i == 2) {
      if (*end == 's') {
        scale = 1000000000ULL;
        end++;
      } else if (!strncmp(end, "ms", 2)) {
        scale = 1000000ULL;
        end += 2;
      } else if (!strncmp(end, "us", 2)) {
        scale = 1000ULL;
        end += 2;
      } else if (!strncmp(end, "ns", 2)) {
        end += 2;
      }
    }
    if (*end && !isspace((unsigned char)*end))
      return rtp_fifo_invalid(-EINVAL);
    if (value > UINT64_MAX / scale)
      return rtp_fifo_invalid(-ERANGE);
    values[i] = value * scale;
    p = end;
  }
  while (isspace((unsigned char)*p))
    p++;
  if (*p || !values[0] || values[0] > INT_MAX || !values[1] ||
      !values[2] || values[3] > 1)
    return rtp_fifo_invalid(-EINVAL);
  return update(ctx, (pid_t)values[0], values[1], values[2], values[3]);
}

static inline int rtp_fifo_drain(struct rtp_fifo *fifo,
                               rtp_fifo_update_fn update, void *ctx)
{
  char buf[4096];
  // bound work so continuous writers cannot starve exit and trace handling
  for (int batch = 0; batch < 16; batch++) {
    ssize_t n = read(fifo->fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EAGAIN || errno == EINTR)
        return 0;
      return -errno;
    }
    if (!n)
      return 0;
    for (ssize_t i = 0; i < n; i++) {
      if (buf[i] == '\n') {
        int err = -EINVAL;
        if (!fifo->discard) {
          fifo->line[fifo->used] = '\0';
          err = rtp_fifo_request(fifo->line, update, ctx);
        } else {
          err = rtp_fifo_invalid(-EINVAL);
        }
        if (err)
          fprintf(stderr, "Realtime parameter request failed: %s\n", strerror(-err));
        fifo->used = 0;
        fifo->discard = false;
      } else if (!fifo->discard) {
        if (!buf[i] || fifo->used == sizeof(fifo->line) - 1)
          fifo->discard = true;
        else
          fifo->line[fifo->used++] = buf[i];
      }
    }
  }
  return 0;
}

#endif
