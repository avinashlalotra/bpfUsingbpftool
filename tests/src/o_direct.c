#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Test for O_DIRECT flag */
int main() {
  int fd = open("tmp/test_odirect.txt", O_CREAT | O_WRONLY | O_DIRECT, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  void *buf;
  posix_memalign(&buf, 4096, 4096);
  memset(buf, 'A', 4096);

  ssize_t bytes_written = write(fd, buf, 4096);
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }

  free(buf);
  close(fd);
  return 0;
}
