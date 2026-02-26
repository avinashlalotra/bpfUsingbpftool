#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <unistd.h>

/** Test for collapse_range syscall */
int main() {
  int fd = open("tmp/test_collapse.txt", O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  ssize_t bytes_written = write(fd, "abcdefghij", 10);
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }

  int ret = fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, 2, 4);
  if (ret < 0) {
    perror("fallocate");
    return 1;
  }

  close(fd);
  return 0;
}
