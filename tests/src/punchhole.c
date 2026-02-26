#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <unistd.h>

/** Test for punchhole syscall */
int main() {
  int fd = open("tmp/test_punch.txt", O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  ssize_t bytes_written = write(fd, "1234567890", 10);
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }

  int ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 2, 4);
  if (ret < 0) {
    perror("fallocate");
    return 1;
  }

  close(fd);
  return 0;
}
