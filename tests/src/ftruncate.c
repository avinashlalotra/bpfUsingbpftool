#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/** Test for ftruncate syscall */
int main() {
  int fd = open("tmp/test_truncate.txt", O_CREAT | O_WRONLY, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  ssize_t bytes_written = write(fd, "hello", 5);
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }

  if (ftruncate(fd, 0) < 0) {
    perror("ftruncate");
    return 1;
  }

  close(fd);
  return 0;
}
