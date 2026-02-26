// test_pwrite.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/** Test for pwrite syscall */
int main() {
  int fd = open("tmp/testfile3.txt", O_CREAT | O_WRONLY, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  ssize_t bytes_written = pwrite(fd, "offset\n", 7, 5);
  if (bytes_written < 0) {
    perror("pwrite");
    return 1;
  }
  close(fd);
  return 0;
}
