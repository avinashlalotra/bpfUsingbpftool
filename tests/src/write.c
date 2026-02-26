// test_write.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/** Test for write syscall */
int main() {
  int fd = open("tmp/testfile1.txt", O_CREAT | O_WRONLY, 0644);

  if (fd < 0) {
    perror("open");
    return 1;
  }
  ssize_t bytes_written = write(fd, "hello\n", 6);
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }
  close(fd);
  return 0;
}
