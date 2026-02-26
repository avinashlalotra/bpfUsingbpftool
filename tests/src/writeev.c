// test_writev.c
#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

/** Test for writev syscall */
int main() {
  int fd = open("tmp/testfile2.txt", O_CREAT | O_WRONLY, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  struct iovec iov[2];
  iov[0].iov_base = "hello ";
  iov[0].iov_len = 6;
  iov[1].iov_base = "world\n";
  iov[1].iov_len = 6;

  ssize_t bytes_written = writev(fd, iov, 2);
  if (bytes_written < 0) {
    perror("writev");
    return 1;
  }
  close(fd);
  return 0;
}
