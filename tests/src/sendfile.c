// test_sendfile.c
#include <fcntl.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <unistd.h>

/** Test for sendfile syscall */
int main() {
  int in = open("tmp/testfile1.txt", O_RDONLY);
  if (in < 0) {
    perror("open");
    return 1;
  }
  int out = open("tmp/testfile5.txt", O_CREAT | O_WRONLY, 0644);
  if (out < 0) {
    perror("open");
    return 1;
  }

  off_t offset = 0;
  ssize_t bytes_written = sendfile(out, in, &offset, 1024);
  if (bytes_written < 0) {
    perror("sendfile");
    return 1;
  }

  close(in);
  close(out);
  return 0;
}
