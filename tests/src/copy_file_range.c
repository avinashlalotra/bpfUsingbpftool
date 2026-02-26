// test_copy.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/** Test for copy_file_range syscall */
int main() {
  int in = open("tmp/testfile1.txt", O_RDONLY);
  if (in < 0) {
    perror("open");
    return 1;
  }
  int out = open("tmp/testfile7.txt", O_CREAT | O_WRONLY, 0644);
  if (out < 0) {
    perror("open");
    return 1;
  }

  ssize_t bytes_written = copy_file_range(in, NULL, out, NULL, 1024, 0);
  if (bytes_written < 0) {
    perror("copy_file_range");
    return 1;
  }

  close(in);
  close(out);
  return 0;
}
