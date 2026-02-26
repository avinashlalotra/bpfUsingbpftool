// test_splice.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/** Test for splice syscall */
int main() {
  int pipefd[2];
  pipe(pipefd);

  int fd_in = open("tmp/testfile1.txt", O_RDONLY);
  if (fd_in < 0) {
    perror("open");
    return 1;
  }
  int fd_out = open("tmp/testfile6.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd_out < 0) {
    perror("open");
    return 1;
  }

  // file → pipe
  ssize_t bytes_written = splice(fd_in, NULL, pipefd[1], NULL, 1024, 0);
  if (bytes_written < 0) {
    perror("splice");
    return 1;
  }

  // pipe → file
  bytes_written = splice(pipefd[0], NULL, fd_out, NULL, 1024, 0);
  if (bytes_written < 0) {
    perror("splice");
    return 1;
  }

  close(fd_in);
  close(fd_out);
  close(pipefd[0]);
  close(pipefd[1]);

  return 0;
}