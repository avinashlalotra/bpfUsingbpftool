#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/** Test for mmap and msync syscalls */
int main() {
  int fd = open("tmp/test_mmap.txt", O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  ftruncate(fd, 4096);

  char *map = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  strcpy(map, "mmap write test\n");

  if (msync(map, 4096, MS_SYNC) < 0) {
    perror("msync");
    return 1;
  }

  if (munmap(map, 4096) < 0) {
    perror("munmap");
    return 1;
  }
  close(fd);
  return 0;
}
