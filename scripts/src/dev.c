#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

uint64_t rawDev(const struct stat *st) {
  uint64_t major = (uint64_t)(st->st_dev >> 8);
  uint64_t minor = (uint64_t)(st->st_dev & 0xff);
  return (major << 20) | minor;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <path>\n", argv[0]);
    return 1;
  }

  struct stat st;
  if (stat(argv[1], &st) != 0) {
    perror("stat");
    return 1;
  }

  printf("%llu\n", (unsigned long long)rawDev(&st));

  return 0;
}