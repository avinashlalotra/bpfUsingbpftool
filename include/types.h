#ifndef __TYPES_H
#define __TYPES_H

#include "vmlinux.h"
#define MAX_FILENAME_LEN 255

/* Event types */
#define CREATE_EVENT 0xcu
#define DELETE_EVENT 0xdu
#define WRITE_EVENT 0xeu

#ifndef S_ISDIR
#define S_IFMT 00170000
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

/* ───────────────────────────────────────────── */

struct KEY {
  __u64 inode;
};

struct VALUE {
  __u64 dummy;
};

struct EVENT {
  __u64 parent_inode;
  __u64 parent_dev;
  __u64 inode;
  __u64 dev;
  __u64 giduid;
  __u8 filename[MAX_FILENAME_LEN];
  __u8 change_type;
  __u32 bytes_written;
  __s64 file_size;
};

#endif /* __TYPES_H */