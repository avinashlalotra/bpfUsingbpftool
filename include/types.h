#ifndef __TYPES_H
#define __TYPES_H

#include "vmlinux.h"
#define MAX_PATH_LEN 256
#define PER_LEVEL 64
#define MAX_DEPTH (MAX_PATH_LEN / PER_LEVEL)

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
  __u64 dev;
};

struct VALUE {
  __u64 dummy;
};

struct dentry_ctx {
  char filepath[MAX_PATH_LEN];
  __u64 inode;
  __u64 dev;
  __s64 before_size;
};

struct EVENT {
  __u64 giduid;
  __u32 change_type;
  __u32 bytes_written;
  __s64 file_size;
  struct dentry_ctx dentry_ctx;
};

#endif /* __TYPES_H */