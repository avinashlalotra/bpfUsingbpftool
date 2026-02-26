#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* change_type values */
#define CREATE_EVENT 0x10u
#define DELETE_EVENT 0x11u
#define MKDIR_EVENT 0x13u
#define RMDIR_EVENT 0x14u

#define MAX_FILENAME_LEN 255
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
/* ───────────────────────────────────────────── */

#define S_IFDIR 0x4000

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
  __u32 reserved;

  __s64 file_size;
};

/* ───────────────────────────────────────────── */
/* Maps                                          */
/* ───────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct KEY);
  __type(value, struct VALUE);
} InodeMap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} rb SEC(".maps");
