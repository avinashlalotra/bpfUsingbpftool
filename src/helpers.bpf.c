#include "../include/maps.h"
#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline bool is_monitored(struct inode *dir) {
  struct KEY key = {};
  key.inode = BPF_CORE_READ(dir, i_ino);
  key.dev = BPF_CORE_READ(dir, i_sb, s_dev);
  return bpf_map_lookup_elem(&InodeMap, &key) != NULL;
}

static __always_inline void construct_path(struct dentry *dentry, char *path) {
  struct dentry *curr = dentry;

#pragma unroll
  for (int i = 0; i < MAX_DEPTH; i++) {

    struct dentry *parent = BPF_CORE_READ(curr, d_parent);
    if (curr == parent)
      break;

    struct qstr d_name = BPF_CORE_READ(curr, d_name);

    /* Always write into fixed 64-byte slot */
    bpf_probe_read_kernel_str(path + (i * PER_LEVEL), PER_LEVEL, d_name.name);

    curr = parent;
  }
}

static __always_inline void print_event(const char *msg, struct EVENT *event) {

  if (event->change_type == DELETE_EVENT) {
    bpf_printk("%s: filepath: %s, type: DELETE", msg,
               event->dentry_ctx.filepath);
  } else if (event->change_type == CREATE_EVENT) {
    bpf_printk("%s: filepath: %s, type: CREATE", msg,
               event->dentry_ctx.filepath);
  } else if (event->change_type == WRITE_EVENT) {
    bpf_printk("%s: filepath: %s, type: WRITE, bytes_written: %llu", msg,
               event->dentry_ctx.filepath, event->bytes_written);
  }
}

static __always_inline void update_dir_map(struct dentry *dentry, bool add) {
  struct inode *inode;
  struct KEY key = {};
  struct VALUE value = {1};
  umode_t mode;

  if (!dentry)
    return;

  inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode)
    return;

  mode = BPF_CORE_READ(inode, i_mode);
  if (!S_ISDIR(mode))
    return;

  key.inode = BPF_CORE_READ(inode, i_ino);

  if (add)
    bpf_map_update_elem(&InodeMap, &key, &value, BPF_ANY);
  else
    bpf_map_delete_elem(&InodeMap, &key);
}

static __always_inline void emit_event(const char *msg,
                                       struct inode *parent_inode,
                                       struct dentry *dentry, __u8 type) {
  struct inode *inode;
  struct EVENT *event;

  inode = BPF_CORE_READ(dentry, d_inode);

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return;

  event->dentry_ctx.inode = BPF_CORE_READ(inode, i_ino);
  event->dentry_ctx.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  event->dentry_ctx.before_size = BPF_CORE_READ(inode, i_size);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = type;
  event->bytes_written = 0;
  event->file_size = BPF_CORE_READ(inode, i_size);

  construct_path(dentry, event->dentry_ctx.filepath);

  print_event(msg, event);
  bpf_ringbuf_submit(event, 0);
}
