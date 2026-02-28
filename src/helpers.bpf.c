#include "../include/maps.h"
#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 255
#define MAX_NAME_LEN 64
#define MAX_DEPTH 10

static __always_inline bool is_monitored(struct inode *dir) {
  struct KEY key = {};
  key.inode = BPF_CORE_READ(dir, i_ino);
  key.dev = BPF_CORE_READ(dir, i_sb, s_dev);
  return bpf_map_lookup_elem(&InodeMap, &key) != NULL;
}

static __always_inline void print_event(const char *msg, struct EVENT *event) {

  if (event->change_type == DELETE_EVENT) {
    bpf_printk("%s: filepath: %s, type: DELETE", msg,
               event->dentry_ctx.filepath[event->dentry_ctx.start]);
  } else if (event->change_type == CREATE_EVENT) {
    bpf_printk("%s: filepath: %s, type: CREATE", msg,
               event->dentry_ctx.filepath[event->dentry_ctx.start]);
  } else if (event->change_type == WRITE_EVENT) {
    bpf_printk("%s: filepath: %s, type: WRITE, bytes_written: %llu", msg,
               event->dentry_ctx.filepath[event->dentry_ctx.start],
               event->bytes_written);
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

  bpf_probe_read_str(event->dentry_ctx.filepath,
                     sizeof(event->dentry_ctx.filepath),
                     BPF_CORE_READ(dentry, d_name.name));

  print_event(msg, event);
  bpf_ringbuf_submit(event, 0);
}

static __always_inline void copy_and_submit_event(const char *msg,
                                                  struct EVENT *event) {
  struct EVENT *new_event;

  new_event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!new_event)
    return;

  new_event->dentry_ctx.inode = event->dentry_ctx.inode;
  new_event->dentry_ctx.dev = event->dentry_ctx.dev;
  new_event->dentry_ctx.before_size = event->dentry_ctx.before_size;
  new_event->giduid = event->giduid;
  new_event->change_type = event->change_type;
  new_event->bytes_written = event->bytes_written;
  new_event->file_size = event->file_size;
  bpf_probe_read_str(new_event->dentry_ctx.filepath,
                     sizeof(new_event->dentry_ctx.filepath),
                     event->dentry_ctx.filepath);

  print_event(msg, new_event);
  bpf_ringbuf_submit(new_event, 0);
}

static __always_inline void construct_path(struct dentry *dentry,
                                           u8 path[MAX_PATH_LEN]) {
  u32 pos = MAX_PATH_LEN - 1;
  __builtin_memset(path, 0, MAX_PATH_LEN);

#pragma unroll
  for (int i = 0; i < MAX_DEPTH; i++) {
    if (!dentry)
      break;

    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    u32 len = d_name.len;

    // 1. Bound 'len' explicitly
    if (len == 0 || len >= MAX_PATH_LEN)
      break;

    // 2. Bound 'pos' against 'len'
    if (pos < len)
      break;
    pos -= len;

    // 3. Re-prove bounds to the verifier right before the read!
    // This stops the verifier from assuming pos + len can exceed MAX_PATH_LEN
    if (pos >= MAX_PATH_LEN)
      break;
    if (pos + len > MAX_PATH_LEN)
      break;

    // 4. Read safely without bitwise masks
    bpf_probe_read_kernel(&path[pos], len, d_name.name);

    if (pos > 0) {
      pos--;
      // Prove bounds again for the slash insertion
      if (pos >= MAX_PATH_LEN)
        break;
      path[pos] = '/';
    }

    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == parent)
      break;
    dentry = parent;
  }
}