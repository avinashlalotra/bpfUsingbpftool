#include "../include/maps.h"
#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline bool is_monitored(struct inode *dir) {
  struct KEY key = {};
  key.inode = BPF_CORE_READ(dir, i_ino);
  return bpf_map_lookup_elem(&InodeMap, &key) != NULL;
}

static __always_inline void print_event(const char *msg, struct EVENT *event) {

  if (event->change_type == DELETE_EVENT) {
    bpf_printk("%s: filename: %s, type: DELETE", msg, event->filename);
  } else if (event->change_type == CREATE_EVENT) {
    bpf_printk("%s: filename: %s, type: CREATE", msg, event->filename);
  } else if (event->change_type == WRITE_EVENT) {
    bpf_printk("%s: filename: %s, type: WRITE, bytes_written: %llu", msg,
               event->filename, event->bytes_written);
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

  event->parent_inode = BPF_CORE_READ(parent_inode, i_ino);
  event->parent_dev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
  event->inode = BPF_CORE_READ(inode, i_ino);
  event->dev = BPF_CORE_READ(inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = type;
  event->bytes_written = 0;
  event->file_size = BPF_CORE_READ(inode, i_size);

  bpf_probe_read_str(event->filename, sizeof(event->filename),
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

  new_event->parent_inode = event->parent_inode;
  new_event->parent_dev = event->parent_dev;
  new_event->inode = event->inode;
  new_event->dev = event->dev;
  new_event->giduid = event->giduid;
  new_event->change_type = event->change_type;
  new_event->bytes_written = event->bytes_written;
  new_event->file_size = event->file_size;
  bpf_probe_read_str(new_event->filename, sizeof(new_event->filename),
                     event->filename);

  print_event(msg, new_event);
  bpf_ringbuf_submit(new_event, 0);
}