// SPDX-License-Identifier: GPL-2.0
//
// vfs_namespace_track.bpf.c
// Tracks namespace operations on monitored directories

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 255

/* Event types */
#define CREATE_EVENT 0x10u
#define MKDIR_EVENT 0x11u
#define MKNOD_EVENT 0x12u
#define LINK_EVENT 0x13u
#define DELETE_EVENT 0x14u

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
  __u32 reserved;
  __s64 file_size;
};

/* Monitored directories */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct KEY);
  __type(value, struct VALUE);
} InodeMap SEC(".maps");

/* Ring buffer */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} rb SEC(".maps");

/** LRU hash map for fentry/fexit communication */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct EVENT);
} LruMap SEC(".maps");

/* ───────────────────────────────────────────── */
/* Helpers                                      */
/* ───────────────────────────────────────────── */

static __always_inline bool is_monitored(struct inode *dir) {
  struct KEY key = {};
  key.inode = BPF_CORE_READ(dir, i_ino);
  return bpf_map_lookup_elem(&InodeMap, &key) != NULL;
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

static __always_inline void emit_event(struct inode *parent_inode,
                                       struct dentry *dentry, __u8 type) {
  struct inode *inode;
  struct EVENT *event;

  if (!parent_inode || !dentry)
    return;

  inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode)
    return;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return;

  event->parent_inode = BPF_CORE_READ(parent_inode, i_ino);
  event->parent_dev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
  event->inode = BPF_CORE_READ(inode, i_ino);
  event->dev = BPF_CORE_READ(inode, i_sb, s_dev);
  event->giduid = bpf_get_current_uid_gid();
  event->change_type = type;
  event->reserved = 0;
  event->file_size = BPF_CORE_READ(inode, i_size);

  bpf_probe_read_str(event->filename, sizeof(event->filename),
                     BPF_CORE_READ(dentry, d_name.name));

  bpf_printk("filename: %s, type: %u, size: %lld, parent: %llu, child: %llu",
             event->filename, event->change_type, event->file_size,
             event->parent_inode, event->inode);
  bpf_ringbuf_submit(event, 0);
}

static __always_inline void copy_and_submit_event(struct EVENT *event) {
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
  new_event->reserved = event->reserved;
  new_event->file_size = event->file_size;
  bpf_probe_read_str(new_event->filename, sizeof(new_event->filename),
                     event->filename);

  bpf_printk("copy_and_submit_event: filename: %s, type: %u, size: %lld, "
             "parent: %llu, child: %llu",
             new_event->filename, new_event->change_type, new_event->file_size,
             new_event->parent_inode, new_event->inode);
  bpf_ringbuf_submit(new_event, 0);
}

/* ───────────────────────────────────────────── */
/* CREATE                                       */
/* ───────────────────────────────────────────── */

SEC("lsm/d_instantiate")
int BPF_PROG(lsm_d_instantiate, struct dentry *dentry, struct inode *inode) {

  struct dentry *parent_dentry;
  struct inode *parent_inode;

  parent_dentry = BPF_CORE_READ(dentry, d_parent);
  parent_inode = BPF_CORE_READ(parent_dentry, d_inode);

  if (!parent_inode || !is_monitored(parent_inode))
    return 0;

  emit_event(parent_inode, dentry, CREATE_EVENT);
  return 0;
}

/* ───────────────────────────────────────────── */
/* MKDIR                                        */
/* ───────────────────────────────────────────── */

SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, umode_t mode, int ret) {
  if (ret != 0 || !is_monitored(dir))
    return 0;

  update_dir_map(dentry, true);
  emit_event(dir, dentry, MKDIR_EVENT);
  return 0;
}

/* ───────────────────────────────────────────── */
/* UNLINK - delete files                                      */
/* ───────────────────────────────────────────── */
SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode) {

  // check if parent is monitored
  if (!is_monitored(dir))
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  struct EVENT event = {};
  event.parent_inode = BPF_CORE_READ(dir, i_ino);
  event.parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
  event.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  event.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  event.giduid = bpf_get_current_uid_gid();
  event.change_type = DELETE_EVENT;
  event.reserved = 0;
  event.file_size = BPF_CORE_READ(dentry, d_inode, i_size);
  bpf_probe_read_str(event.filename, sizeof(event.filename),
                     BPF_CORE_READ(dentry, d_name.name));
  bpf_map_update_elem(&LruMap, &pid_tgid, &event, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode, int ret) {

  if (ret < 0)
    goto out;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct EVENT *event;
  event = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!event)
    goto out;

  copy_and_submit_event(event);
out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);

  return 0;
}

/* ───────────────────────────────────────────── */
/* RMDIR                                        */
/* ───────────────────────────────────────────── */

SEC("fentry/vfs_rmdir")
int BPF_PROG(fentry_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry) {

  // check if folder is monitored
  if (!is_monitored(dir))
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  struct EVENT event = {};
  event.parent_inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  event.parent_dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  event.inode = BPF_CORE_READ(dir, i_ino);
  event.dev = BPF_CORE_READ(dir, i_sb, s_dev);
  event.giduid = bpf_get_current_uid_gid();
  event.change_type = DELETE_EVENT;
  event.reserved = 0;
  event.file_size = BPF_CORE_READ(dir, i_size);
  bpf_probe_read_str(event.filename, sizeof(event.filename),
                     BPF_CORE_READ(dentry, d_name.name));
  bpf_map_update_elem(&LruMap, &pid_tgid, &event, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, int ret) {

  if (ret < 0)
    goto out;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct EVENT *event;
  event = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!event)
    goto out;

  copy_and_submit_event(event);
out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);

  return 0;
}

/* ───────────────────────────────────────────── */
/* RENAME (delete + create model)               */
/* ───────────────────────────────────────────── */
SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, struct renamedata *rd) {
  u64 key = bpf_get_current_pid_tgid();
  struct EVENT ev = {};

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  if (!old_dir || !new_dir || !old_dentry || !new_dentry)
    return 0;

  struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
  if (!inode)
    return 0;

  ev.inode = BPF_CORE_READ(inode, i_ino);
  ev.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  ev.file_size = BPF_CORE_READ(inode, i_size);

  ev.parent_inode = BPF_CORE_READ(old_dir, i_ino);
  ev.parent_dev = BPF_CORE_READ(old_dir, i_sb, s_dev);

  __u32 uid = BPF_CORE_READ(inode, i_uid.val);
  __u32 gid = BPF_CORE_READ(inode, i_gid.val);
  ev.giduid = ((__u64)gid << 32) | uid;

  bpf_probe_read_str(ev.filename, sizeof(ev.filename),
                     BPF_CORE_READ(old_dentry, d_name.name));

  struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
  if (target)
    ev.reserved = 1;

  bpf_printk("[RENAME-ENTRY] inode=%llu old_parent=%llu name=%s overwrite=%u\n",
             ev.inode, ev.parent_inode, ev.filename, ev.reserved);

  bpf_map_update_elem(&LruMap, &key, &ev, BPF_ANY);
  return 0;
}
SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, struct renamedata *rd, int ret) {
  u64 key = bpf_get_current_pid_tgid();
  struct EVENT *ev = bpf_map_lookup_elem(&LruMap, &key);

  if (!ev)
    return 0;

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  if (ret != 0) {
    bpf_printk("[RENAME-EXIT] FAILED ret=%d inode=%llu\n", ret, ev->inode);
    goto cleanup;
  }

  bool old_mon = old_dir && is_monitored(old_dir);
  bool new_mon = new_dir && is_monitored(new_dir);

  bpf_printk(
      "[RENAME-EXIT] SUCCESS inode=%llu old_mon=%d new_mon=%d overwrite=%u\n",
      ev->inode, old_mon, new_mon, ev->reserved);

  /*
   * 1️⃣ DELETE old path
   */
  if (old_mon) {
    ev->change_type = DELETE_EVENT;

    bpf_printk("  -> DELETE old path parent=%llu name=%s\n", ev->parent_inode,
               ev->filename);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);
    update_dir_map(old_dentry, false);
  }

  /*
   * 2️⃣ DELETE overwritten target
   */
  if (new_mon && ev->reserved) {
    ev->change_type = DELETE_EVENT;
    ev->parent_inode = BPF_CORE_READ(new_dir, i_ino);
    ev->parent_dev = BPF_CORE_READ(new_dir, i_sb, s_dev);

    bpf_printk("  -> DELETE overwritten target parent=%llu\n",
               ev->parent_inode);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);
  }

  /*
   * 3️⃣ CREATE new path
   */
  if (new_mon) {
    ev->change_type = CREATE_EVENT;

    ev->parent_inode = BPF_CORE_READ(new_dir, i_ino);
    ev->parent_dev = BPF_CORE_READ(new_dir, i_sb, s_dev);

    bpf_probe_read_str(ev->filename, sizeof(ev->filename),
                       BPF_CORE_READ(new_dentry, d_name.name));

    bpf_printk("  -> CREATE new path parent=%llu name=%s\n", ev->parent_inode,
               ev->filename);

    bpf_ringbuf_output(&rb, ev, sizeof(*ev), 0);

    update_dir_map(new_dentry, true);
  }

cleanup:
  bpf_map_delete_elem(&LruMap, &key);
  return 0;
}
char LICENSE[] SEC("license") = "GPL";