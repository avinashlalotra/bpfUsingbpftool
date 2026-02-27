#include "../include/helpers.h"
#include "../include/maps.h"
#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Unlink - file deletion
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
  event.bytes_written = 0;
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

  copy_and_submit_event("fexit_vfs_unlink", event);
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
  event.parent_inode = BPF_CORE_READ(dir, i_ino);
  event.parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
  event.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  event.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  event.giduid = bpf_get_current_uid_gid();
  event.change_type = DELETE_EVENT;
  event.bytes_written = 0;
  event.file_size = BPF_CORE_READ(dir, i_size);
  bpf_probe_read_str(event.filename, sizeof(event.filename),
                     BPF_CORE_READ(dentry, d_name.name));
  bpf_map_update_elem(&LruMap, &pid_tgid, &event, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, int ret) {

  struct KEY key = {};
  if (ret < 0)
    goto out;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct EVENT *event;
  event = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!event)
    goto out;

  // delete entry from inode map
  key.inode = event->inode;
  bpf_map_delete_elem(&InodeMap, &key);

  copy_and_submit_event("fexit_vfs_rmdir", event);
out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);

  return 0;
}