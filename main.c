#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 255
#define WRITE_EVENT 0x3

struct KEY {
  __u64 inode;
};
struct VALUE {
  __u64 chuma;
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

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write, struct file *file, const char *buf, size_t count,
             loff_t *pos, long ret) {

  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("vfs_write: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_printk("vfs_write: %d %llu %llu %llu %llu %llu %u %lld %s",
             event->change_type, event->inode, event->dev, event->parent_inode,
             event->parent_dev, event->giduid, event->bytes_written,
             event->file_size, event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";

SEC("fexit/vfs_writev")
int BPF_PROG(vfs_writev, struct file *file, const struct iovec *vec,
             unsigned long vlen, loff_t *pos, rwf_t flags, long ret) {

  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("vfs_writev: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_printk("vfs_writev: %d %llu %llu %llu %llu %llu %u %lld %s",
             event->change_type, event->inode, event->dev, event->parent_inode,
             event->parent_dev, event->giduid, event->bytes_written,
             event->file_size, event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// Splice syscall
SEC("fexit/__do_splice")
int BPF_PROG(do_splice, struct file *in, loff_t *off_in, struct file *out,
             loff_t *off_out, size_t len, unsigned int flags, long ret) {

  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(out, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("do_splice: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(out, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(out, f_inode, i_ino);
  event->dev = BPF_CORE_READ(out, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(out, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(out, f_inode, i_size);

  bpf_printk("do_splice: %d %llu %llu %llu %llu %llu %u %lld %s",
             event->change_type, event->inode, event->dev, event->parent_inode,
             event->parent_dev, event->giduid, event->bytes_written,
             event->file_size, event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// copy file range syscall
SEC("fexit/vfs_copy_file_range")
int BPF_PROG(vfs_copy_file_range, struct file *file_in, loff_t pos_in,
             struct file *file_out, loff_t pos_out, size_t len,
             unsigned int flags, ssize_t ret) {

  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(file_out, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("vfs_copy_file_range: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(file_out, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(file_out, f_inode, i_ino);
  event->dev = BPF_CORE_READ(file_out, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file_out, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(file_out, f_inode, i_size);

  bpf_printk("vfs_copy_file_range: %d %llu %llu %llu %llu %llu %u %lld %s",
             event->change_type, event->inode, event->dev, event->parent_inode,
             event->parent_dev, event->giduid, event->bytes_written,
             event->file_size, event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// sendfile and vfs_copy_file_range
SEC("fexit/do_splice_direct")
int BPF_PROG(sendfile_do_splice_direct, struct file *in, loff_t *ppos,
             struct file *out, loff_t *opos, size_t len, unsigned int flags,
             ssize_t ret) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(out, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk(
        "sendfile_do_splice_direct: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(out, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(out, f_inode, i_ino);
  event->dev = BPF_CORE_READ(out, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(out, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(out, f_inode, i_size);

  bpf_printk(
      "sendfile_do_splice_direct: %d %llu %llu %llu %llu %llu %u %lld %s",
      event->change_type, event->inode, event->dev, event->parent_inode,
      event->parent_dev, event->giduid, event->bytes_written, event->file_size,
      event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

#define PROT_WRITE 0x2
#define MAP_SHARED 0x01

/// Mmap
SEC("lsm/mmap_file")
int BPF_PROG(handle_mmap, struct file *file, unsigned long prot,
             unsigned long flags) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("mmap: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = 0;
  event->file_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_printk("mmap: %d %llu %llu %llu %llu %llu %u %lld %s", event->change_type,
             event->inode, event->dev, event->parent_inode, event->parent_dev,
             event->giduid, event->bytes_written, event->file_size,
             event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// fallocate
SEC("fexit/vfs_fallocate")
int BPF_PROG(handle_fallocate, struct file *file, int mode, loff_t offset,
             loff_t len, ssize_t ret) {
  struct KEY key;
  struct VALUE *value;
  struct EVENT *event;
  const unsigned char *name;

  if (ret < 0)
    return 0;

  // check if parent directory is being monitored or not
  key.inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  value = bpf_map_lookup_elem(&InodeMap, &key);

  // if no such key id found return
  if (!value) {
    return 0;
  }

  // if key exist then colect the event details and send it to the ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("fallocate: Failed to reserve ring buffer space\n");
    return 0;
  }

  event->parent_inode = key.inode;
  event->parent_dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  event->inode = BPF_CORE_READ(file, f_inode, i_ino);
  event->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  event->giduid = bpf_get_current_uid_gid();

  name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
  bpf_probe_read_str(event->filename, sizeof(event->filename), name);

  event->change_type = WRITE_EVENT;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(file, f_inode, i_size);

  bpf_printk("fallocate: %d %llu %llu %llu %llu %llu %u %lld %s",
             event->change_type, event->inode, event->dev, event->parent_inode,
             event->parent_dev, event->giduid, event->bytes_written,
             event->file_size, event->filename);

  bpf_ringbuf_submit(event, 0);

  return 0;
}