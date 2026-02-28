#ifndef __MAPS_H
#define __MAPS_H

#include "types.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Monitored directories */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct KEY);
  __type(value, struct VALUE);
} InodeMap SEC(".maps");

/* Ring buffer */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
} rb SEC(".maps");

/** LRU hash map for fentry/fexit communication */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, struct dentry_ctx);
} LruMap SEC(".maps");

/* heap scratch space for dentry_ctx */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dentry_ctx);
} scratch_dentry_ctx SEC(".maps");
#endif /* __MAPS_H */
