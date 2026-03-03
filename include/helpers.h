
#ifndef __HELPERS_H
#define __HELPERS_H

#include "types.h"

static bool is_monitored(struct inode *dir);
static void update_dir_map(struct dentry *dentry, bool add);
static void emit_event(const char *msg, struct inode *parent_inode,
                       struct dentry *dentry, __u8 type);
static void print_event(const char *msg, struct EVENT *event);
static void construct_path(struct dentry *dentry, char *path);
#endif /* __HELPERS_H */