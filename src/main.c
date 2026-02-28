#define DEBUG
#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>

// #include "create.bpf.c"
#include "delete.bpf.c"
#include "helpers.bpf.c"
// #include "modify.bpf.c"
// #include "rename.bpf.c"

char LICENSE[] SEC("license") = "GPL";
