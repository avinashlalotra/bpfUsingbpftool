F ?= folder

BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -Iinclude

BPF_SRCS := $(wildcard src/*.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

FINAL_BPF := fim.bpf.o

FINAL_BPF := fim.bpf.o

all: vmlinux $(FINAL_BPF)

$(FINAL_BPF):
	$(BPF_CLANG) $(BPF_CFLAGS) -c src/main.c -o $@
# Dump vmlinux BTF header
vmlinux:
	@echo "[+] Dumping vmlinux BTF for CO-RE"
	@mkdir -p include
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# Load program
load:
	sudo bpftool prog loadall $(FINAL_BPF) /sys/fs/bpf/myprog autoattach

# Unload program
unload:
	sudo rm -rf /sys/fs/bpf/myprog

# Trace logs
showlog:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Add folder to monitored map
map:
	mkdir -p $(F)
	sudo bpftool map update id $$(./scripts/getMapid.sh) \
		key $$(./scripts/printInodeHex.sh $(F)) \
		value 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
	$(MAKE) -B dump

# Dump map
dump:
	sudo bpftool map dump id $$(./scripts/getMapid.sh)

clean:
	rm -f src/*.bpf.o $(FINAL_BPF)
	rm -f include/vmlinux.h