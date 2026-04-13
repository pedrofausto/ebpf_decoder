CLANG       ?= clang
BPFTOOL     ?= bpftool
ARCH        := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_VER  := $(shell uname -r)
VMLINUX_H   := vmlinux/vmlinux.h
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
               -I./kernel/common -I./vmlinux \
               -mcpu=v3

BPF_SOURCES := kernel/layer1_xdp/xdp_edge.bpf.c \
               kernel/layer1_tc/tc_stateful.bpf.c \
               kernel/layer2_capture/uprobe_tls.bpf.c \
               kernel/layer2_capture/socket_filter.bpf.c \
               kernel/layer3_data/dynptr_handler.bpf.c \
               kernel/layer4_transport/ringbuf_producer.bpf.c \
               kernel/layer4_transport/user_ringbuf_consumer.bpf.c

BPF_OBJECTS := $(BPF_SOURCES:.c=.o)
SKELS       := $(BPF_OBJECTS:.o=.skel.h)

.PHONY: all clean vmlinux skeletons kernel userspace

all: vmlinux skeletons kernel userspace

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@mkdir -p vmlinux
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

%.o: %.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

skeletons: $(BPF_OBJECTS)
	@mkdir -p userspace/loader/src/skels
	@for obj in $(BPF_OBJECTS); do \
		name=$$(basename $$obj .bpf.o); \
		$(BPFTOOL) gen skeleton $$obj > userspace/loader/src/skels/$$name.skel.h; \
	done

kernel: $(BPF_OBJECTS)
	@echo "[+] All BPF objects compiled"

userspace:
	cargo build --release --workspace

clean:
	find kernel -name "*.o" -delete
	find userspace -name "*.skel.h" -delete
	rm -rf userspace/loader/src/skels
	cargo clean
	rm -f $(VMLINUX_H)
