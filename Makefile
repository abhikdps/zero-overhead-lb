CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BUILD_DIR := build
BPF_SRC   := src/bpf/xdp_lb_kern.c
BPF_OBJ   := $(BUILD_DIR)/xdp_lb_kern.o
BPF_SKEL  := $(BUILD_DIR)/xdp_lb_kern.skel.h
VMLINUX   := src/bpf/vmlinux.h
USR_SRCS  := $(wildcard src/user/*.c)
TARGET    := $(BUILD_DIR)/zlb

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wall -Werror -I src/bpf

USR_CFLAGS  := -O2 -g -Wall -Werror -I $(BUILD_DIR) -I src/bpf
USR_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean vmlinux help

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

# Generate vmlinux.h from kernel BTF
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) src/bpf/xdp_lb_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build userspace binary
$(TARGET): $(USR_SRCS) $(BPF_SKEL) src/bpf/xdp_lb_common.h | $(BUILD_DIR)
	$(CC) $(USR_CFLAGS) -o $@ $(USR_SRCS) $(USR_LDFLAGS)

vmlinux: $(VMLINUX)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(VMLINUX)

help:
	@echo "Targets:"
	@echo "  all      Build everything (default)"
	@echo "  vmlinux  Generate vmlinux.h from kernel BTF"
	@echo "  clean    Remove build artifacts"
	@echo "  help     Show this message"
