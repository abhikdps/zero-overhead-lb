CLANG        ?= clang
BPFTOOL      ?= bpftool
CC           ?= cc
CLANG_FORMAT ?= clang-format
CPPCHECK     ?= cppcheck

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BUILD_DIR := build
BPF_SRC   := src/bpf/xdp_lb_kern.c
BPF_OBJ   := $(BUILD_DIR)/xdp_lb_kern.o
BPF_SKEL  := $(BUILD_DIR)/xdp_lb_kern.skel.h
VMLINUX   := src/bpf/vmlinux.h
USR_SRCS  := $(wildcard src/user/*.c) src/vendor/cJSON.c
TARGET    := $(BUILD_DIR)/zlb

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wall -Werror -I src/bpf

USR_CFLAGS  := -O2 -g -Wall -Werror -I $(BUILD_DIR) -I src/bpf -I src/vendor \
               -I src/user
USR_LDFLAGS := -lbpf -lelf -lz -lpthread

SRC_FILES := $(wildcard src/user/*.c src/user/*.h src/bpf/xdp_lb_common.h)

.PHONY: all clean vmlinux test bench fmt fmt-check check help

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

test: $(TARGET)
	@echo "Prerequisites: sudo scripts/setup_testbed.sh && LB attached"
	sudo pytest tests/test_lb.py -v --tb=short

bench: $(TARGET)
	@echo "Prerequisites: sudo scripts/setup_testbed.sh && LB attached"
	sudo bash tests/bench_pps.sh $(or $(BENCH_DURATION),10)

fmt:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || \
		{ echo "Error: $(CLANG_FORMAT) not found. Install with: sudo apt install clang-format"; exit 1; }
	$(CLANG_FORMAT) -i $(SRC_FILES)
	@echo "Formatted $(words $(SRC_FILES)) files"

fmt-check:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || \
		{ echo "Error: $(CLANG_FORMAT) not found. Install with: sudo apt install clang-format"; exit 1; }
	@$(CLANG_FORMAT) --dry-run --Werror $(SRC_FILES) && \
		echo "All files formatted correctly" || \
		{ echo "Run 'make fmt' to fix formatting"; exit 1; }

check:
	@command -v $(CPPCHECK) >/dev/null 2>&1 || \
		{ echo "Error: $(CPPCHECK) not found. Install with: sudo apt install cppcheck"; exit 1; }
	$(CPPCHECK) --enable=warning,style,performance --error-exitcode=1 \
		--suppress=missingIncludeSystem --quiet \
		-I src/bpf -I src/vendor -I src/user \
		$(filter %.c,$(SRC_FILES))

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(VMLINUX)

help:
	@echo "Targets:"
	@echo "  all        Build everything (default)"
	@echo "  vmlinux    Generate vmlinux.h from kernel BTF"
	@echo "  clean      Remove build artifacts"
	@echo "  test       Run functional tests (requires testbed + LB attached)"
	@echo "  bench      Run performance benchmark (BENCH_DURATION=N for seconds)"
	@echo "  fmt        Format C source files with clang-format"
	@echo "  fmt-check  Check formatting without modifying files"
	@echo "  check      Run static analysis with cppcheck"
	@echo "  help       Show this message"
