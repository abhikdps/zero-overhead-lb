# Zero-Overhead Load Balancer

A Layer 4 (TCP/UDP) load balancer that routes packets at the NIC driver level using eBPF/XDP, completely bypassing the Linux kernel's networking stack.

Packets are parsed, rewritten, and forwarded before `sk_buff` allocation, interrupts, or any TCP/IP stack traversal — the same technique used by Cloudflare, Facebook (Katran), and high-frequency trading infrastructure to handle millions of packets per second with minimal CPU overhead.

## Architecture

```
              Incoming packet
                    │
                    ▼
        ┌───────────────────────┐
        │   NIC Driver (XDP)    │
        │                       │
        │  Parse Eth/IP/TCP/UDP │
        │  Lookup VIP table     │──── miss ──── XDP_PASS ──► kernel stack
        │  Hash src IP          │
        │  Select backend       │
        │  Rewrite MAC + IP     │
        │  Recalculate checksum │
        │  XDP_TX               │
        └───────────┬───────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │Backend 1│ │Backend 2│ │Backend 3│
   └─────────┘ └─────────┘ └─────────┘
```

**Data plane** (kernel, XDP/eBPF): Parses raw Ethernet frames, matches destination IP:port against a virtual IP table, hashes the source IP for consistent backend selection, rewrites L2/L3 headers, fixes checksums, and transmits via `XDP_TX` — all in a single pass, before the packet reaches the kernel networking stack.

**Control plane** (userspace): Manages the BPF program lifecycle, populates VIP and backend maps, runs health checks, and exposes per-backend statistics.

## Project Structure

```
├── src/
│   ├── bpf/
│   │   ├── xdp_lb_kern.c       # XDP load balancer program
│   │   ├── xdp_lb_common.h     # Shared structs (BPF ↔ userspace)
│   │   ├── xdp_pass.c          # Reference: minimal pass-through
│   │   └── xdp_parse.c         # Reference: packet parser prototype
│   └── user/
│       └── main.c              # CLI: load, attach, detach
├── config/                      # Sample configurations
├── scripts/                     # Test environment setup
├── tests/                       # Functional and performance tests
├── docs/                        # Architecture and testing docs
└── Makefile
```

## BPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `vip_table` | Hash | Maps virtual IP:port:protocol → backend pool metadata |
| `backends` | Array | Backend server addresses and MAC addresses |
| `stats` | Per-CPU Array | Per-backend packet and byte counters (lock-free) |
| `connection_table` | LRU Hash | Source IP:port → backend index for session affinity |

## Requirements

- Linux kernel ≥ 5.15 (BTF, ring buffer, bounded loops)
- clang ≥ 14 (BPF target)
- libbpf-dev ≥ 0.8
- bpftool
- libelf-dev, zlib1g-dev

### Install on Ubuntu 24.04

```bash
sudo apt install clang llvm libbpf-dev linux-tools-common \
    linux-tools-$(uname -r) libelf-dev zlib1g-dev pkg-config
```

> **Note**: XDP programs cannot run on macOS. Use a Linux machine, VM, or [Lima](https://github.com/lima-vm/lima) instance for development.

## Build

```bash
make            # build everything
make clean      # remove build artifacts
make help       # list all targets
```

The build pipeline:
1. Generates `vmlinux.h` from kernel BTF (CO-RE portability)
2. Compiles BPF C → BPF ELF object with clang
3. Generates a BPF skeleton header with bpftool
4. Compiles the userspace binary against libbpf

Output: `build/zlb`

## Usage

```bash
# Attach to an interface
sudo build/zlb start -i eth0

# Detach from an interface
sudo build/zlb stop -i eth0
```

The program attaches in SKB (generic) mode by default. Non-VIP traffic passes through to the kernel stack unmodified.

## Testing

A bridge-based network namespace testbed is included for local testing without physical servers.

## License

[MIT](LICENSE)
