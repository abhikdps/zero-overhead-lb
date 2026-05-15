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
        │  Check conn table     │
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

**Data plane** (kernel, XDP/eBPF): Parses raw Ethernet frames (with VLAN support), matches destination IP:port against a virtual IP table, checks the connection table for session affinity or hashes the source IP for consistent backend selection, rewrites L2/L3 headers, incrementally recalculates IP and L4 checksums, and transmits via `XDP_TX` — all in a single pass, before the packet reaches the kernel networking stack.

**Control plane** (userspace): Manages the BPF program lifecycle, populates VIP and backend maps from CLI arguments, and exposes per-backend statistics via BPF maps.

## Project Structure

```
├── src/
│   ├── bpf/
│   │   ├── xdp_lb_kern.c       # XDP load balancer (data plane)
│   │   ├── xdp_lb_common.h     # Shared structs (BPF ↔ userspace)
│   │   ├── xdp_pass.c          # Reference: minimal pass-through
│   │   └── xdp_parse.c         # Reference: packet parser prototype
│   └── user/
│       └── main.c              # CLI: load, attach, configure, detach
├── scripts/
│   ├── setup_testbed.sh         # Create bridge + namespace test environment
│   └── teardown_testbed.sh      # Clean up test environment
├── config/                      # Sample configurations
├── tests/                       # Functional and performance tests
├── docs/                        # Architecture and testing docs
└── Makefile
```

## BPF Maps

| Map | Type | Key → Value | Purpose |
|-----|------|-------------|---------|
| `vip_table` | Hash | `{ip, port, proto}` → `{backend_count, start_idx}` | Identify virtual IPs to load-balance |
| `backends` | Array | index → `{ip, port, mac}` | Backend server pool |
| `connection_table` | LRU Hash | `{src_ip, src_port, proto}` → `{backend_idx}` | Session affinity (sticky connections) |
| `stats` | Per-CPU Array | index → `{packets, bytes}` | Per-backend counters (lock-free) |
| `lb_config` | Array | 0 → `{lb_mac}` | Load balancer interface MAC address |

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
# Attach with a VIP and backends
sudo build/zlb start -i eth0 \
    -v 10.0.0.100:80:tcp \
    -b 10.0.0.2:80:aa:bb:cc:dd:ee:01 \
    -b 10.0.0.3:80:aa:bb:cc:dd:ee:02

# Detach from an interface
sudo build/zlb stop -i eth0
```

**Flags:**
- `-i <interface>` — network interface to attach XDP program to
- `-v <ip>:<port>:<tcp|udp>` — virtual IP address to load-balance
- `-b <ip>:<port>:<mac>` — backend server (repeat for multiple backends)

The program attaches in SKB (generic) mode by default. Non-VIP traffic passes through to the kernel stack unmodified.

## Testing

A bridge-based network namespace testbed is included for local testing without physical servers.

```bash
# Set up the testbed (creates client, LB, and backend namespaces on a bridge)
sudo scripts/setup_testbed.sh

# The script prints interface MACs and example commands to run

# Tear down when done
sudo scripts/teardown_testbed.sh
```

### Testbed Topology

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  client-ns   │    │    lb-ns     │    │   be1-ns     │    │   be2-ns     │
│  10.0.0.10   │    │  10.0.0.1    │    │  10.0.0.2    │    │  10.0.0.3    │
│              │    │  VIP: .100   │    │  HTTP :80    │    │  HTTP :80    │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       └───────────────────┴───────────────────┴───────────────────┘
                              br-zlb (bridge)
```

### Verification

```bash
# In one terminal — start tcpdump on a backend
sudo ip netns exec be1-ns tcpdump -i veth-be1-ns -nn tcp

# In another — attach the LB inside lb-ns
sudo ip netns exec lb-ns build/zlb start -i veth-lb-ns \
    -v 10.0.0.100:80:tcp \
    -b 10.0.0.2:80:<be1-mac> \
    -b 10.0.0.3:80:<be2-mac>

# In another — send traffic from client
sudo ip netns exec client-ns hping3 -S -p 80 10.0.0.100 -c 3

# Check per-backend stats
sudo bpftool map dump name stats
```

You should see packets arriving at the backend with rewritten destination IP and MAC, valid checksums (backend kernel responds with SYN-ACK), and stats counters incrementing.

## How It Works

1. **Packet parsing**: The XDP program parses the raw byte stream — Ethernet header (with optional 802.1Q VLAN tag), IP header (variable-length via `ihl`), and TCP/UDP header. Every pointer dereference is bounds-checked against `data_end` to satisfy the BPF verifier.

2. **VIP lookup**: The destination `{IP, port, protocol}` is looked up in the `vip_table` hash map. Misses are passed to the kernel stack (`XDP_PASS`).

3. **Connection affinity**: The `{source IP, source port, protocol}` tuple is looked up in an LRU hash map. On a hit, the same backend is reused. On a miss, a Knuth multiplicative hash of the source IP selects a backend, and the mapping is stored for future packets.

4. **Header rewriting**: The destination MAC is set to the backend's MAC. The source MAC is set to the LB's MAC (captured from the incoming packet). The destination IP is changed from the VIP to the backend's real IP.

5. **Checksum recalculation**: IP and L4 (TCP/UDP) checksums are updated incrementally using `bpf_csum_diff()` — only the changed fields are recalculated, not the entire header. UDP checksums of 0 are preserved per RFC 768.

6. **Forwarding**: The rewritten packet is sent back out the same interface via `XDP_TX`, where the L2 network (switch/bridge) delivers it to the backend based on the new destination MAC.

## License

[MIT](LICENSE)
