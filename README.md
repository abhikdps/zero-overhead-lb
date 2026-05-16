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

**Control plane** (userspace): Manages the BPF program lifecycle, loads VIP and backend configuration from JSON config files or CLI arguments, runs TCP health checks with automatic failover, pins BPF maps for cross-process access, and provides live per-backend statistics.

## Project Structure

```
├── src/
│   ├── bpf/
│   │   ├── xdp_lb_kern.c       # XDP load balancer (data plane)
│   │   ├── xdp_lb_common.h     # Shared structs (BPF ↔ userspace)
│   │   ├── xdp_pass.c          # Reference: minimal pass-through
│   │   └── xdp_parse.c         # Reference: packet parser prototype
│   ├── user/
│   │   ├── main.c              # CLI: start, stop, stats, status
│   │   ├── config.c / .h       # JSON config parsing (cJSON)
│   │   ├── stats.c / .h        # Per-CPU stats aggregation + display
│   │   └── health.c / .h       # TCP health checks (pthread)
│   └── vendor/
│       └── cJSON.c / .h        # Vendored JSON parser (MIT)
├── scripts/
│   ├── setup_testbed.sh         # Create bridge + namespace test environment
│   └── teardown_testbed.sh      # Clean up test environment
├── config/
│   └── example.json             # Sample configuration
├── tests/
│   ├── conftest.py              # Pytest fixtures: namespace helpers, packet capture
│   ├── test_lb.py               # Functional tests (scapy-based)
│   └── bench_pps.sh             # Performance benchmark (hping3 flood)
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
make test       # run functional tests (requires testbed + LB)
make bench      # run performance benchmark
make help       # list all targets
```

The build pipeline:
1. Generates `vmlinux.h` from kernel BTF (CO-RE portability)
2. Compiles BPF C → BPF ELF object with clang
3. Generates a BPF skeleton header with bpftool
4. Compiles the userspace binary against libbpf

Output: `build/zlb`

## Usage

### Start with a config file

```bash
sudo build/zlb start -i eth0 -c config/example.json
```

Sample `config/example.json`:
```json
{
  "interface": "eth0",
  "vip": { "address": "10.0.0.100", "port": 80, "protocol": "tcp" },
  "backends": [
    { "address": "10.0.0.2", "port": 80, "mac": "aa:bb:cc:dd:ee:01" },
    { "address": "10.0.0.3", "port": 80, "mac": "aa:bb:cc:dd:ee:02" }
  ],
  "health": { "interval": 5, "timeout": 2000 }
}
```

### Start with CLI flags

```bash
sudo build/zlb start -i eth0 \
    -v 10.0.0.100:80:tcp \
    -b 10.0.0.2:80:aa:bb:cc:dd:ee:01 \
    -b 10.0.0.3:80:aa:bb:cc:dd:ee:02
```

### Other commands

```bash
sudo build/zlb stats        # show per-backend packet/byte counters
sudo build/zlb stats -w     # live watch mode (updates every second with PPS)
sudo build/zlb status       # show pinned map status
sudo build/zlb stop -i eth0 # detach XDP program
```

The program attaches in SKB (generic) mode by default. Non-VIP traffic passes through to the kernel stack unmodified. BPF maps are pinned to `/sys/fs/bpf/zlb/` for cross-process access.

### Health checking

When started with a config file, TCP health checks run automatically in a background thread:
- Connects to each backend's `address:port` every `interval` seconds
- 3 consecutive failures → backend marked **DOWN**, traffic shifted to healthy backends
- 2 consecutive successes → backend marked **UP**, traffic restored
- On shutdown, original backend configuration is restored

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

# In another — attach the LB (use nsenter to keep bpffs accessible)
sudo nsenter --net=/var/run/netns/lb-ns build/zlb start \
    -i veth-lb-ns -c config/example.json

# In another — send traffic from client
sudo ip netns exec client-ns hping3 -S -p 80 10.0.0.100 -c 3

# Check per-backend stats
sudo bpftool map dump name stats
```

You should see packets arriving at the backend with rewritten destination IP and MAC, valid checksums (backend kernel responds with SYN-ACK), and stats counters incrementing.

> **Note**: Use `nsenter --net=/var/run/netns/<ns>` instead of `ip netns exec` when running `zlb start` inside a namespace. This enters only the network namespace while keeping the root mount namespace, so BPF map pinning to `/sys/fs/bpf/zlb/` works correctly and `zlb stats`/`zlb status` can access the maps from outside.

### Functional Tests

The test suite uses [scapy](https://scapy.net/) and [pytest](https://pytest.org/) to send crafted packets through the load balancer and verify correct behavior.

```bash
# Install test dependencies
sudo apt install python3-pytest python3-scapy hping3

# Set up testbed and attach the LB
sudo scripts/setup_testbed.sh
sudo nsenter --net=/var/run/netns/lb-ns build/zlb start \
    -i veth-lb-ns -c config/example.json &

# Run all functional tests
sudo pytest tests/test_lb.py -v
```

Tests cover:

| Test | What it verifies |
|------|------------------|
| TCP SYN to VIP | Packet arrives at backend with rewritten MAC/IP, valid checksums |
| UDP to VIP | Same as above for UDP, including checksum handling |
| Connection affinity | Same source IP:port always reaches the same backend |
| Source distribution | Different source IPs are spread across backends |
| Non-VIP passthrough | Traffic to the LB's own IP bypasses XDP (kernel handles it) |
| ICMP passthrough | Ping to VIP works (ICMP is non-TCP/UDP, passed to kernel) |
| ARP passthrough | ARP resolution works through the XDP program |
| Stats increment | Per-backend packet counters update correctly |

Some XDP code paths (truncated headers, VLAN tags) cannot be tested in generic/SKB mode because the kernel validates packets before XDP processes them. These tests are documented as skipped.

### Performance Benchmark

```bash
# Run a 10-second hping3 flood through the LB and measure PPS
sudo bash tests/bench_pps.sh 10

# Or via make (default 10 seconds, override with BENCH_DURATION)
make bench BENCH_DURATION=30
```

The benchmark uses `hping3 --flood` to generate TCP SYN traffic, reads per-backend stats from the pinned BPF maps before and after, and reports packets per second, throughput, and per-backend distribution.

## How It Works

1. **Packet parsing**: The XDP program parses the raw byte stream — Ethernet header (with optional 802.1Q VLAN tag), IP header (variable-length via `ihl`), and TCP/UDP header. Every pointer dereference is bounds-checked against `data_end` to satisfy the BPF verifier.

2. **VIP lookup**: The destination `{IP, port, protocol}` is looked up in the `vip_table` hash map. Misses are passed to the kernel stack (`XDP_PASS`).

3. **Connection affinity**: The `{source IP, source port, protocol}` tuple is looked up in an LRU hash map. On a hit, the same backend is reused. On a miss, a Knuth multiplicative hash of the source IP selects a backend, and the mapping is stored for future packets.

4. **Header rewriting**: The destination MAC is set to the backend's MAC. The source MAC is set to the LB's MAC (captured from the incoming packet). The destination IP is changed from the VIP to the backend's real IP.

5. **Checksum recalculation**: IP and L4 (TCP/UDP) checksums are updated incrementally using `bpf_csum_diff()` — only the changed fields are recalculated, not the entire header. UDP checksums of 0 are preserved per RFC 768.

6. **Forwarding**: The rewritten packet is sent back out the same interface via `XDP_TX`, where the L2 network (switch/bridge) delivers it to the backend based on the new destination MAC.

## License

[MIT](LICENSE)
