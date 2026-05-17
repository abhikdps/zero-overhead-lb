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
        │  Drop fragments       │──── frag ──── XDP_PASS ──► kernel stack
        │  Own-IP check         │──── own  ──── XDP_PASS ──► kernel stack
        │  Lookup VIP table     │──── miss ──── XDP_PASS ──► kernel stack
        │  Check conn table     │
        │  Hash src IP          │            ┌─────────────┐
        │  Select backend       │            │ Ring buffer  │
        │  Rewrite MAC + IP     │──events──► │ (events map) │
        │  Recalculate checksum │            └──────┬──────┘
        │  XDP_TX / REDIRECT    │                   │
        └───────────┬───────────┘              zlb events
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │Backend 1│ │Backend 2│ │Backend 3│
   │  w=3    │ │  w=1    │ │  w=1    │
   └─────────┘ └─────────┘ └─────────┘
```

**Data plane** (kernel, XDP/eBPF): Parses raw Ethernet frames (with VLAN support), drops IP fragments early, passes LB-destined traffic to the kernel, matches destination IP:port against a virtual IP table, checks the connection table for session affinity or hashes the source IP for consistent backend selection, rewrites L2/L3 headers, incrementally recalculates IP and L4 checksums, and forwards via `XDP_TX` or `XDP_REDIRECT` — all in a single pass, before the packet reaches the kernel networking stack. A ring buffer streams structured events to userspace for real-time observability.

**Control plane** (userspace): Manages the BPF program lifecycle, loads VIP and backend configuration from JSON config files or CLI arguments, supports weighted round-robin distribution, runs TCP health checks with automatic failover (weight-aware), supports hitless reload of backend configuration without detaching the XDP program, pins BPF maps for cross-process access, and provides live per-backend statistics and event streaming.

## Project Structure

```
├── src/
│   ├── bpf/
│   │   ├── xdp_lb_kern.c       # XDP load balancer (data plane)
│   │   ├── xdp_lb_common.h     # Shared structs + event types (BPF ↔ userspace)
│   │   ├── xdp_pass.c          # Reference: minimal pass-through
│   │   └── xdp_parse.c         # Reference: packet parser prototype
│   ├── user/
│   │   ├── main.c              # CLI: start, stop, stats, status, events, reload
│   │   ├── config.c / .h       # JSON config parsing + validation (cJSON)
│   │   ├── stats.c / .h        # Per-CPU stats aggregation + display
│   │   ├── health.c / .h       # TCP health checks (pthread, weight-aware)
│   │   └── events.c / .h       # Ring buffer event consumer
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
| `backends` | Array (256) | index → `{ip, port, mac}` | Backend server pool (weight-expanded) |
| `connection_table` | LRU Hash (262K) | `{src_ip, src_port, proto}` → `{backend_idx}` | Session affinity (sticky connections) |
| `stats` | Per-CPU Array | index → `{packets, bytes}` | Per-backend counters (lock-free) |
| `lb_config` | Array | 0 → `{lb_mac, lb_ip, use_redirect}` | LB interface config + forwarding mode |
| `events` | Ring Buffer (256 KB) | — | Structured event stream to userspace |
| `tx_port` | DEVMAP | 0 → ifindex | Egress interface for XDP_REDIRECT |
| `event_counter` | Per-CPU Array | 0 → counter | Rate-limit FORWARD event sampling |

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
    { "address": "10.0.0.2", "port": 80, "mac": "aa:bb:cc:dd:ee:01", "weight": 3 },
    { "address": "10.0.0.3", "port": 80, "mac": "aa:bb:cc:dd:ee:02", "weight": 1 }
  ],
  "health": { "interval": 5, "timeout": 2000 },
  "redirect": { "enabled": false, "egress_iface": "" }
}
```

- **weight** (1-10, default 1): Controls traffic distribution. A backend with `weight: 3` receives 3x the traffic of one with `weight: 1`. Implemented by expanding backends into proportional array slots — the BPF hash selects uniformly across all slots.
- **redirect**: When `enabled: true`, the LB uses `XDP_REDIRECT` via a DEVMAP to forward packets out `egress_iface` instead of the ingress NIC (`XDP_TX`). Useful when backends are on a different NIC than clients. Disabled by default — does not work in bridge+veth+SKB mode testbed.

All configuration is validated before the BPF program is loaded: IP addresses are checked with `inet_pton`, ports must be in [1-65535], MAC addresses must be valid unicast (no multicast/broadcast), weights must be in [1-10] with total weight not exceeding 256 slots, and health parameters are range-checked. Invalid configs produce clear error messages and abort before touching the NIC.

### Start with CLI flags

```bash
sudo build/zlb start -i eth0 \
    -v 10.0.0.100:80:tcp \
    -b 10.0.0.2:80:aa:bb:cc:dd:ee:01 \
    -b 10.0.0.3:80:aa:bb:cc:dd:ee:02
```

### Other commands

```bash
sudo build/zlb stats          # show per-backend packet/byte counters
sudo build/zlb stats -w       # live watch mode (updates every second with PPS)
sudo build/zlb events         # stream real-time events from the BPF ring buffer
sudo build/zlb status         # show pinned map status
sudo build/zlb reload -c new.json  # hitless reload — update backends without detaching
sudo build/zlb stop -i eth0   # detach XDP program
```

The program attaches in SKB (generic) mode by default. Non-VIP traffic passes through to the kernel stack unmodified. BPF maps are pinned to `/sys/fs/bpf/zlb/` for cross-process access.

### Event streaming

`zlb events` consumes the BPF ring buffer and prints structured events in real time:

```
FORWARD tcp 10.0.0.10:41234 -> 10.0.0.100:80 backend=0
CONN_NEW tcp 10.0.0.10:41235 -> 10.0.0.100:80 backend=1
PASS [fragment] 10.0.0.10 -> 10.0.0.100
PASS [lb-own-ip] tcp 10.0.0.10:22 -> 10.0.0.1:22
```

Event types:
- **FORWARD**: Packet forwarded to a backend (sampled — every 1000th packet to avoid ring buffer saturation)
- **PASS**: Packet passed to the kernel stack, with a reason (not-ipv4, not-tcp/udp, vip-miss, no-backends, lb-own-ip, fragment, backend-miss)
- **CONN_NEW**: New connection mapping created in the affinity table

### Hitless reload

`zlb reload -c config.json` updates the backend pool and weights on a running load balancer without detaching the XDP program. The BPF data plane continues forwarding packets during the reload — there is no window where packets are dropped.

The reload updates pinned maps atomically per-element: backends are written first (expanded by weight), stale slots are cleared, then the VIP metadata is updated with the new count. Existing connections in the LRU table naturally age out; stale connections to removed backends will fail and clients reconnect.

Health checks run in the `zlb start` process and are not affected by reload. Restart `zlb start` to pick up health check configuration changes.

### Health checking

When started with a config file, TCP health checks run automatically in a background thread:
- Connects to each backend's `address:port` every `interval` seconds
- 3 consecutive failures → backend marked **DOWN**, traffic shifted to healthy backends
- 2 consecutive successes → backend marked **UP**, traffic restored
- Weight-aware: when a backend with weight > 1 fails, all of its expanded slots are reassigned to a healthy backend; on recovery, all slots are restored
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

2. **Edge case handling**: IP fragments (MF flag or non-zero fragment offset) are passed to the kernel for reassembly — load-balancing a fragment without the L4 header would select the wrong backend. Packets destined to the LB's own IP are also passed through so the LB itself remains reachable for SSH, health checks, etc.

3. **VIP lookup**: The destination `{IP, port, protocol}` is looked up in the `vip_table` hash map. Misses are passed to the kernel stack (`XDP_PASS`).

4. **Connection affinity**: The `{source IP, source port, protocol}` tuple is looked up in a 262K-entry LRU hash map. On a hit, the same backend is reused. On a miss, a Knuth multiplicative hash of the source IP selects a backend from the weight-expanded pool, and the mapping is stored for future packets.

5. **Header rewriting**: The destination MAC is set to the backend's MAC. The source MAC is set to the LB's MAC. The destination IP is changed from the VIP to the backend's real IP.

6. **Checksum recalculation**: IP and L4 (TCP/UDP) checksums are updated incrementally using `bpf_csum_diff()` — only the changed fields are recalculated, not the entire header. UDP checksums of 0 are preserved per RFC 768.

7. **Forwarding**: The rewritten packet is sent out via `XDP_TX` (same interface) or `XDP_REDIRECT` (different interface via DEVMAP), depending on configuration. The L2 network delivers it to the backend based on the new destination MAC.

8. **Event logging**: A ring buffer streams structured events to userspace. PASS and CONN_NEW events are always emitted. FORWARD events are rate-limited (1 in every 1000 packets) using a per-CPU counter to avoid saturating the ring buffer under high traffic.

## License

[MIT](LICENSE)
