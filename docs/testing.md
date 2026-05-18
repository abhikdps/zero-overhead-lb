# Testing

This document covers the testing infrastructure for the XDP load balancer: network namespace testbed setup, functional tests, and performance benchmarks.

## Prerequisites

Install test dependencies on Ubuntu 24.04:

```bash
sudo apt install python3-pytest python3-scapy hping3
```

The load balancer must be built first:

```bash
make
```

## Network Namespace Testbed

The testbed creates an isolated L2 network using Linux network namespaces and a bridge. No physical servers or cloud instances needed.

### Topology

```text
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  client-ns   │    │    lb-ns     │    │   be1-ns     │    │   be2-ns     │
│  10.0.0.10   │    │  10.0.0.1    │    │  10.0.0.2    │    │  10.0.0.3    │
│              │    │  VIP: .100   │    │  HTTP :80    │    │  HTTP :80    │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │                   │
    veth-cl             veth-lb             veth-be1            veth-be2
       │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┘
                              br-zlb (bridge)
```

All namespaces share a single `/24` subnet on a Linux bridge (`br-zlb`). Each namespace has a veth pair — one end inside the namespace, the other attached to the bridge.

### Setup

```bash
sudo scripts/setup_testbed.sh
```

This script:

1. Creates the bridge `br-zlb`
2. Creates four namespaces (`client-ns`, `lb-ns`, `be1-ns`, `be2-ns`) with veth pairs
3. Assigns IP addresses to the namespace-side interfaces
4. Adds the VIP (`10.0.0.100/32`) to the LB namespace
5. Starts Python HTTP servers on port 80 in both backend namespaces
6. Prints interface MAC addresses (needed for config) and runs connectivity checks

### Attaching the Load Balancer

Use `nsenter` (not `ip netns exec`) to enter only the network namespace while preserving the root mount namespace. This is critical — BPF map pinning requires access to `/sys/fs/bpf/`, which is in the root mount namespace.

```bash
sudo nsenter --net=/var/run/netns/lb-ns build/zlb start \
    -i veth-lb-ns -c config/example.json
```

The `config/example.json` must contain the backend MAC addresses from `setup_testbed.sh` output. Update them after each testbed creation since MACs are randomly assigned.

### Manual Verification

Send traffic from the client namespace:

```bash
# TCP SYN to VIP
sudo ip netns exec client-ns hping3 -S -p 80 10.0.0.100 -c 3

# Watch packets arrive at a backend
sudo ip netns exec be1-ns tcpdump -i veth-be1-ns -nn tcp

# Check stats
sudo build/zlb stats

# Stream events
sudo build/zlb events
```

### Teardown

```bash
sudo scripts/teardown_testbed.sh
```

Deletes all namespaces, which automatically cleans up veth pairs and the bridge.

## Functional Tests

The test suite uses [scapy](https://scapy.net/) to craft packets at the byte level and [pytest](https://pytest.org/) to assert correct behavior.

### Running Tests

```bash
# 1. Set up testbed
sudo scripts/setup_testbed.sh

# 2. Attach the LB in background
sudo nsenter --net=/var/run/netns/lb-ns build/zlb start \
    -i veth-lb-ns -c config/example.json &

# 3. Run tests
sudo pytest tests/test_lb.py -v

# 4. Stop the LB and tear down
kill %1
sudo scripts/teardown_testbed.sh
```

Or use the Makefile target (requires testbed + LB already running):

```bash
make test
```

### Test Architecture

Tests are in `tests/test_lb.py` with shared fixtures in `tests/conftest.py`.

**Key fixtures:**

- `testbed_up`: verifies namespace connectivity and reads MAC addresses
- `lb_attached`: confirms the LB is running by checking pinned maps

**Helpers:**

- `send_packet(ns, pkt, iface)`: writes a scapy packet to a temp pcap and replays it in the namespace
- `PacketCapture(ns, iface, filter)`: context manager that runs `tcpdump` in a namespace and returns captured packets via `rdpcap()`
- `send_and_capture(...)`: combines sending and capturing across multiple namespaces
- `read_stats()`: parses `bpftool map dump` JSON output into per-backend packet/byte counts

### Test Coverage

| Test Class | Test | What It Verifies |
| ----------- | ------ | ------------------ |
| `TestTCPForwarding` | `tcp_syn_to_vip` | TCP SYN to VIP arrives at backend with correct MAC/IP rewrite and valid checksums |
| | `connection_affinity` | Same `{src_ip, src_port}` always reaches the same backend (5 consecutive sends) |
| | `different_sources_distribute` | 10 different source IPs distribute across at least 2 backends |
| `TestUDPForwarding` | `udp_to_vip` | UDP packet to VIP is forwarded with valid IP and UDP checksums |
| `TestPassthrough` | `non_vip_passthrough` | TCP connect to LB's own IP (not VIP) gets `RST` from kernel, proving `XDP_PASS` |
| | `icmp_passthrough` | Ping to VIP succeeds — ICMP is non-TCP/UDP, so XDP returns `XDP_PASS` |
| | `arp_passthrough` | Ping after ARP cache flush succeeds — ARP is non-IPv4, passes through |
| `TestStats` | `stats_increment` | Sending 5 packets increases the aggregate stats counter by at least 5 |
| `TestEdgeCases` | `vlan_tagged` | Skipped: bridge strips VLAN tags before XDP in SKB mode |
| | `malformed_packets` | Skipped: kernel validates packets before XDP in SKB mode |

### Skipped Tests and Why

Two edge-case tests are skipped because the testbed runs XDP in **generic/SKB mode** (the only mode supported on veth interfaces):

- **VLAN-tagged packets**: the bridge strips 802.1Q tags before the XDP program sees the packet. The VLAN parsing code in the BPF program works, but can't be tested this way.
- **Malformed packets**: the kernel validates Ethernet and IP headers before passing the `sk_buff` to the XDP hook. Truncated or corrupt headers never reach the program.

These code paths can be tested with:

- Native XDP on real or supported virtual NICs (e.g., `virtio_net`)
- `BPF_PROG_TEST_RUN` (programmatic packet injection that bypasses kernel validation)

### Checksum Verification

Tests verify checksums by:

1. Saving the received packet's checksum
2. Deleting the checksum field
3. Rebuilding the packet with scapy (which recalculates)
4. Asserting the original matches the recalculated value

This validates the incremental checksum update in the BPF program.

## Performance Benchmark

The benchmark measures raw packet throughput using `hping3 --flood`.

### Running

```bash
# Default: 10 seconds
sudo bash tests/bench_pps.sh

# Custom duration
sudo bash tests/bench_pps.sh 30

# Via Makefile
make bench BENCH_DURATION=30
```

### What It Does

1. Verifies prerequisites (namespaces exist, LB attached, hping3 installed)
2. Reads baseline packet/byte counters from the pinned `stats` map
3. Runs `hping3 --flood -S -p 80 10.0.0.100` from `client-ns` for the specified duration
4. Reads post-run counters
5. Reports: total packets, PPS, throughput (bytes/sec), per-backend distribution

### Output

Measured on a Lima VM (Ubuntu 24.04, ARM64, generic/SKB mode):

```text
=== Results ===
Duration:     10s
Packets:      3.0M
PPS:          ~300K
Throughput:   16.0 MB/s

Per-backend distribution:
  10.0.0.2:80             1,500,123 pkts  (50.0%)
  10.0.0.3:80             1,499,877 pkts  (50.0%)
```

### Performance Notes

- The testbed uses **SKB (generic) mode**, which is significantly slower than native XDP. The kernel allocates an `sk_buff`, builds it from metadata, then hands it to the XDP hook. This adds overhead that doesn't exist with native XDP.
- `hping3 --flood` itself is rate-limited by kernel socket buffer allocation and scheduling.
- For realistic performance numbers, test with native XDP on real NICs or `virtio_net` in a VM. Production XDP load balancers (Katran, Cilium) achieve millions of PPS.
- The benchmark measures end-to-end throughput including `hping3` overhead, bridge forwarding, and LB processing. It's useful for regression testing and relative comparisons, not absolute XDP performance.

### Weighted Distribution Verification

With weighted backends, the benchmark shows the traffic split. For example, with `weight: 3` on backend 1 and `weight: 1` on backend 2:

```text
Per-backend distribution:
  10.0.0.2:80               183,894 pkts  (75.1%)
  10.0.0.3:80                61,023 pkts  (24.9%)
```

This confirms the weight-expanded array produces the expected proportional distribution.
