# Architecture

Zero-Overhead LB is a Layer 4 load balancer split into two components: a **data plane** (XDP/eBPF program running in the NIC driver) and a **control plane** (userspace C binary managing configuration, health, and observability).

## Data Plane

The XDP program (`src/bpf/xdp_lb_kern.c`) runs at the earliest possible hook point in the Linux networking stack — before `sk_buff` allocation, before interrupts are coalesced, before the TCP/IP stack sees the packet. It processes raw byte buffers and makes a forwarding decision in a single pass.

### Packet Flow

```text
                    Incoming packet
                          |
                          v
                   Parse Ethernet
                   (+ optional 802.1Q VLAN tag)
                          |
                   Is it IPv4?
                  /              \
                no                yes
                |                  |
           XDP_PASS           Parse IP header
          (to kernel)         (variable ihl)
                                   |
                              IP fragment?
                             /            \
                           yes              no
                            |                |
                       XDP_PASS         Parse TCP/UDP
                      (reassembly)           |
                                        Dest = LB own IP?
                                       /              \
                                     yes                no
                                      |                  |
                                 XDP_PASS           VIP lookup
                                (mgmt traffic)     (hash map)
                                                  /          \
                                               miss           hit
                                                |              |
                                           XDP_PASS       Connection table
                                                         lookup (LRU hash)
                                                        /              \
                                                     hit               miss
                                                      |                 |
                                                 Use stored        Hash src IP
                                                 backend_idx       % backend_count
                                                      \               /
                                                       v             v
                                                   Lookup backend array
                                                          |
                                                   Rewrite MAC + IP
                                                   Update checksums
                                                   Update stats
                                                          |
                                                   XDP_TX or XDP_REDIRECT
```

### Packet Parsing

The parser handles:

- **Ethernet**: standard 14-byte header. If `h_proto == 0x8100` (802.1Q), the parser skips the 4-byte VLAN tag and uses the inner ethertype.
- **IP**: variable-length header via `ihl * 4`. Every pointer dereference is bounds-checked against `data_end` to satisfy the BPF verifier.
- **TCP/UDP**: extracts source and destination ports for VIP matching and connection tracking.

Non-IPv4 traffic (ARP, IPv6, etc.) is passed to the kernel via `XDP_PASS`.

### Edge Case Handling

**IP fragments**: If the MF (More Fragments) flag is set or the fragment offset is non-zero, the packet is passed to the kernel. A non-initial fragment lacks L4 headers, so we can't determine the destination port — load-balancing it would send it to the wrong backend. The kernel reassembles fragments normally.

```c
if (iph->frag_off & bpf_htons(0x3FFF))  // MF flag + 13-bit offset (excludes DF)
    return XDP_PASS;
```

**LB own-IP passthrough**: Before the VIP lookup, the program checks if the packet is destined for the load balancer's own IP address (stored in `lb_config` map). This ensures SSH, health checks to the LB itself, and other management traffic reaches the kernel stack.

### Backend Selection

Two-stage lookup for consistent backend selection with session affinity:

1. **Connection table** (LRU hash, 262K entries): keyed by `{src_ip, src_port, protocol}`. If found, the stored `backend_idx` is reused — same client always reaches the same backend for the lifetime of the connection.

2. **Hash selection** (on miss): Knuth multiplicative hash of the source IP, modulo `backend_count`. The result is stored in the connection table for future packets.

```c
hash = src_ip * 2654435761  // Knuth multiplicative constant
backend_idx = (hash >> 16) % backend_count
```

The LRU eviction policy naturally ages out stale connections without requiring explicit timeout management.

### Weighted Round-Robin

Weights are implemented entirely in userspace — no BPF program changes needed. The `backends` array is expanded proportionally:

```text
Backend A (weight=3): slots [0, 1, 2]
Backend B (weight=1): slot  [3]

backend_count = 4 (total weight)
hash % 4 selects uniformly → A gets ~75%, B gets ~25%
```

The BPF program sees a flat array and hashes into it. Userspace manages the expansion.

### Header Rewriting

After selecting a backend:

1. **Source MAC** ← LB's own MAC (from `lb_config` map)
2. **Destination MAC** ← backend's MAC (from `backends` array)
3. **Destination IP** ← backend's real IP

Source IP is not modified — backends see the original client IP (Direct Server Return-compatible).

### Checksum Recalculation

Checksums are updated incrementally using `bpf_csum_diff()` (RFC 1624). Only the changed field (destination IP) is factored in — the entire header is not re-summed.

```c
iph->check = csum_fold(
    bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4, ~iph->check));
```

The same approach updates TCP and UDP checksums (the L4 pseudo-header includes the destination IP). UDP checksums of 0 are preserved per RFC 768; if an incremental update produces 0, it's set to `0xFFFF`.

### Forwarding

Two forwarding modes:

- **XDP_TX** (default): sends the rewritten packet back out the same NIC. The L2 network (switch/bridge) delivers it based on the new destination MAC.
- **XDP_REDIRECT**: sends via a different NIC using a DEVMAP. Enabled by setting `use_redirect = 1` in `lb_config` and populating `tx_port` with the egress interface index.

## BPF Maps

All state is stored in BPF maps shared between the data plane and control plane:

| Map | Type | Size | Key | Value | Purpose |
| ----- | ------ | ------ | ----- | ------- | --------- |
| `vip_table` | HASH | 32 entries | `{ip, port, protocol, pad}` (8B) | `{backend_count, start_idx}` (8B) | VIP identification |
| `backends` | ARRAY | 256 entries | `__u32` index | `{ip, port, mac[6]}` (12B) | Backend pool (weight-expanded) |
| `connection_table` | LRU_HASH | 262,144 entries | `{src_ip, src_port, protocol, pad}` (8B) | `{backend_idx}` (4B) | Session affinity |
| `stats` | PERCPU_ARRAY | 256 entries | `__u32` index | `{packets, bytes}` (16B) | Per-slot counters (lock-free) |
| `lb_config` | ARRAY | 1 entry | `__u32` (always 0) | `{lb_mac[6], pad[2], lb_ip, use_redirect, pad2[3]}` (16B) | LB interface config |
| `events` | RINGBUF | 256 KB | — | `struct lb_event` (20B) | Event stream to userspace |
| `tx_port` | DEVMAP | 1 entry | `__u32` (always 0) | `__u32` ifindex | Egress NIC for XDP_REDIRECT |
| `event_counter` | PERCPU_ARRAY | 1 entry | `__u32` (always 0) | `__u64` counter | Rate-limit FORWARD event sampling |

Maps are pinned to `/sys/fs/bpf/zlb/` so that separate processes (`zlb stats`, `zlb reload`, `zlb events`) can access them without holding the BPF program's file descriptor.

### Memory Footprint

- `backends` array: 256 * 12B = 3 KB
- `connection_table` LRU hash: 262,144 * 12B = ~3 MB
- `stats` per-CPU array: 256 \* 16B \* N_CPUs (e.g., ~16 KB on 4 CPUs)
- `events` ring buffer: 256 KB
- Total: ~3.3 MB + per-CPU overhead

## Control Plane

The userspace binary (`build/zlb`) manages the full lifecycle:

### Commands

| Command | Description |
| --------- | ------------- |
| `start -i <iface> -c <config>` | Load BPF, attach to NIC, populate maps, start health checks |
| `stop -i <iface>` | Detach XDP program from NIC |
| `stats [-w]` | Read per-CPU counters, aggregate, display. `-w` for live watch with PPS |
| `events` | Consume ring buffer, print structured events |
| `status` | Check which maps are pinned (is the LB running?) |
| `reload -c <config>` | Update backends and VIP config on a running LB |

### Configuration

JSON config file parsed with cJSON (vendored, MIT). All fields are validated before the BPF program is loaded:

- IP addresses validated with `inet_pton()`
- Ports checked for [1-65535] range
- MAC addresses validated for format and unicast (no multicast/broadcast)
- Weights checked for [1-10] range, total weight must not exceed 256 (MAX_BACKENDS)
- Health check parameters range-checked

### Health Checking

A background pthread runs TCP connect checks against each physical backend:

- Non-blocking `connect()` with configurable timeout (default 2000ms)
- 3 consecutive failures → mark DOWN, reassign all weight-expanded slots to a healthy backend
- 2 consecutive successes → mark UP, restore original slots
- On `zlb` shutdown, all backends are restored to their original configuration

The health checker is weight-aware: each physical backend maps to a range of array slots. When a backend with `weight=3` fails, all 3 of its slots are overwritten with a healthy backend's info. On recovery, all 3 are restored.

### Hitless Reload

`zlb reload` updates pinned maps in-place without detaching the XDP program:

1. Write all backend entries (expanded by weight) — backends are updated first so the data plane always has valid entries to index into
2. Clear stale slots beyond the new total weight (zero out)
3. Update `vip_meta.backend_count` with the new total — this is the "atomic flip" that makes the new pool size visible to BPF
4. Update `lb_config` if the interface changed

The BPF program continues forwarding throughout. Existing connections in the LRU table age out naturally; stale entries pointing to removed backends will fail and clients reconnect.

### Event System

The BPF ring buffer streams structured events to userspace:

```c
struct lb_event {
    __u8   type;        // FORWARD, PASS, CONN_NEW
    __u8   reason;      // for PASS: why it was passed
    __u8   protocol;    // IPPROTO_TCP or IPPROTO_UDP
    __u8   pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u32  backend_idx;
};
```

Event types:

- **LB_EVENT_FORWARD**: Packet forwarded to a backend. Rate-limited to 1 in every 1000 packets using a per-CPU counter to avoid ring buffer saturation under high traffic.
- **LB_EVENT_PASS**: Packet passed to kernel. Always emitted. Includes a reason code (fragment, own-IP, VIP miss, no backends, etc.).
- **LB_EVENT_CONN_NEW**: New connection affinity mapping created. Always emitted.

`zlb events` opens the pinned ring buffer, creates a `ring_buffer` poller, and prints events as they arrive with formatted IP addresses, ports, and reason codes.

### Stats Aggregation

Per-CPU counters are summed across all CPUs for display. When weighted backends are in use, multiple array slots map to the same physical backend — stats are deduplicated by grouping slots with the same `{IP, port}` and summing their counters.

Watch mode (`-w`) clears and redraws every second, showing packets-per-second deltas.
