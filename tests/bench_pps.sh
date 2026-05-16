#!/usr/bin/env bash
set -euo pipefail

DURATION=${1:-10}
VIP=10.0.0.100
PORT=80
CLIENT_NS=client-ns
PIN_DIR=/sys/fs/bpf/zlb

echo "=== XDP Load Balancer Benchmark ==="
echo ""

# Pre-flight checks
for ns in client-ns lb-ns be1-ns be2-ns; do
    if [ ! -e "/var/run/netns/$ns" ]; then
        echo "ERROR: namespace $ns not found. Run: sudo scripts/setup_testbed.sh"
        exit 1
    fi
done

if [ ! -e "$PIN_DIR/stats" ]; then
    echo "ERROR: LB not attached (no pinned maps at $PIN_DIR)"
    echo "Start with: sudo nsenter --net=/var/run/netns/lb-ns build/zlb start -i veth-lb-ns -c config/example.json"
    exit 1
fi

if ! command -v hping3 &>/dev/null; then
    echo "ERROR: hping3 not found. Install with: sudo apt install hping3"
    exit 1
fi

# Read baseline stats
read_total_stats() {
    local json
    json=$(bpftool map dump pinned "$PIN_DIR/stats" -j 2>/dev/null || echo "[]")
    echo "$json" | python3 -c "
import json, sys
entries = json.load(sys.stdin)
total_pkts = 0
total_bytes = 0
per_be = {}
for e in entries:
    idx = e['key']
    pkts = sum(v['value']['packets'] for v in e['values'])
    byts = sum(v['value']['bytes'] for v in e['values'])
    if pkts > 0:
        per_be[idx] = {'packets': pkts, 'bytes': byts}
    total_pkts += pkts
    total_bytes += byts
print(json.dumps({'total_packets': total_pkts, 'total_bytes': total_bytes, 'per_backend': per_be}))
"
}

echo "Reading baseline stats..."
BASELINE=$(read_total_stats)
BASELINE_PKTS=$(echo "$BASELINE" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_packets'])")

echo "Running hping3 flood for ${DURATION}s to ${VIP}:${PORT}..."
echo ""

ip netns exec $CLIENT_NS hping3 --flood -S -p $PORT $VIP -q 2>/dev/null &
HPING_PID=$!

sleep "$DURATION"

kill $HPING_PID 2>/dev/null || true
wait $HPING_PID 2>/dev/null || true

sleep 0.5

echo "Reading post-run stats..."
POST=$(read_total_stats)
POST_PKTS=$(echo "$POST" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_packets'])")
POST_BYTES=$(echo "$POST" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_bytes'])")

DELTA_PKTS=$((POST_PKTS - BASELINE_PKTS))
BASELINE_BYTES=$(echo "$BASELINE" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_bytes'])")
DELTA_BYTES=$((POST_BYTES - BASELINE_BYTES))

if [ "$DURATION" -gt 0 ]; then
    PPS=$((DELTA_PKTS / DURATION))
    BPS=$((DELTA_BYTES / DURATION))
else
    PPS=0
    BPS=0
fi

format_number() {
    local n=$1
    if [ "$n" -ge 1000000000 ]; then
        printf "%.1fB" "$(echo "scale=1; $n / 1000000000" | bc)"
    elif [ "$n" -ge 1000000 ]; then
        printf "%.1fM" "$(echo "scale=1; $n / 1000000" | bc)"
    elif [ "$n" -ge 1000 ]; then
        printf "%.1fK" "$(echo "scale=1; $n / 1000" | bc)"
    else
        printf "%d" "$n"
    fi
}

format_bytes() {
    local n=$1
    if [ "$n" -ge 1000000000 ]; then
        printf "%.1f GB" "$(echo "scale=1; $n / 1000000000" | bc)"
    elif [ "$n" -ge 1000000 ]; then
        printf "%.1f MB" "$(echo "scale=1; $n / 1000000" | bc)"
    elif [ "$n" -ge 1000 ]; then
        printf "%.1f KB" "$(echo "scale=1; $n / 1000" | bc)"
    else
        printf "%d B" "$n"
    fi
}

echo ""
echo "=== Results ==="
echo "Duration:     ${DURATION}s"
echo "Packets:      $(format_number $DELTA_PKTS)"
echo "PPS:          $(format_number $PPS)"
echo "Throughput:   $(format_bytes $BPS)/s"
echo ""

# Per-backend breakdown
echo "Per-backend distribution:"
echo "$POST" | python3 -c "
import json, sys, socket, struct

post = json.load(sys.stdin)
per_be = post.get('per_backend', {})

# Read backend IPs from the backends map
try:
    import subprocess
    result = subprocess.run(
        ['bpftool', 'map', 'dump', 'pinned', '$PIN_DIR/backends', '-j'],
        capture_output=True, text=True
    )
    backends = json.loads(result.stdout)
except Exception:
    backends = []

be_ips = {}
for b in backends:
    idx = b.get('key', 0)
    val = b.get('value', {})
    addr = val.get('address', 0)
    port = val.get('port', 0)
    if addr != 0:
        ip = socket.inet_ntoa(struct.pack('!I', addr))
        be_ips[str(idx)] = f'{ip}:{socket.ntohs(port)}'

total = sum(v['packets'] for v in per_be.values())
for idx, stats in sorted(per_be.items(), key=lambda x: int(x[0])):
    ip_str = be_ips.get(str(idx), f'backend-{idx}')
    pkts = stats['packets']
    pct = (pkts / total * 100) if total > 0 else 0
    print(f'  {ip_str:22s}  {pkts:>12,} pkts  ({pct:.1f}%)')
"
