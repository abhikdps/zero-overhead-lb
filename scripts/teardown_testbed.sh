#!/usr/bin/env bash
set -euo pipefail

echo "=== Stopping HTTP servers ==="
pkill -f "python3 -m http.server 80" 2>/dev/null || true

echo "=== Removing namespaces ==="
for ns in client-ns lb-ns be1-ns be2-ns; do
    ip netns del $ns 2>/dev/null && echo "  deleted $ns" || true
done

echo "=== Removing bridge ==="
ip link del br-zlb 2>/dev/null && echo "  deleted br-zlb" || true

echo "=== Teardown complete ==="
