#!/usr/bin/env bash
set -euo pipefail

# Bridge-based L2 testbed for XDP load balancer testing.
#
# Topology:
#
#   client-ns (10.0.0.10)  lb-ns (10.0.0.1, VIP .100)  be1-ns (10.0.0.2)  be2-ns (10.0.0.3)
#        |                        |                          |                   |
#     veth-cl               veth-lb                     veth-be1            veth-be2
#        |                        |                          |                   |
#        +------------------------+--------------------------+-------------------+
#                                 br-zlb (bridge)

BRIDGE=br-zlb
CLIENT_NS=client-ns
LB_NS=lb-ns
BE1_NS=be1-ns
BE2_NS=be2-ns
VIP=10.0.0.100

echo "=== Creating bridge ==="
ip link add $BRIDGE type bridge
ip link set $BRIDGE up

create_ns_with_veth() {
    local ns=$1 veth_root=$2 veth_ns=$3 ip_addr=$4

    ip netns add $ns
    ip link add $veth_root type veth peer name $veth_ns
    ip link set $veth_root master $BRIDGE
    ip link set $veth_root up
    ip link set $veth_ns netns $ns
    ip netns exec $ns ip addr add ${ip_addr}/24 dev $veth_ns
    ip netns exec $ns ip link set $veth_ns up
    ip netns exec $ns ip link set lo up
}

echo "=== Creating namespaces ==="
create_ns_with_veth $CLIENT_NS veth-cl   veth-cl-ns   10.0.0.10
create_ns_with_veth $LB_NS     veth-lb   veth-lb-ns   10.0.0.1
create_ns_with_veth $BE1_NS    veth-be1  veth-be1-ns  10.0.0.2
create_ns_with_veth $BE2_NS    veth-be2  veth-be2-ns  10.0.0.3

echo "=== Configuring VIP on LB ==="
ip netns exec $LB_NS ip addr add ${VIP}/32 dev veth-lb-ns

echo "=== Starting HTTP servers on backends ==="
ip netns exec $BE1_NS python3 -m http.server 80 --bind 0.0.0.0 &>/dev/null &
echo "  be1-ns: python3 HTTP server on :80 (pid $!)"
ip netns exec $BE2_NS python3 -m http.server 80 --bind 0.0.0.0 &>/dev/null &
echo "  be2-ns: python3 HTTP server on :80 (pid $!)"

echo ""
echo "=== Interface MAC addresses ==="
get_mac() {
    ip netns exec $1 cat /sys/class/net/$2/address
}
echo "  client  (veth-cl-ns):  $(get_mac $CLIENT_NS veth-cl-ns)"
echo "  lb      (veth-lb-ns):  $(get_mac $LB_NS     veth-lb-ns)"
echo "  be1     (veth-be1-ns): $(get_mac $BE1_NS    veth-be1-ns)"
echo "  be2     (veth-be2-ns): $(get_mac $BE2_NS    veth-be2-ns)"

echo ""
echo "=== Connectivity check ==="
ip netns exec $CLIENT_NS ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 && \
    echo "  client → lb:  OK" || echo "  client → lb:  FAIL"
ip netns exec $CLIENT_NS ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 && \
    echo "  client → be1: OK" || echo "  client → be1: FAIL"
ip netns exec $CLIENT_NS ping -c 1 -W 1 10.0.0.3 >/dev/null 2>&1 && \
    echo "  client → be2: OK" || echo "  client → be2: FAIL"

echo ""
echo "=== Testbed ready ==="
echo ""
echo "To attach the LB (run from lb-ns):"
echo "  sudo ip netns exec $LB_NS build/zlb start -i veth-lb-ns \\"
echo "    -v ${VIP}:80:tcp \\"
echo "    -b 10.0.0.2:80:\$(get_mac $BE1_NS veth-be1-ns) \\"
echo "    -b 10.0.0.3:80:\$(get_mac $BE2_NS veth-be2-ns)"
echo ""
echo "To test from client:"
echo "  sudo ip netns exec $CLIENT_NS hping3 -S -p 80 $VIP -c 3"
echo "  sudo ip netns exec $BE1_NS tcpdump -i veth-be1-ns -nn"
