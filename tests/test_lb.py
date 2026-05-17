"""Functional tests for the XDP load balancer.

Prerequisites:
  1. sudo scripts/setup_testbed.sh
  2. sudo nsenter --net=/var/run/netns/lb-ns build/zlb start \
         -i veth-lb-ns -c config/example.json &
  3. sudo pytest tests/test_lb.py -v
"""

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw

from conftest import (
    CLIENT_NS, LB_NS, BE1_NS, BE2_NS,
    VIP, LB_IP, BE1_IP, BE2_IP, CLIENT_IP,
    VIP_PORT,
    CLIENT_IFACE, BE1_IFACE, BE2_IFACE,
    nsexec, send_and_capture, send_packet, read_stats, PacketCapture,
)

pytestmark = [pytest.mark.usefixtures("lb_attached")]


def verify_ip_checksum(pkt):
    """Verify IP checksum is correct by recomputing it."""
    original_chksum = pkt[IP].chksum
    del pkt[IP].chksum
    pkt = IP(bytes(pkt[IP]))
    assert pkt.chksum == original_chksum, (
        f"IP checksum mismatch: got {original_chksum:#x}, "
        f"expected {pkt.chksum:#x}"
    )


def verify_tcp_checksum(pkt):
    original_chksum = pkt[TCP].chksum
    del pkt[TCP].chksum
    rebuilt = IP(bytes(pkt[IP]))
    assert rebuilt[TCP].chksum == original_chksum, (
        f"TCP checksum mismatch: got {original_chksum:#x}, "
        f"expected {rebuilt[TCP].chksum:#x}"
    )


def verify_udp_checksum(pkt):
    original_chksum = pkt[UDP].chksum
    if original_chksum == 0:
        return
    del pkt[UDP].chksum
    rebuilt = IP(bytes(pkt[IP]))
    assert rebuilt[UDP].chksum == original_chksum, (
        f"UDP checksum mismatch: got {original_chksum:#x}, "
        f"expected {rebuilt[UDP].chksum:#x}"
    )


def find_lb_forwarded_packets(captures, backend_ips):
    """Find packets forwarded by the LB across multiple captures.

    Returns list of (backend_ip, packet) tuples.
    """
    results = []
    for cap, be_ip in zip(captures, backend_ips):
        for pkt in cap.packets:
            if IP in pkt and pkt[IP].dst == be_ip and pkt[IP].src == CLIENT_IP:
                results.append((be_ip, pkt))
    return results


class TestTCPForwarding:
    def test_tcp_syn_to_vip_reaches_backend(self, testbed_up):
        pkt = (
            Ether(src=testbed_up.client_mac, dst=testbed_up.lb_mac)
            / IP(src=CLIENT_IP, dst=VIP)
            / TCP(sport=12345, dport=VIP_PORT, flags="S")
        )

        captures = send_and_capture(
            send_ns=CLIENT_NS, send_iface=CLIENT_IFACE,
            capture_configs=[
                (BE1_NS, BE1_IFACE, "tcp"),
                (BE2_NS, BE2_IFACE, "tcp"),
            ],
            packet=pkt,
        )

        forwarded = find_lb_forwarded_packets(
            captures, [BE1_IP, BE2_IP]
        )

        assert len(forwarded) >= 1, "No packet reached any backend"

        be_ip, rcvd = forwarded[0]
        assert rcvd[IP].dst == be_ip
        assert rcvd[IP].src == CLIENT_IP
        assert rcvd[TCP].sport == 12345
        assert rcvd[TCP].dport == VIP_PORT

        if be_ip == BE1_IP:
            assert rcvd[Ether].dst.lower() == testbed_up.be1_mac.lower()
        else:
            assert rcvd[Ether].dst.lower() == testbed_up.be2_mac.lower()

        verify_ip_checksum(rcvd.copy())
        verify_tcp_checksum(rcvd.copy())

    def test_connection_affinity(self, testbed_up):
        pkt = (
            Ether(src=testbed_up.client_mac, dst=testbed_up.lb_mac)
            / IP(src=CLIENT_IP, dst=VIP)
            / TCP(sport=40000, dport=VIP_PORT, flags="S")
        )

        destinations = []
        for _ in range(5):
            captures = send_and_capture(
                send_ns=CLIENT_NS, send_iface=CLIENT_IFACE,
                capture_configs=[
                    (BE1_NS, BE1_IFACE, "tcp"),
                    (BE2_NS, BE2_IFACE, "tcp"),
                ],
                packet=pkt,
                settle_time=0.3,
                capture_timeout=2.0,
            )
            forwarded = find_lb_forwarded_packets(
                captures, [BE1_IP, BE2_IP]
            )
            if forwarded:
                destinations.append(forwarded[0][0])

        assert len(destinations) >= 3, "Too few packets captured"
        assert len(set(destinations)) == 1, (
            f"Connection affinity broken: packets went to {set(destinations)}"
        )

    def test_different_sources_distribute(self, testbed_up):
        extra_ips = [f"10.0.0.{i}" for i in range(11, 21)]
        try:
            for ip in extra_ips:
                nsexec(
                    CLIENT_NS,
                    ["ip", "addr", "add", f"{ip}/24", "dev", CLIENT_IFACE],
                    check=False,
                )

            backends_hit = set()
            for i, src_ip in enumerate(extra_ips):
                pkt = (
                    Ether(src=testbed_up.client_mac, dst=testbed_up.lb_mac)
                    / IP(src=src_ip, dst=VIP)
                    / TCP(sport=50000 + i, dport=VIP_PORT, flags="S")
                )
                captures = send_and_capture(
                    send_ns=CLIENT_NS, send_iface=CLIENT_IFACE,
                    capture_configs=[
                        (BE1_NS, BE1_IFACE, "tcp"),
                        (BE2_NS, BE2_IFACE, "tcp"),
                    ],
                    packet=pkt,
                    settle_time=0.3,
                    capture_timeout=2.0,
                )
                for cap, be_ip in zip(captures, [BE1_IP, BE2_IP]):
                    for p in cap.packets:
                        if IP in p and p[IP].dst == be_ip:
                            backends_hit.add(be_ip)

            assert len(backends_hit) >= 2, (
                "All traffic went to a single backend — "
                "expected distribution across at least 2"
            )
        finally:
            for ip in extra_ips:
                nsexec(
                    CLIENT_NS,
                    ["ip", "addr", "del", f"{ip}/24", "dev", CLIENT_IFACE],
                    check=False,
                )


class TestUDPForwarding:
    @pytest.mark.skip(
        reason="Default config uses TCP-only VIP — UDP requires a separate "
               "VIP entry with protocol=udp"
    )
    def test_udp_to_vip_reaches_backend(self, testbed_up):
        pkt = (
            Ether(src=testbed_up.client_mac, dst=testbed_up.lb_mac)
            / IP(src=CLIENT_IP, dst=VIP)
            / UDP(sport=54321, dport=VIP_PORT)
            / Raw(b"hello")
        )

        captures = send_and_capture(
            send_ns=CLIENT_NS, send_iface=CLIENT_IFACE,
            capture_configs=[
                (BE1_NS, BE1_IFACE, "udp"),
                (BE2_NS, BE2_IFACE, "udp"),
            ],
            packet=pkt,
        )

        forwarded = find_lb_forwarded_packets(
            captures, [BE1_IP, BE2_IP]
        )

        assert len(forwarded) >= 1, "No UDP packet reached any backend"

        be_ip, rcvd = forwarded[0]
        assert rcvd[IP].dst == be_ip
        assert rcvd[IP].src == CLIENT_IP
        assert rcvd[UDP].sport == 54321

        verify_ip_checksum(rcvd.copy())
        verify_udp_checksum(rcvd.copy())


class TestPassthrough:
    def test_non_vip_passthrough(self, testbed_up):
        """Traffic to the LB's own IP (not VIP) should pass to kernel stack."""
        script = (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(2)\n"
            "try:\n"
            f"    s.connect(('{LB_IP}', {VIP_PORT}))\n"
            "except ConnectionRefusedError:\n"
            "    sys.exit(0)\n"
            "except socket.timeout:\n"
            "    sys.exit(1)\n"
            "finally:\n"
            "    s.close()\n"
        )
        result = nsexec(
            CLIENT_NS,
            ["python3", "-c", script],
            timeout=5,
            check=False,
        )
        assert result.returncode == 0, (
            "Expected ConnectionRefused (XDP_PASS → kernel RST), "
            f"got timeout or error: {result.stderr}"
        )

    def test_icmp_passthrough(self, testbed_up):
        """ICMP is non-TCP/UDP — XDP returns XDP_PASS, kernel responds."""
        result = nsexec(
            CLIENT_NS,
            ["ping", "-c", "1", "-W", "2", VIP],
            check=False,
        )
        assert result.returncode == 0, (
            f"Ping to VIP failed — ICMP not passing through: {result.stderr}"
        )

    def test_arp_passthrough(self, testbed_up):
        """ARP is non-IPv4 — XDP returns XDP_PASS."""
        nsexec(CLIENT_NS, ["ip", "neigh", "flush", "dev", CLIENT_IFACE],
               check=False)
        result = nsexec(
            CLIENT_NS,
            ["ping", "-c", "1", "-W", "2", LB_IP],
            check=False,
        )
        assert result.returncode == 0, (
            "Ping after ARP flush failed — ARP not passing through"
        )


class TestStats:
    def test_stats_increment(self, testbed_up):
        stats_before = read_stats()

        pkt = (
            Ether(src=testbed_up.client_mac, dst=testbed_up.lb_mac)
            / IP(src=CLIENT_IP, dst=VIP)
            / TCP(sport=33333, dport=VIP_PORT, flags="S")
        )
        n_packets = 5
        for _ in range(n_packets):
            send_packet(CLIENT_NS, pkt, CLIENT_IFACE)
            import time
            time.sleep(0.1)

        import time
        time.sleep(1)
        stats_after = read_stats()

        total_before = sum(s["packets"] for s in stats_before.values())
        total_after = sum(s["packets"] for s in stats_after.values())
        delta = total_after - total_before

        assert delta >= n_packets, (
            f"Expected at least {n_packets} new packets in stats, "
            f"got {delta} (before={total_before}, after={total_after})"
        )


class TestEdgeCases:
    @pytest.mark.skip(
        reason="Bridge strips VLAN tags before XDP processes them in SKB mode"
    )
    def test_vlan_tagged_packet(self, testbed_up):
        pass

    @pytest.mark.skip(
        reason="SKB mode: kernel validates packets before XDP — "
               "truncated/malformed headers never reach the XDP program"
    )
    def test_malformed_packets(self, testbed_up):
        """Code paths for truncated Ethernet, IP (IHL<5), TCP, UDP headers
        cannot be tested in generic/SKB XDP mode. These paths are exercised
        only with native XDP on real or supported virtual NICs, or via
        BPF_PROG_TEST_RUN."""
        pass
