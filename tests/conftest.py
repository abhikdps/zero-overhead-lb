import json
import os
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass

import pytest
from scapy.all import rdpcap, wrpcap

CLIENT_NS = "client-ns"
LB_NS = "lb-ns"
BE1_NS = "be1-ns"
BE2_NS = "be2-ns"

VIP = "10.0.0.100"
LB_IP = "10.0.0.1"
BE1_IP = "10.0.0.2"
BE2_IP = "10.0.0.3"
CLIENT_IP = "10.0.0.10"

VIP_PORT = 80

CLIENT_IFACE = "veth-cl-ns"
LB_IFACE = "veth-lb-ns"
BE1_IFACE = "veth-be1-ns"
BE2_IFACE = "veth-be2-ns"

BPF_PIN_DIR = "/sys/fs/bpf/zlb"


@dataclass
class TestbedInfo:
    client_mac: str
    lb_mac: str
    be1_mac: str
    be2_mac: str


def nsexec(ns, cmd, timeout=10, check=True):
    full_cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def get_mac(ns, iface):
    result = nsexec(ns, ["cat", f"/sys/class/net/{iface}/address"])
    return result.stdout.strip()


@pytest.fixture(scope="session")
def testbed_up():
    for ns in [CLIENT_NS, LB_NS, BE1_NS, BE2_NS]:
        if not os.path.exists(f"/var/run/netns/{ns}"):
            pytest.skip(
                f"Namespace {ns} not found. "
                "Run: sudo scripts/setup_testbed.sh"
            )

    for target_ip in [LB_IP, BE1_IP, BE2_IP]:
        result = nsexec(
            CLIENT_NS,
            ["ping", "-c", "1", "-W", "1", target_ip],
            check=False,
        )
        if result.returncode != 0:
            pytest.skip(
                f"Cannot reach {target_ip} from {CLIENT_NS}. "
                "Run: sudo scripts/setup_testbed.sh"
            )

    return TestbedInfo(
        client_mac=get_mac(CLIENT_NS, CLIENT_IFACE),
        lb_mac=get_mac(LB_NS, LB_IFACE),
        be1_mac=get_mac(BE1_NS, BE1_IFACE),
        be2_mac=get_mac(BE2_NS, BE2_IFACE),
    )


@pytest.fixture(scope="session")
def lb_attached(testbed_up):
    if not os.path.exists(f"{BPF_PIN_DIR}/stats"):
        pytest.skip(
            "LB not attached (no pinned maps). Start with: "
            "sudo nsenter --net=/var/run/netns/lb-ns "
            "build/zlb start -i veth-lb-ns -c config/example.json"
        )
    return testbed_up


class PacketCapture:
    def __init__(self, ns, iface, filter_expr="", max_packets=10, timeout=3.0):
        self.ns = ns
        self.iface = iface
        self.filter_expr = filter_expr
        self.max_packets = max_packets
        self.timeout = timeout
        self.pcap_path = os.path.join(
            tempfile.gettempdir(), f"zlb_cap_{uuid.uuid4().hex}.pcap"
        )
        self.proc = None
        self.packets = []

    def __enter__(self):
        cmd = [
            "ip", "netns", "exec", self.ns,
            "tcpdump", "-i", self.iface,
            "-w", self.pcap_path,
            "-U",
            "-c", str(self.max_packets),
        ]
        if self.filter_expr:
            cmd.extend(self.filter_expr.split())
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return self

    def __exit__(self, *args):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if os.path.exists(self.pcap_path):
            try:
                self.packets = list(rdpcap(self.pcap_path))
            except Exception:
                self.packets = []
            os.unlink(self.pcap_path)


def send_packet(ns, packet, iface, count=1):
    pcap_path = os.path.join(
        tempfile.gettempdir(), f"zlb_send_{uuid.uuid4().hex}.pcap"
    )
    wrpcap(pcap_path, packet)
    try:
        nsexec(
            ns,
            [
                "python3", "-c",
                f"from scapy.all import *; "
                f"sendp(rdpcap('{pcap_path}'), iface='{iface}', "
                f"count={count}, verbose=0)",
            ],
            timeout=10,
        )
    finally:
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


def send_and_capture(
    send_ns, send_iface, capture_configs, packet,
    settle_time=0.5, capture_timeout=3.0, send_count=1,
):
    """Send a packet and capture on one or more interfaces.

    capture_configs: list of (ns, iface, filter_expr) tuples
    Returns: list of PacketCapture objects (one per config)
    """
    captures = []
    for ns, iface, filt in capture_configs:
        cap = PacketCapture(
            ns, iface, filter_expr=filt,
            max_packets=send_count + 5,
            timeout=capture_timeout,
        )
        cap.__enter__()
        captures.append(cap)

    time.sleep(settle_time)
    send_packet(send_ns, packet, send_iface, count=send_count)
    time.sleep(capture_timeout)

    for cap in captures:
        cap.__exit__(None, None, None)

    return captures


def read_stats():
    result = subprocess.run(
        ["bpftool", "map", "dump", "pinned",
         f"{BPF_PIN_DIR}/stats", "-j"],
        capture_output=True, text=True, check=True,
    )
    entries = json.loads(result.stdout)
    stats = {}
    for entry in entries:
        fmt = entry.get("formatted", entry)
        idx = fmt.get("key", entry.get("key", 0))
        if isinstance(idx, list):
            idx = int.from_bytes(
                bytes(int(x, 16) for x in idx), "little"
            )
        values = fmt.get("values", entry.get("values", []))
        total_pkts = 0
        total_bytes = 0
        for v in values:
            vv = v.get("value", {})
            if isinstance(vv, dict):
                total_pkts += vv.get("packets", 0)
                total_bytes += vv.get("bytes", 0)
        if total_pkts > 0 or total_bytes > 0:
            stats[idx] = {"packets": total_pkts, "bytes": total_bytes}
    return stats
