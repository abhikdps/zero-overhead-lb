#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_lb_common.h"

#define ETH_P_IP    0x0800
#define ETH_P_8021Q 0x8100
#define ETH_ALEN    6

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VIPS);
	__type(key, struct vip_key);
	__type(value, struct vip_meta);
} vip_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend_info);
} backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct lb_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, struct conn_key);
	__type(value, struct conn_val);
} connection_table SEC(".maps");

SEC("xdp")
int xdp_lb_func(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__u16 eth_proto = eth->h_proto;

	/* Skip 802.1Q VLAN tag if present */
	struct vlan_hdr {
		__be16 tci;
		__be16 inner_proto;
	};
	struct vlan_hdr *vlan = NULL;

	if (eth_proto == bpf_htons(ETH_P_8021Q)) {
		vlan = (void *)(eth + 1);
		if ((void *)(vlan + 1) > data_end)
			return XDP_DROP;
		eth_proto = vlan->inner_proto;
	}

	if (eth_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = vlan ? (void *)(vlan + 1) : (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	__u32 ip_hdr_len = iph->ihl * 4;
	if (ip_hdr_len < sizeof(*iph))
		return XDP_DROP;

	if ((void *)iph + ip_hdr_len > data_end)
		return XDP_DROP;

	__be16 dst_port = 0;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)iph + ip_hdr_len;
		if ((void *)(tcph + 1) > data_end)
			return XDP_DROP;
		dst_port = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (void *)iph + ip_hdr_len;
		if ((void *)(udph + 1) > data_end)
			return XDP_DROP;
		dst_port = udph->dest;
	} else {
		return XDP_PASS;
	}

	struct vip_key vkey = {
		.address  = iph->daddr,
		.port     = dst_port,
		.protocol = iph->protocol,
	};

	struct vip_meta *vmeta = bpf_map_lookup_elem(&vip_table, &vkey);
	if (!vmeta)
		return XDP_PASS;

	bpf_printk("VIP hit: proto=%u port=%u backends=%u",
		   iph->protocol, bpf_ntohs(dst_port), vmeta->backend_count);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
