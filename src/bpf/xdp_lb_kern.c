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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lb_config);
} lb_config SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u32 hash_ip(__be32 addr)
{
	__u32 h = bpf_ntohl(addr);
	h *= 2654435761U;
	return h >> 16;
}

SEC("xdp")
int xdp_lb_func(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__u16 eth_proto = eth->h_proto;

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

	__be16 src_port = 0;
	__be16 dst_port = 0;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = (void *)iph + ip_hdr_len;
		if ((void *)(tcph + 1) > data_end)
			return XDP_DROP;
		src_port = tcph->source;
		dst_port = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + ip_hdr_len;
		if ((void *)(udph + 1) > data_end)
			return XDP_DROP;
		src_port = udph->source;
		dst_port = udph->dest;
	} else {
		return XDP_PASS;
	}

	/* --- VIP lookup --- */

	struct vip_key vkey = {
		.address  = iph->daddr,
		.port     = dst_port,
		.protocol = iph->protocol,
	};

	struct vip_meta *vmeta = bpf_map_lookup_elem(&vip_table, &vkey);
	if (!vmeta)
		return XDP_PASS;

	if (vmeta->backend_count == 0)
		return XDP_PASS;

	/* --- Backend selection with connection affinity --- */

	struct conn_key ckey = {
		.src_ip   = iph->saddr,
		.src_port = src_port,
		.protocol = iph->protocol,
	};

	__u32 backend_idx;
	struct conn_val *cval = bpf_map_lookup_elem(&connection_table, &ckey);

	if (cval) {
		backend_idx = cval->backend_idx;
	} else {
		backend_idx = hash_ip(iph->saddr) % vmeta->backend_count;
		struct conn_val new_cval = { .backend_idx = backend_idx };
		bpf_map_update_elem(&connection_table, &ckey, &new_cval, BPF_NOEXIST);
	}

	__u32 idx = vmeta->backend_start_idx + backend_idx;
	struct backend_info *be = bpf_map_lookup_elem(&backends, &idx);
	if (!be)
		return XDP_PASS;

	/* --- MAC rewriting --- */

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);

	/* --- IP rewriting + checksum --- */

	__be32 old_daddr = iph->daddr;
	iph->daddr = be->address;

	iph->check = csum_fold(
		bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4, ~iph->check));

	/* --- L4 checksum update (pseudo-header includes dst IP) --- */

	if (tcph) {
		tcph->check = csum_fold(
			bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4,
				       ~tcph->check));
	} else if (udph && udph->check) {
		udph->check = csum_fold(
			bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4,
				       ~udph->check));
		if (!udph->check)
			udph->check = bpf_htons(0xffff);
	}

	/* --- Stats --- */

	struct lb_stats *st = bpf_map_lookup_elem(&stats, &backend_idx);
	if (st) {
		st->packets++;
		st->bytes += data_end - data;
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
