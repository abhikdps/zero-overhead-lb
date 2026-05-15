#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_parse_func(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    /* ihl is the header length in 32-bit words */
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return XDP_DROP;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;

        bpf_printk("TCP | src_ip=%u dst_port=%u\n",
                   __builtin_bswap32(iph->saddr),
                   __builtin_bswap16(tcph->dest));

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + ip_hdr_len;
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;

        bpf_printk("UDP | src_ip=%u dst_port=%u\n",
                   __builtin_bswap32(iph->saddr),
                   __builtin_bswap16(udph->dest));
    }

    return XDP_PASS;
}

char _license[] = "GPL";
