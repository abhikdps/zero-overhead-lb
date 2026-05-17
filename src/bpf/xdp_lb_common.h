#ifndef __XDP_LB_COMMON_H
#define __XDP_LB_COMMON_H

#define MAX_BACKENDS     256
#define MAX_VIPS         32
#define MAX_CONNECTIONS  262144
#define CFG_IDX          0
#define RINGBUF_SIZE     (256 * 1024)
#define EVENT_SAMPLE     1000

struct vip_key {
	__be32 address;
	__be16 port;
	__u8   protocol;
	__u8   pad;
};

struct vip_meta {
	__u32 backend_count;
	__u32 backend_start_idx;
};

struct backend_info {
	__be32 address;
	__be16 port;
	__u8   mac[6];
};

struct lb_stats {
	__u64 packets;
	__u64 bytes;
};

struct conn_key {
	__be32 src_ip;
	__be16 src_port;
	__u8   protocol;
	__u8   pad;
};

struct conn_val {
	__u32 backend_idx;
};

struct lb_config {
	__u8   lb_mac[6];
	__u8   pad[2];
	__be32 lb_ip;
	__u8   use_redirect;
	__u8   pad2[3];
};

enum lb_event_type {
	LB_EVENT_FORWARD  = 1,
	LB_EVENT_PASS     = 2,
	LB_EVENT_CONN_NEW = 3,
};

enum lb_pass_reason {
	PASS_NOT_IPV4     = 1,
	PASS_NOT_TCP_UDP  = 2,
	PASS_VIP_MISS     = 3,
	PASS_NO_BACKENDS  = 4,
	PASS_LB_OWN_IP    = 5,
	PASS_FRAGMENT     = 6,
	PASS_BACKEND_MISS = 7,
};

struct lb_event {
	__u8   type;
	__u8   reason;
	__u8   protocol;
	__u8   pad;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u32  backend_idx;
};

#endif
