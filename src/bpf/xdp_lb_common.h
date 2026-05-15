#ifndef __XDP_LB_COMMON_H
#define __XDP_LB_COMMON_H

#define MAX_BACKENDS     64
#define MAX_VIPS         32
#define MAX_CONNECTIONS  65536
#define CFG_IDX          0

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
	__u8 lb_mac[6];
	__u8 pad[2];
};

#endif
