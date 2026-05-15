#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>

#include "xdp_lb_common.h"
#include "xdp_lb_kern.skel.h"

#define MAX_BACKENDS_CLI 16

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

struct backend_arg {
	char ip[INET_ADDRSTRLEN];
	int  port;
	char mac_str[18];
};

static int parse_mac(const char *str, __u8 mac[6])
{
	unsigned int m[6];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
		   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++)
		mac[i] = (__u8)m[i];
	return 0;
}

static int get_iface_mac(const char *ifname, __u8 mac[6])
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	int err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (err < 0)
		return -1;

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options]\n"
		"\n"
		"Commands:\n"
		"  start -i <iface> -v <vip_ip>:<port>:<tcp|udp> -b <ip>:<port>:<mac> [-b ...]\n"
		"  stop  -i <interface>\n"
		"\n"
		"Example:\n"
		"  %s start -i eth0 -v 10.0.0.100:80:tcp \\\n"
		"    -b 10.0.0.2:80:aa:bb:cc:dd:ee:01 \\\n"
		"    -b 10.0.0.3:80:aa:bb:cc:dd:ee:02\n",
		prog, prog);
}

static int populate_maps(struct xdp_lb_kern *skel, const char *ifname,
			 const char *vip_str,
			 struct backend_arg *be_args, int be_count)
{
	/* Parse VIP: ip:port:proto */
	char vip_ip[INET_ADDRSTRLEN];
	int vip_port;
	char proto_str[8];

	if (sscanf(vip_str, "%[^:]:%d:%7s", vip_ip, &vip_port, proto_str) != 3) {
		fprintf(stderr, "Bad VIP format: %s (expected ip:port:tcp|udp)\n",
			vip_str);
		return -1;
	}

	__u8 protocol;
	if (strcmp(proto_str, "tcp") == 0)
		protocol = IPPROTO_TCP;
	else if (strcmp(proto_str, "udp") == 0)
		protocol = IPPROTO_UDP;
	else {
		fprintf(stderr, "Unknown protocol: %s\n", proto_str);
		return -1;
	}

	struct vip_key vkey = { .protocol = protocol };
	if (inet_pton(AF_INET, vip_ip, &vkey.address) != 1) {
		fprintf(stderr, "Bad VIP IP: %s\n", vip_ip);
		return -1;
	}
	vkey.port = htons(vip_port);

	struct vip_meta vmeta = {
		.backend_count     = be_count,
		.backend_start_idx = 0,
	};

	int map_fd = bpf_map__fd(skel->maps.vip_table);
	if (bpf_map_update_elem(map_fd, &vkey, &vmeta, BPF_ANY)) {
		perror("Failed to update vip_table");
		return -1;
	}

	/* Populate backends */
	map_fd = bpf_map__fd(skel->maps.backends);
	for (int i = 0; i < be_count; i++) {
		struct backend_info be = {0};

		if (inet_pton(AF_INET, be_args[i].ip, &be.address) != 1) {
			fprintf(stderr, "Bad backend IP: %s\n", be_args[i].ip);
			return -1;
		}
		be.port = htons(be_args[i].port);

		if (parse_mac(be_args[i].mac_str, be.mac) < 0) {
			fprintf(stderr, "Bad backend MAC: %s\n",
				be_args[i].mac_str);
			return -1;
		}

		__u32 key = i;
		if (bpf_map_update_elem(map_fd, &key, &be, BPF_ANY)) {
			perror("Failed to update backends");
			return -1;
		}

		printf("  backend[%d] = %s:%d (%s)\n", i,
		       be_args[i].ip, be_args[i].port, be_args[i].mac_str);
	}

	/* Store LB interface MAC */
	__u8 lb_mac[6];
	if (get_iface_mac(ifname, lb_mac) < 0) {
		fprintf(stderr, "Warning: couldn't read MAC for %s\n", ifname);
	} else {
		struct lb_config cfg = {0};
		memcpy(cfg.lb_mac, lb_mac, 6);
		__u32 cfg_key = CFG_IDX;
		map_fd = bpf_map__fd(skel->maps.lb_config);
		bpf_map_update_elem(map_fd, &cfg_key, &cfg, BPF_ANY);
		printf("  lb_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
		       lb_mac[0], lb_mac[1], lb_mac[2],
		       lb_mac[3], lb_mac[4], lb_mac[5]);
	}

	printf("VIP %s:%d/%s → %d backends\n",
	       vip_ip, vip_port, proto_str, be_count);
	return 0;
}

static int cmd_start(int argc, char **argv)
{
	const char *ifname = NULL;
	const char *vip_str = NULL;
	struct backend_arg be_args[MAX_BACKENDS_CLI];
	int be_count = 0;
	int opt;

	optind = 1;
	while ((opt = getopt(argc, argv, "i:v:b:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'v':
			vip_str = optarg;
			break;
		case 'b':
			if (be_count >= MAX_BACKENDS_CLI) {
				fprintf(stderr, "Too many backends (max %d)\n",
					MAX_BACKENDS_CLI);
				return 1;
			}
			if (sscanf(optarg, "%[^:]:%d:%17s",
				   be_args[be_count].ip,
				   &be_args[be_count].port,
				   be_args[be_count].mac_str) != 3) {
				fprintf(stderr,
					"Bad backend format: %s "
					"(expected ip:port:mac)\n", optarg);
				return 1;
			}
			be_count++;
			break;
		default:
			return 1;
		}
	}

	if (!ifname || !vip_str || be_count == 0) {
		fprintf(stderr,
			"Error: -i, -v, and at least one -b required\n");
		return 1;
	}

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		return 1;
	}

	struct xdp_lb_kern *skel = xdp_lb_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int err = xdp_lb_kern__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	if (populate_maps(skel, ifname, vip_str, be_args, be_count) < 0) {
		err = -1;
		goto cleanup;
	}

	int prog_fd = bpf_program__fd(skel->progs.xdp_lb_func);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach to %s: %d\n", ifname, err);
		goto cleanup;
	}

	printf("XDP load balancer attached to %s (ifindex %u)\n",
	       ifname, ifindex);
	printf("Press Ctrl+C to detach\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		sleep(1);

	printf("\nDetaching from %s...\n", ifname);
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	xdp_lb_kern__destroy(skel);
	return err ? 1 : 0;
}

static int cmd_stop(int argc, char **argv)
{
	const char *ifname = NULL;
	int opt;

	optind = 1;
	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		default:
			return 1;
		}
	}

	if (!ifname) {
		fprintf(stderr, "Error: -i <interface> required\n");
		return 1;
	}

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		return 1;
	}

	int err = bpf_xdp_detach(ifindex, 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to detach from %s: %d\n", ifname, err);
		return 1;
	}

	printf("XDP program detached from %s\n", ifname);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];
	argc--;
	argv++;

	if (strcmp(cmd, "start") == 0)
		return cmd_start(argc, argv);
	if (strcmp(cmd, "stop") == 0)
		return cmd_stop(argc, argv);

	fprintf(stderr, "Unknown command: %s\n", cmd);
	usage(argv[0]);
	return 1;
}
