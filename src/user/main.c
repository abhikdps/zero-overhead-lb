#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>

#include "xdp_lb_common.h"
#include "xdp_lb_kern.skel.h"
#include "config.h"
#include "stats.h"
#include "health.h"

#define MAX_BACKENDS_CLI 16
#define PIN_BASE_DIR     "/sys/fs/bpf/zlb"

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

static int populate_maps(struct xdp_lb_kern *skel, const char *ifname,
			 const char *vip_ip, int vip_port, __u8 protocol,
			 struct backend_arg *be_args, int be_count)
{
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

	__u8 lb_mac[6];
	if (get_iface_mac(ifname, lb_mac) == 0) {
		struct lb_config cfg = {0};
		memcpy(cfg.lb_mac, lb_mac, 6);
		__u32 cfg_key = CFG_IDX;
		map_fd = bpf_map__fd(skel->maps.lb_config);
		bpf_map_update_elem(map_fd, &cfg_key, &cfg, BPF_ANY);
		printf("  lb_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
		       lb_mac[0], lb_mac[1], lb_mac[2],
		       lb_mac[3], lb_mac[4], lb_mac[5]);
	}

	const char *proto_name = (protocol == IPPROTO_TCP) ? "tcp" : "udp";
	printf("VIP %s:%d/%s -> %d backends\n",
	       vip_ip, vip_port, proto_name, be_count);
	return 0;
}

static int pin_maps(struct xdp_lb_kern *skel)
{
	mkdir(PIN_BASE_DIR, 0700);
	return bpf_object__pin_maps(skel->obj, PIN_BASE_DIR);
}

static void unpin_maps(struct xdp_lb_kern *skel)
{
	bpf_object__unpin_maps(skel->obj, PIN_BASE_DIR);
	rmdir(PIN_BASE_DIR);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options]\n"
		"\n"
		"Commands:\n"
		"  start  -i <iface> -c <config.json>\n"
		"  start  -i <iface> -v <vip> -b <backend> [-b ...]\n"
		"  stop   -i <interface>\n"
		"  stats  [-w]\n"
		"  status\n"
		"\n"
		"Examples:\n"
		"  %s start -i eth0 -c config/example.json\n"
		"  %s start -i eth0 -v 10.0.0.100:80:tcp -b 10.0.0.2:80:aa:bb:cc:dd:ee:01\n"
		"  %s stats -w\n",
		prog, prog, prog, prog);
}

static int cmd_start(int argc, char **argv)
{
	const char *ifname = NULL;
	const char *vip_str = NULL;
	const char *config_path = NULL;
	struct backend_arg be_args[MAX_BACKENDS_CLI];
	int be_count = 0;
	int opt;

	optind = 1;
	while ((opt = getopt(argc, argv, "i:v:b:c:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'v':
			vip_str = optarg;
			break;
		case 'c':
			config_path = optarg;
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
					"Bad backend: %s (ip:port:mac)\n",
					optarg);
				return 1;
			}
			be_count++;
			break;
		default:
			return 1;
		}
	}

	struct lb_cfg *cfg = NULL;

	if (config_path) {
		cfg = config_load(config_path);
		if (!cfg)
			return 1;
		if (!ifname)
			ifname = cfg->interface;
	}

	if (!ifname) {
		fprintf(stderr, "Error: -i <interface> required\n");
		config_free(cfg);
		return 1;
	}

	if (!config_path && (!vip_str || be_count == 0)) {
		fprintf(stderr,
			"Error: -c <config> or -v <vip> -b <backend> required\n");
		return 1;
	}

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		config_free(cfg);
		return 1;
	}

	struct xdp_lb_kern *skel = xdp_lb_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		config_free(cfg);
		return 1;
	}

	int err = xdp_lb_kern__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	if (pin_maps(skel) < 0) {
		fprintf(stderr, "Warning: failed to pin maps to %s\n",
			PIN_BASE_DIR);
	}

	if (cfg) {
		for (int i = 0; i < cfg->backend_count; i++) {
			snprintf(be_args[i].ip, sizeof(be_args[i].ip), "%s",
				 cfg->backends[i].ip);
			be_args[i].port = cfg->backends[i].port;
			snprintf(be_args[i].mac_str,
				 sizeof(be_args[i].mac_str), "%s",
				 cfg->backends[i].mac_str);
		}
		be_count = cfg->backend_count;

		err = populate_maps(skel, ifname,
				    cfg->vip_ip, cfg->vip_port,
				    cfg->protocol, be_args, be_count);
	} else {
		char vip_ip[INET_ADDRSTRLEN];
		int vip_port;
		char proto_str[8];

		if (sscanf(vip_str, "%[^:]:%d:%7s", vip_ip, &vip_port,
			   proto_str) != 3) {
			fprintf(stderr, "Bad VIP: %s\n", vip_str);
			err = -1;
			goto cleanup_pin;
		}

		__u8 protocol;
		if (strcmp(proto_str, "tcp") == 0)
			protocol = IPPROTO_TCP;
		else if (strcmp(proto_str, "udp") == 0)
			protocol = IPPROTO_UDP;
		else {
			fprintf(stderr, "Unknown protocol: %s\n", proto_str);
			err = -1;
			goto cleanup_pin;
		}

		err = populate_maps(skel, ifname, vip_ip, vip_port, protocol,
				    be_args, be_count);
	}

	if (err)
		goto cleanup_pin;

	int prog_fd = bpf_program__fd(skel->progs.xdp_lb_func);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach to %s: %d\n", ifname, err);
		goto cleanup_pin;
	}

	printf("XDP load balancer attached to %s (ifindex %u)\n",
	       ifname, ifindex);

	struct health_ctx *hctx = NULL;
	if (cfg && cfg->health_interval > 0 && be_count > 0) {
		hctx = calloc(1, sizeof(*hctx));
		if (hctx) {
			hctx->backends_fd = bpf_map__fd(skel->maps.backends);
			hctx->vip_fd = bpf_map__fd(skel->maps.vip_table);
			hctx->nr_backends = be_count;
			hctx->interval_sec = cfg->health_interval;
			hctx->timeout_ms = cfg->health_timeout;
			if (health_start(hctx) < 0) {
				free(hctx);
				hctx = NULL;
			}
		}
	}

	printf("Press Ctrl+C to detach\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		sleep(1);

	printf("\nShutting down...\n");

	if (hctx) {
		health_stop(hctx);
		free(hctx);
	}

	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup_pin:
	unpin_maps(skel);

cleanup:
	xdp_lb_kern__destroy(skel);
	config_free(cfg);
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

static int cmd_status(void)
{
	char path[256];
	const char *map_names[] = {
		"vip_table", "backends", "stats",
		"connection_table", "lb_config"
	};

	printf("Pin directory: %s\n", PIN_BASE_DIR);

	int any = 0;
	for (int i = 0; i < 5; i++) {
		snprintf(path, sizeof(path), "%s/%s", PIN_BASE_DIR,
			 map_names[i]);
		int fd = bpf_obj_get(path);
		if (fd >= 0) {
			printf("  %-20s pinned\n", map_names[i]);
			close(fd);
			any = 1;
		}
	}

	if (!any) {
		printf("  No pinned maps found. Is the load balancer running?\n");
		return 1;
	}

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
	if (strcmp(cmd, "stats") == 0)
		return cmd_stats(argc, argv);
	if (strcmp(cmd, "status") == 0)
		return cmd_status();

	fprintf(stderr, "Unknown command: %s\n", cmd);
	usage(argv[0]);
	return 1;
}
