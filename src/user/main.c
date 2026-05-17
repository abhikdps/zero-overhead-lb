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
#include "events.h"

#define MAX_BACKENDS_CLI 16
#define PIN_BASE_DIR "/sys/fs/bpf/zlb"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

struct backend_arg {
	char ip[INET_ADDRSTRLEN];
	int port;
	char mac_str[18];
	int weight;
};

static int parse_mac(const char *str, __u8 mac[6])
{
	unsigned int m[6];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4],
	           &m[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++)
		mac[i] = (__u8)m[i];
	return 0;
}

static int get_iface_ip(const char *ifname, __be32 *ip)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	int err = ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	if (err < 0)
		return -1;

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
	*ip = addr->sin_addr.s_addr;
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
                         struct backend_arg *be_args, int be_count,
                         int redirect_enabled, const char *egress_iface)
{
	struct vip_key vkey = {.protocol = protocol};
	if (inet_pton(AF_INET, vip_ip, &vkey.address) != 1) {
		fprintf(stderr, "Bad VIP IP: %s\n", vip_ip);
		return -1;
	}
	vkey.port = htons(vip_port);

	int total_weight = 0;
	for (int i = 0; i < be_count; i++) {
		int w = be_args[i].weight > 0 ? be_args[i].weight : 1;
		total_weight += w;
	}

	struct vip_meta vmeta = {
	    .backend_count = total_weight,
	    .backend_start_idx = 0,
	};

	int map_fd = bpf_map__fd(skel->maps.vip_table);
	if (bpf_map_update_elem(map_fd, &vkey, &vmeta, BPF_ANY)) {
		perror("Failed to update vip_table");
		return -1;
	}

	map_fd = bpf_map__fd(skel->maps.backends);
	__u32 slot = 0;
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

		int w = be_args[i].weight > 0 ? be_args[i].weight : 1;
		for (int j = 0; j < w; j++) {
			__u32 key = slot++;
			if (bpf_map_update_elem(map_fd, &key, &be, BPF_ANY)) {
				perror("Failed to update backends");
				return -1;
			}
		}

		printf("  backend[%d] = %s:%d (%s) weight=%d\n", i,
		       be_args[i].ip, be_args[i].port, be_args[i].mac_str, w);
	}

	__u8 lb_mac[6];
	if (get_iface_mac(ifname, lb_mac) == 0) {
		struct lb_config lbcfg = {0};
		memcpy(lbcfg.lb_mac, lb_mac, 6);
		get_iface_ip(ifname, &lbcfg.lb_ip);

		if (redirect_enabled && egress_iface &&
		    strlen(egress_iface) > 0) {
			unsigned int egress_idx = if_nametoindex(egress_iface);
			if (!egress_idx) {
				fprintf(stderr,
				        "Egress interface %s not found\n",
				        egress_iface);
				return -1;
			}
			lbcfg.use_redirect = 1;

			__u32 devmap_key = 0;
			__u32 devmap_val = egress_idx;
			int devmap_fd = bpf_map__fd(skel->maps.tx_port);
			bpf_map_update_elem(devmap_fd, &devmap_key, &devmap_val,
			                    BPF_ANY);
			printf("  redirect -> %s (ifindex %u)\n", egress_iface,
			       egress_idx);
		}

		__u32 cfg_key = CFG_IDX;
		map_fd = bpf_map__fd(skel->maps.lb_config);
		bpf_map_update_elem(map_fd, &cfg_key, &lbcfg, BPF_ANY);

		char ip_str[INET_ADDRSTRLEN] = "none";
		if (lbcfg.lb_ip)
			inet_ntop(AF_INET, &lbcfg.lb_ip, ip_str,
			          sizeof(ip_str));
		printf("  lb_mac = %02x:%02x:%02x:%02x:%02x:%02x  lb_ip = %s\n",
		       lb_mac[0], lb_mac[1], lb_mac[2], lb_mac[3], lb_mac[4],
		       lb_mac[5], ip_str);
	}

	const char *proto_name = (protocol == IPPROTO_TCP) ? "tcp" : "udp";
	printf("VIP %s:%d/%s -> %d backends (total_weight=%d)\n", vip_ip,
	       vip_port, proto_name, be_count, total_weight);
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
	        "  start   -i <iface> -c <config.json>\n"
	        "  start   -i <iface> -v <vip> -b <backend> [-b ...]\n"
	        "  stop    -i <interface>\n"
	        "  stats   [-w]\n"
	        "  status\n"
	        "  events\n"
	        "  reload  -c <config.json>\n"
	        "\n"
	        "Examples:\n"
	        "  %s start -i eth0 -c config/example.json\n"
	        "  %s start -i eth0 -v 10.0.0.100:80:tcp -b "
	        "10.0.0.2:80:aa:bb:cc:dd:ee:01\n"
	        "  %s stats -w\n"
	        "  %s events\n",
	        prog, prog, prog, prog, prog);
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
		if (config_validate(cfg) < 0) {
			config_free(cfg);
			return 1;
		}
		if (!ifname)
			ifname = cfg->interface;
	}

	if (!ifname) {
		fprintf(stderr, "Error: -i <interface> required\n");
		config_free(cfg);
		return 1;
	}

	if (!config_path && (!vip_str || be_count == 0)) {
		fprintf(
		    stderr,
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
			snprintf(be_args[i].mac_str, sizeof(be_args[i].mac_str),
			         "%s", cfg->backends[i].mac_str);
			be_args[i].weight = cfg->backends[i].weight;
		}
		be_count = cfg->backend_count;

		err = populate_maps(skel, ifname, cfg->vip_ip, cfg->vip_port,
		                    cfg->protocol, be_args, be_count,
		                    cfg->redirect_enabled, cfg->egress_iface);
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
		                    be_args, be_count, 0, NULL);
	}

	if (err)
		goto cleanup_pin;

	int prog_fd = bpf_program__fd(skel->progs.xdp_lb_func);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach to %s: %d\n", ifname, err);
		goto cleanup_pin;
	}

	printf("XDP load balancer attached to %s (ifindex %u)\n", ifname,
	       ifindex);

	struct health_ctx *hctx = NULL;
	if (cfg && cfg->health_interval > 0 && be_count > 0) {
		hctx = calloc(1, sizeof(*hctx));
		if (hctx) {
			hctx->backends_fd = bpf_map__fd(skel->maps.backends);
			hctx->vip_fd = bpf_map__fd(skel->maps.vip_table);
			hctx->nr_backends = be_count;
			hctx->interval_sec = cfg->health_interval;
			hctx->timeout_ms = cfg->health_timeout;

			hctx->nr_physical = be_count;
			__u32 s = 0;
			for (int i = 0; i < be_count; i++) {
				int w = be_args[i].weight > 0
				            ? be_args[i].weight
				            : 1;
				hctx->slots[i].start = s;
				hctx->slots[i].count = w;
				s += w;
			}

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
	const char *map_names[] = {"vip_table", "backends", "stats",
	                           "connection_table", "lb_config"};

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
		printf(
		    "  No pinned maps found. Is the load balancer running?\n");
		return 1;
	}

	return 0;
}

static int cmd_reload(int argc, char **argv)
{
	const char *config_path = NULL;
	int opt;

	optind = 1;
	while ((opt = getopt(argc, argv, "c:")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		default:
			fprintf(stderr, "Usage: zlb reload -c <config.json>\n");
			return 1;
		}
	}

	if (!config_path) {
		fprintf(stderr, "Usage: zlb reload -c <config.json>\n");
		return 1;
	}

	struct lb_cfg *cfg = config_load(config_path);
	if (!cfg)
		return 1;

	if (config_validate(cfg) < 0) {
		config_free(cfg);
		return 1;
	}

	char path[256];
	snprintf(path, sizeof(path), "%s/backends", PIN_BASE_DIR);
	int backends_fd = bpf_obj_get(path);
	snprintf(path, sizeof(path), "%s/vip_table", PIN_BASE_DIR);
	int vip_fd = bpf_obj_get(path);
	snprintf(path, sizeof(path), "%s/lb_config", PIN_BASE_DIR);
	int config_fd = bpf_obj_get(path);

	if (backends_fd < 0 || vip_fd < 0) {
		fprintf(stderr,
		        "Cannot open pinned maps at %s\n"
		        "Is the load balancer running?\n",
		        PIN_BASE_DIR);
		config_free(cfg);
		return 1;
	}

	/* Step 1: write all backend slots (expanded by weight) */
	int total_weight = 0;
	for (int i = 0; i < cfg->backend_count; i++) {
		int w =
		    cfg->backends[i].weight > 0 ? cfg->backends[i].weight : 1;
		total_weight += w;
	}

	__u32 slot = 0;
	for (int i = 0; i < cfg->backend_count; i++) {
		struct backend_info be = {0};
		inet_pton(AF_INET, cfg->backends[i].ip, &be.address);
		be.port = htons(cfg->backends[i].port);
		parse_mac(cfg->backends[i].mac_str, be.mac);

		int w =
		    cfg->backends[i].weight > 0 ? cfg->backends[i].weight : 1;
		for (int j = 0; j < w; j++) {
			__u32 key = slot++;
			bpf_map_update_elem(backends_fd, &key, &be, BPF_ANY);
		}
	}

	/* Clear stale slots beyond new total */
	struct backend_info empty = {0};
	for (__u32 k = slot; k < MAX_BACKENDS; k++) {
		bpf_map_update_elem(backends_fd, &k, &empty, BPF_ANY);
	}

	/* Step 2: update VIP entry with new backend_count */
	struct vip_key vkey = {.protocol = cfg->protocol};
	inet_pton(AF_INET, cfg->vip_ip, &vkey.address);
	vkey.port = htons(cfg->vip_port);
	struct vip_meta vmeta = {
	    .backend_count = total_weight,
	    .backend_start_idx = 0,
	};
	bpf_map_update_elem(vip_fd, &vkey, &vmeta, BPF_ANY);

	/* Step 3: update lb_config if possible */
	if (config_fd >= 0 && cfg->interface[0]) {
		struct lb_config lbcfg = {0};
		get_iface_mac(cfg->interface, lbcfg.lb_mac);
		get_iface_ip(cfg->interface, &lbcfg.lb_ip);

		if (cfg->redirect_enabled && cfg->egress_iface[0]) {
			lbcfg.use_redirect = 1;
			/* DEVMAP update requires skeleton access; skip here */
		}

		__u32 cfg_key = CFG_IDX;
		bpf_map_update_elem(config_fd, &cfg_key, &lbcfg, BPF_ANY);
		close(config_fd);
	}

	printf("Reload complete: %d backends, total_weight=%d\n",
	       cfg->backend_count, total_weight);
	printf("Note: health checks use the running process config; "
	       "restart zlb for health check updates.\n");

	close(backends_fd);
	close(vip_fd);
	config_free(cfg);
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
	if (strcmp(cmd, "events") == 0)
		return cmd_events(argc, argv);
	if (strcmp(cmd, "reload") == 0)
		return cmd_reload(argc, argv);

	fprintf(stderr, "Unknown command: %s\n", cmd);
	usage(argv[0]);
	return 1;
}
