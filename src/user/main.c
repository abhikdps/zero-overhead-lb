#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_lb_kern.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options]\n"
		"\n"
		"Commands:\n"
		"  start -i <interface>   Attach XDP load balancer\n"
		"  stop  -i <interface>   Detach XDP load balancer\n",
		prog);
}

static int cmd_start(int argc, char **argv)
{
	const char *ifname = NULL;
	int opt;

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
	usage(argv[0] - 1);
	return 1;
}
