#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "xdp_lb_common.h"
#include "stats.h"

#define PIN_BASE "/sys/fs/bpf/zlb"

static volatile sig_atomic_t stats_running = 1;

static void stats_sig_handler(int sig)
{
	stats_running = 0;
}

static int get_nr_cpus(void)
{
	return libbpf_num_possible_cpus();
}

static void format_bytes(char *buf, size_t bufsz, __u64 bytes)
{
	if (bytes >= 1000000000ULL)
		snprintf(buf, bufsz, "%.1f GB", (double)bytes / 1e9);
	else if (bytes >= 1000000ULL)
		snprintf(buf, bufsz, "%.1f MB", (double)bytes / 1e6);
	else if (bytes >= 1000ULL)
		snprintf(buf, bufsz, "%.1f KB", (double)bytes / 1e3);
	else
		snprintf(buf, bufsz, "%llu B", (unsigned long long)bytes);
}

static void format_number(char *buf, size_t bufsz, __u64 n)
{
	if (n >= 1000000000ULL)
		snprintf(buf, bufsz, "%.1fB", (double)n / 1e9);
	else if (n >= 1000000ULL)
		snprintf(buf, bufsz, "%.1fM", (double)n / 1e6);
	else if (n >= 1000ULL)
		snprintf(buf, bufsz, "%.1fK", (double)n / 1e3);
	else
		snprintf(buf, bufsz, "%llu", (unsigned long long)n);
}

struct backend_display {
	char addr_str[24];
	__u64 packets;
	__u64 bytes;
	__u64 prev_packets;
};

static int find_display(const struct backend_display *out, int count,
                        const char *addr_str)
{
	for (int i = 0; i < count; i++) {
		if (strcmp(out[i].addr_str, addr_str) == 0)
			return i;
	}
	return -1;
}

static int read_stats(int stats_fd, int backends_fd, int nr_cpus,
                      struct backend_display *out, int *out_count)
{
	int count = *out_count;
	size_t val_sz = nr_cpus * sizeof(struct lb_stats);
	struct lb_stats *percpu_vals = malloc(val_sz);
	if (!percpu_vals)
		return -1;

	/* Save previous packet counts for PPS */
	__u64 prev[MAX_BACKENDS];
	for (int i = 0; i < count; i++)
		prev[i] = out[i].packets;

	/* Zero out current values before re-aggregation */
	for (int i = 0; i < count; i++) {
		out[i].packets = 0;
		out[i].bytes = 0;
	}

	for (__u32 i = 0; i < MAX_BACKENDS; i++) {
		struct backend_info be;
		if (bpf_map_lookup_elem(backends_fd, &i, &be) < 0)
			break;

		if (be.address == 0)
			break;

		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &be.address, ip, sizeof(ip));
		char addr_str[24];
		snprintf(addr_str, sizeof(addr_str), "%s:%d", ip,
		         ntohs(be.port));

		int idx = find_display(out, count, addr_str);
		if (idx < 0) {
			idx = count++;
			snprintf(out[idx].addr_str, sizeof(out[idx].addr_str),
			         "%s", addr_str);
			out[idx].packets = 0;
			out[idx].bytes = 0;
			out[idx].prev_packets = 0;
		}

		memset(percpu_vals, 0, val_sz);
		if (bpf_map_lookup_elem(stats_fd, &i, percpu_vals) == 0) {
			for (int c = 0; c < nr_cpus; c++) {
				out[idx].packets += percpu_vals[c].packets;
				out[idx].bytes += percpu_vals[c].bytes;
			}
		}
	}

	for (int i = 0; i < count; i++)
		out[i].prev_packets = (i < *out_count) ? prev[i] : 0;

	*out_count = count;
	free(percpu_vals);
	return 0;
}

static void print_table(struct backend_display *backends, int count,
                        int show_pps)
{
	if (show_pps)
		printf("%-22s %12s %10s %10s\n", "Backend", "Packets", "Bytes",
		       "PPS");
	else
		printf("%-22s %12s %10s\n", "Backend", "Packets", "Bytes");

	for (int i = 0; i < (show_pps ? 58 : 46); i++)
		putchar('-');
	putchar('\n');

	for (int i = 0; i < count; i++) {
		char pkts_str[16], bytes_str[16];
		format_number(pkts_str, sizeof(pkts_str), backends[i].packets);
		format_bytes(bytes_str, sizeof(bytes_str), backends[i].bytes);

		if (show_pps) {
			__u64 pps =
			    backends[i].packets - backends[i].prev_packets;
			char pps_str[16];
			format_number(pps_str, sizeof(pps_str), pps);
			printf("%-22s %12s %10s %10s\n", backends[i].addr_str,
			       pkts_str, bytes_str, pps_str);
		} else {
			printf("%-22s %12s %10s\n", backends[i].addr_str,
			       pkts_str, bytes_str);
		}
	}
}

int cmd_stats(int argc, char **argv)
{
	int watch = 0;
	int opt;

	optind = 1;
	while ((opt = getopt(argc, argv, "w")) != -1) {
		switch (opt) {
		case 'w':
			watch = 1;
			break;
		default:
			fprintf(stderr, "Usage: zlb stats [-w]\n");
			return 1;
		}
	}

	char stats_path[256], backends_path[256];
	snprintf(stats_path, sizeof(stats_path), "%s/stats", PIN_BASE);
	snprintf(backends_path, sizeof(backends_path), "%s/backends", PIN_BASE);

	int stats_fd = bpf_obj_get(stats_path);
	if (stats_fd < 0) {
		fprintf(stderr,
		        "Cannot open pinned stats map at %s\n"
		        "Is the load balancer running?\n",
		        stats_path);
		return 1;
	}

	int backends_fd = bpf_obj_get(backends_path);
	if (backends_fd < 0) {
		fprintf(stderr, "Cannot open pinned backends map at %s\n",
		        backends_path);
		close(stats_fd);
		return 1;
	}

	int nr_cpus = get_nr_cpus();
	struct backend_display backends[MAX_BACKENDS] = {0};
	int count = 0;

	if (!watch) {
		read_stats(stats_fd, backends_fd, nr_cpus, backends, &count);
		print_table(backends, count, 0);
	} else {
		signal(SIGINT, stats_sig_handler);
		signal(SIGTERM, stats_sig_handler);

		read_stats(stats_fd, backends_fd, nr_cpus, backends, &count);

		while (stats_running) {
			sleep(1);
			if (!stats_running)
				break;
			read_stats(stats_fd, backends_fd, nr_cpus, backends,
			           &count);
			printf("\033[2J\033[H");
			print_table(backends, count, 1);
		}
		printf("\n");
	}

	close(stats_fd);
	close(backends_fd);
	return 0;
}
