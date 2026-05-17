#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "xdp_lb_common.h"
#include "events.h"

#define PIN_BASE "/sys/fs/bpf/zlb"

static volatile sig_atomic_t events_running = 1;

static void events_sig_handler(int sig)
{
	events_running = 0;
}

static const char *event_type_str(__u8 type)
{
	switch (type) {
	case LB_EVENT_FORWARD:  return "FORWARD";
	case LB_EVENT_PASS:     return "PASS";
	case LB_EVENT_CONN_NEW: return "CONN_NEW";
	default:                return "UNKNOWN";
	}
}

static const char *pass_reason_str(__u8 reason)
{
	switch (reason) {
	case PASS_NOT_IPV4:     return "not_ipv4";
	case PASS_NOT_TCP_UDP:  return "not_tcp_udp";
	case PASS_VIP_MISS:     return "vip_miss";
	case PASS_NO_BACKENDS:  return "no_backends";
	case PASS_LB_OWN_IP:    return "lb_own_ip";
	case PASS_FRAGMENT:     return "fragment";
	case PASS_BACKEND_MISS: return "backend_miss";
	default:                return "";
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	if (size < sizeof(struct lb_event))
		return 0;

	struct lb_event *evt = data;

	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &evt->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &evt->dst_ip, dst, sizeof(dst));

	const char *proto = "?";
	if (evt->protocol == IPPROTO_TCP)
		proto = "TCP";
	else if (evt->protocol == IPPROTO_UDP)
		proto = "UDP";

	if (evt->type == LB_EVENT_FORWARD) {
		printf("%-8s %s %s:%d -> %s:%d  be=%u\n",
		       event_type_str(evt->type), proto,
		       src, ntohs(evt->src_port),
		       dst, ntohs(evt->dst_port),
		       evt->backend_idx);
	} else if (evt->type == LB_EVENT_PASS) {
		printf("%-8s %s %s:%d -> %s:%d  reason=%s\n",
		       event_type_str(evt->type), proto,
		       src, ntohs(evt->src_port),
		       dst, ntohs(evt->dst_port),
		       pass_reason_str(evt->reason));
	} else {
		printf("%-8s %s %s:%d -> %s:%d  be=%u\n",
		       event_type_str(evt->type), proto,
		       src, ntohs(evt->src_port),
		       dst, ntohs(evt->dst_port),
		       evt->backend_idx);
	}

	return 0;
}

int cmd_events(int argc, char **argv)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/events", PIN_BASE);

	int fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr,
			"Cannot open ring buffer at %s\n"
			"Is the load balancer running?\n", path);
		return 1;
	}

	struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer reader\n");
		close(fd);
		return 1;
	}

	signal(SIGINT, events_sig_handler);
	signal(SIGTERM, events_sig_handler);

	printf("%-8s %-4s %-21s    %-21s    %s\n",
	       "TYPE", "PROTO", "SOURCE", "DESTINATION", "INFO");
	for (int i = 0; i < 72; i++)
		putchar('-');
	putchar('\n');

	while (events_running) {
		int err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR)
			break;
	}

	printf("\n");
	ring_buffer__free(rb);
	close(fd);
	return 0;
}
