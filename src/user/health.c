#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include "health.h"

struct backend_health {
	int consecutive_fail;
	int consecutive_ok;
	int healthy;
};

static int tcp_check(struct backend_info *be, int timeout_ms)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_in addr = {
	    .sin_family = AF_INET,
	    .sin_addr.s_addr = be->address,
	    .sin_port = be->port,
	};

	int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == 0) {
		close(fd);
		return 0;
	}

	if (errno != EINPROGRESS) {
		close(fd);
		return -1;
	}

	struct pollfd pfd = {.fd = fd, .events = POLLOUT};
	ret = poll(&pfd, 1, timeout_ms);

	if (ret > 0 && (pfd.revents & POLLOUT)) {
		int err = 0;
		socklen_t len = sizeof(err);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
		close(fd);
		return err ? -1 : 0;
	}

	close(fd);
	return -1;
}

static void update_slots(struct health_ctx *ctx, int phys_idx,
                         struct backend_info *be)
{
	for (int s = 0; s < ctx->slots[phys_idx].count; s++) {
		__u32 key = ctx->slots[phys_idx].start + s;
		bpf_map_update_elem(ctx->backends_fd, &key, be, BPF_ANY);
	}
}

static void *health_thread(void *arg)
{
	struct health_ctx *ctx = arg;
	struct backend_health bh[MAX_PHYSICAL_BACKENDS] = {0};

	for (int i = 0; i < ctx->nr_physical; i++)
		bh[i].healthy = 1;

	while (!ctx->stop) {
		for (int i = 0; i < ctx->nr_physical; i++) {
			struct backend_info *be = &ctx->originals[i];
			int ok = (tcp_check(be, ctx->timeout_ms) == 0);

			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &be->address, ip, sizeof(ip));

			if (ok) {
				bh[i].consecutive_fail = 0;
				bh[i].consecutive_ok++;

				if (!bh[i].healthy && bh[i].consecutive_ok >=
				                          HEALTH_OK_THRESHOLD) {
					bh[i].healthy = 1;
					fprintf(stderr, "[health] %s:%d UP\n",
					        ip, ntohs(be->port));
					update_slots(ctx, i,
					             &ctx->originals[i]);
				}
			} else {
				bh[i].consecutive_ok = 0;
				bh[i].consecutive_fail++;

				if (bh[i].healthy &&
				    bh[i].consecutive_fail >=
				        HEALTH_FAIL_THRESHOLD) {
					bh[i].healthy = 0;
					fprintf(stderr, "[health] %s:%d DOWN\n",
					        ip, ntohs(be->port));

					int replace = -1;
					for (int j = 0; j < ctx->nr_physical;
					     j++) {
						if (j != i && bh[j].healthy) {
							replace = j;
							break;
						}
					}

					if (replace >= 0)
						update_slots(
						    ctx, i,
						    &ctx->originals[replace]);
				}
			}
		}

		for (int s = 0; s < ctx->interval_sec && !ctx->stop; s++)
			sleep(1);
	}

	return NULL;
}

int health_start(struct health_ctx *ctx)
{
	for (int i = 0; i < ctx->nr_physical; i++) {
		__u32 key = ctx->slots[i].start;
		if (bpf_map_lookup_elem(ctx->backends_fd, &key,
		                        &ctx->originals[i]) < 0) {
			fprintf(stderr, "Failed to read backend %d\n", i);
			return -1;
		}
	}

	ctx->stop = 0;
	if (pthread_create(&ctx->thread, NULL, health_thread, ctx)) {
		perror("pthread_create");
		return -1;
	}

	fprintf(stderr,
	        "[health] started: interval=%ds timeout=%dms "
	        "backends=%d\n",
	        ctx->interval_sec, ctx->timeout_ms, ctx->nr_physical);
	return 0;
}

void health_stop(struct health_ctx *ctx)
{
	ctx->stop = 1;
	pthread_join(ctx->thread, NULL);

	for (int i = 0; i < ctx->nr_physical; i++)
		update_slots(ctx, i, &ctx->originals[i]);

	fprintf(stderr, "[health] stopped, backends restored\n");
}
