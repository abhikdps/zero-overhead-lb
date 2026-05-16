#ifndef __ZLB_HEALTH_H
#define __ZLB_HEALTH_H

#include <pthread.h>
#include <linux/types.h>
#include "xdp_lb_common.h"

#define HEALTH_FAIL_THRESHOLD 3
#define HEALTH_OK_THRESHOLD   2

struct health_ctx {
	int    backends_fd;
	int    vip_fd;
	int    nr_backends;
	int    interval_sec;
	int    timeout_ms;

	struct backend_info originals[MAX_BACKENDS];

	volatile int stop;
	pthread_t    thread;
};

int  health_start(struct health_ctx *ctx);
void health_stop(struct health_ctx *ctx);

#endif
