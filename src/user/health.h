#ifndef __ZLB_HEALTH_H
#define __ZLB_HEALTH_H

#include <pthread.h>
#include <linux/types.h>
#include "xdp_lb_common.h"

#define HEALTH_FAIL_THRESHOLD 3
#define HEALTH_OK_THRESHOLD 2
#define MAX_PHYSICAL_BACKENDS 16

struct backend_slot_range {
	int start;
	int count;
};

struct health_ctx {
	int backends_fd;
	int vip_fd;
	int nr_backends;
	int interval_sec;
	int timeout_ms;

	int nr_physical;
	struct backend_slot_range slots[MAX_PHYSICAL_BACKENDS];
	struct backend_info originals[MAX_PHYSICAL_BACKENDS];

	volatile int stop;
	pthread_t thread;
};

int health_start(struct health_ctx *ctx);
void health_stop(struct health_ctx *ctx);

#endif
