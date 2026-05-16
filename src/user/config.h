#ifndef __ZLB_CONFIG_H
#define __ZLB_CONFIG_H

#include <linux/types.h>
#include "xdp_lb_common.h"

#define MAX_CFG_BACKENDS 16

struct backend_cfg {
	char     ip[16];
	int      port;
	char     mac_str[18];
};

struct lb_cfg {
	char     interface[16];
	char     vip_ip[16];
	int      vip_port;
	__u8     protocol;

	struct backend_cfg backends[MAX_CFG_BACKENDS];
	int    backend_count;

	int    health_interval;
	int    health_timeout;
};

struct lb_cfg *config_load(const char *path);
void config_free(struct lb_cfg *cfg);

#endif
