#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "config.h"
#include "cJSON.h"

struct lb_cfg *config_load(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		perror(path);
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *buf = malloc(len + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, len, f) != (size_t)len) {
		free(buf);
		fclose(f);
		fprintf(stderr, "Failed to read %s\n", path);
		return NULL;
	}
	buf[len] = '\0';
	fclose(f);

	cJSON *root = cJSON_Parse(buf);
	free(buf);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n",
		        cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown");
		return NULL;
	}

	struct lb_cfg *cfg = calloc(1, sizeof(*cfg));
	if (!cfg) {
		cJSON_Delete(root);
		return NULL;
	}

	cfg->health_interval = 5;
	cfg->health_timeout = 2000;

	cJSON *iface = cJSON_GetObjectItem(root, "interface");
	if (cJSON_IsString(iface))
		snprintf(cfg->interface, sizeof(cfg->interface), "%s",
		         iface->valuestring);

	cJSON *vip = cJSON_GetObjectItem(root, "vip");
	if (vip) {
		cJSON *addr = cJSON_GetObjectItem(vip, "address");
		cJSON *port = cJSON_GetObjectItem(vip, "port");
		cJSON *proto = cJSON_GetObjectItem(vip, "protocol");

		if (cJSON_IsString(addr))
			snprintf(cfg->vip_ip, sizeof(cfg->vip_ip), "%s",
			         addr->valuestring);
		if (cJSON_IsNumber(port))
			cfg->vip_port = port->valueint;
		if (cJSON_IsString(proto)) {
			if (strcmp(proto->valuestring, "tcp") == 0)
				cfg->protocol = IPPROTO_TCP;
			else if (strcmp(proto->valuestring, "udp") == 0)
				cfg->protocol = IPPROTO_UDP;
		}
	}

	cJSON *backends = cJSON_GetObjectItem(root, "backends");
	if (cJSON_IsArray(backends)) {
		cJSON *be;
		cJSON_ArrayForEach(be, backends)
		{
			if (cfg->backend_count >= MAX_CFG_BACKENDS)
				break;

			struct backend_cfg *b =
			    &cfg->backends[cfg->backend_count];
			cJSON *addr = cJSON_GetObjectItem(be, "address");
			cJSON *port = cJSON_GetObjectItem(be, "port");
			cJSON *mac = cJSON_GetObjectItem(be, "mac");

			if (cJSON_IsString(addr))
				snprintf(b->ip, sizeof(b->ip), "%s",
				         addr->valuestring);
			if (cJSON_IsNumber(port))
				b->port = port->valueint;
			if (cJSON_IsString(mac))
				snprintf(b->mac_str, sizeof(b->mac_str), "%s",
				         mac->valuestring);

			cJSON *weight = cJSON_GetObjectItem(be, "weight");
			b->weight =
			    (cJSON_IsNumber(weight) && weight->valueint > 0)
			        ? weight->valueint
			        : 1;

			cfg->backend_count++;
		}
	}

	cJSON *health = cJSON_GetObjectItem(root, "health");
	if (health) {
		cJSON *interval = cJSON_GetObjectItem(health, "interval");
		cJSON *timeout = cJSON_GetObjectItem(health, "timeout");

		if (cJSON_IsNumber(interval))
			cfg->health_interval = interval->valueint;
		if (cJSON_IsNumber(timeout))
			cfg->health_timeout = timeout->valueint;
	}

	cJSON *redirect = cJSON_GetObjectItem(root, "redirect");
	if (redirect) {
		cJSON *enabled = cJSON_GetObjectItem(redirect, "enabled");
		cJSON *egress = cJSON_GetObjectItem(redirect, "egress_iface");

		if (cJSON_IsTrue(enabled))
			cfg->redirect_enabled = 1;
		if (cJSON_IsString(egress) && strlen(egress->valuestring) > 0)
			snprintf(cfg->egress_iface, sizeof(cfg->egress_iface),
			         "%s", egress->valuestring);
	}

	cJSON_Delete(root);
	return cfg;
}

void config_free(struct lb_cfg *cfg)
{
	free(cfg);
}

static int validate_mac(const char *str)
{
	unsigned int m[6];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4],
	           &m[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (m[i] > 0xff)
			return -1;
	}
	if (m[0] & 0x01)
		return -1;
	return 0;
}

int config_validate(struct lb_cfg *cfg)
{
	struct in_addr tmp;

	if (strlen(cfg->interface) == 0) {
		fprintf(stderr, "Error: interface name is empty\n");
		return -1;
	}

	if (inet_pton(AF_INET, cfg->vip_ip, &tmp) != 1) {
		fprintf(stderr, "Error: invalid VIP address '%s'\n",
		        cfg->vip_ip);
		return -1;
	}

	if (cfg->vip_port <= 0 || cfg->vip_port > 65535) {
		fprintf(stderr, "Error: VIP port %d out of range [1-65535]\n",
		        cfg->vip_port);
		return -1;
	}

	if (cfg->protocol != IPPROTO_TCP && cfg->protocol != IPPROTO_UDP) {
		fprintf(stderr, "Error: protocol must be 'tcp' or 'udp'\n");
		return -1;
	}

	if (cfg->backend_count <= 0) {
		fprintf(stderr, "Error: at least one backend required\n");
		return -1;
	}
	if (cfg->backend_count > MAX_CFG_BACKENDS) {
		fprintf(stderr, "Error: too many backends (max %d)\n",
		        MAX_CFG_BACKENDS);
		return -1;
	}

	int total_weight = 0;
	for (int i = 0; i < cfg->backend_count; i++) {
		if (inet_pton(AF_INET, cfg->backends[i].ip, &tmp) != 1) {
			fprintf(stderr, "Error: backend[%d] invalid IP '%s'\n",
			        i, cfg->backends[i].ip);
			return -1;
		}
		if (cfg->backends[i].port <= 0 ||
		    cfg->backends[i].port > 65535) {
			fprintf(stderr,
			        "Error: backend[%d] port %d out of range\n", i,
			        cfg->backends[i].port);
			return -1;
		}
		if (validate_mac(cfg->backends[i].mac_str) < 0) {
			fprintf(stderr, "Error: backend[%d] invalid MAC '%s'\n",
			        i, cfg->backends[i].mac_str);
			return -1;
		}

		int w =
		    cfg->backends[i].weight > 0 ? cfg->backends[i].weight : 1;
		if (w > 10) {
			fprintf(stderr,
			        "Error: backend[%d] weight %d exceeds max 10\n",
			        i, w);
			return -1;
		}
		total_weight += w;
	}

	if (total_weight > MAX_BACKENDS) {
		fprintf(stderr,
		        "Error: total weight %d exceeds MAX_BACKENDS (%d)\n",
		        total_weight, MAX_BACKENDS);
		return -1;
	}

	if (cfg->health_interval < 1 || cfg->health_interval > 300) {
		fprintf(stderr,
		        "Error: health interval %d out of range [1-300]\n",
		        cfg->health_interval);
		return -1;
	}
	if (cfg->health_timeout < 100 || cfg->health_timeout > 30000) {
		fprintf(stderr,
		        "Error: health timeout %d out of range [100-30000]\n",
		        cfg->health_timeout);
		return -1;
	}

	return 0;
}
