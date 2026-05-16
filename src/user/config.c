#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	cfg->health_timeout  = 2000;

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
		cJSON_ArrayForEach(be, backends) {
			if (cfg->backend_count >= MAX_CFG_BACKENDS)
				break;

			struct backend_cfg *b = &cfg->backends[cfg->backend_count];
			cJSON *addr = cJSON_GetObjectItem(be, "address");
			cJSON *port = cJSON_GetObjectItem(be, "port");
			cJSON *mac  = cJSON_GetObjectItem(be, "mac");

			if (cJSON_IsString(addr))
				snprintf(b->ip, sizeof(b->ip), "%s",
					 addr->valuestring);
			if (cJSON_IsNumber(port))
				b->port = port->valueint;
			if (cJSON_IsString(mac))
				snprintf(b->mac_str, sizeof(b->mac_str), "%s",
					 mac->valuestring);

			cfg->backend_count++;
		}
	}

	cJSON *health = cJSON_GetObjectItem(root, "health");
	if (health) {
		cJSON *interval = cJSON_GetObjectItem(health, "interval");
		cJSON *timeout  = cJSON_GetObjectItem(health, "timeout");

		if (cJSON_IsNumber(interval))
			cfg->health_interval = interval->valueint;
		if (cJSON_IsNumber(timeout))
			cfg->health_timeout = timeout->valueint;
	}

	cJSON_Delete(root);
	return cfg;
}

void config_free(struct lb_cfg *cfg)
{
	free(cfg);
}
