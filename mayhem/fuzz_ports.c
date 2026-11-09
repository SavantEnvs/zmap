// libFuzzer harness for zmap's -p/--target-ports parser (parse_ports).
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/pbm.h"
#include "../src/state.h"
#include "../src/ports.h"

// parse_ports() exits through log_fatal() on a port outside 0-65535 or a reversed range; the
// command line rejects those before parsing, so reject them here the same way.
static int portdef_is_fatal(const char *def)
{
	char *copy = strdup(def);
	if (!copy) {
		return 1;
	}
	int fatal = 0;
	for (char *next = strtok(copy, ","); next && !fatal; next = strtok(NULL, ",")) {
		char *dash = strchr(next, '-');
		if (dash) {
			*dash = '\0';
			long first = atoi(next), last = atoi(dash + 1);
			fatal = last > 0xFFFF || first > last || first < 0;
		} else {
			long p = atoi(next);
			fatal = p < 0 || p > 0xFFFF;
		}
	}
	free(copy);
	return fatal;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 256) {
		return -1;
	}
	char *def = malloc(size + 1);
	memcpy(def, data, size);
	def[size] = '\0';
	if (!strcmp(def, "*") || portdef_is_fatal(def)) {
		free(def);
		return -1;
	}
	struct port_conf *ports = calloc(1, sizeof(struct port_conf));
	ports->port_bitmap = bm_init();
	parse_ports(def, ports);
	for (uint32_t i = 0; i < ports->port_count && i <= 0xFFFF; i++) {
		if (!bm_check(ports->port_bitmap, ports->ports[i])) {
			abort();
		}
	}
	free(ports->port_bitmap);
	free(ports);
	free(def);
	return 0;
}
