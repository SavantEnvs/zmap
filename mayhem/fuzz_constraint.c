// libFuzzer harness for zmap's allow/blocklist radix tree (lib/constraint.c), the structure behind
// --allowlist-file/--blocklist-file. The input is a list of constraint_set() operations; the tree is
// then checked against a trivial model (last covering prefix wins).
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/constraint.h"

#define MAX_OPS 48

struct op {
	uint32_t prefix;
	int len;
	value_t value;
};

static int covers(const struct op *o, uint32_t addr)
{
	return o->len == 0 || ((addr ^ o->prefix) >> (32 - o->len)) == 0;
}

static value_t model(const struct op *ops, int n, value_t initial, uint32_t addr)
{
	value_t v = initial;
	for (int i = 0; i < n; i++) {
		if (covers(&ops[i], addr)) {
			v = ops[i].value;
		}
	}
	return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// byte 0: initial value (bit 0) and whether to paint + index-lookup (bit 1); then 6-byte ops
	if (size < 1 + 6) {
		return -1;
	}
	value_t initial = data[0] & 1;
	int paint = (data[0] >> 1) & 1;
	int n = (int)((size - 1) / 6 > MAX_OPS ? MAX_OPS : (size - 1) / 6);
	struct op ops[MAX_OPS];
	constraint_t *con = constraint_init(initial);
	for (int i = 0; i < n; i++) {
		const uint8_t *p = data + 1 + 6 * i;
		ops[i].prefix = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
		ops[i].len = p[4] % 33;
		ops[i].value = p[5] & 1;
		constraint_set(con, ops[i].prefix, ops[i].len, ops[i].value);
	}
	for (int i = 0; i < n; i++) {
		uint32_t base = ops[i].prefix;
		uint32_t last = ops[i].len == 0 ? 0xFFFFFFFFu : ops[i].len == 32 ? base : base | (0xFFFFFFFFu >> ops[i].len);
		uint32_t probes[] = {base, last, base - 1, last + 1};
		for (int k = 0; k < 4; k++) {
			if (constraint_lookup_ip(con, probes[k]) != model(ops, n, initial, probes[k])) {
				abort();
			}
		}
	}
	if (constraint_count_ips(con, 0) + constraint_count_ips(con, 1) != (1ULL << 32)) {
		abort();
	}
	if (paint) {
		uint64_t count = constraint_count_ips(con, 1);
		if (count > 0) {
			uint32_t seed = (uint32_t)data[size - 1] * 2654435761u;
			uint64_t index = seed % count;
			uint32_t ip = constraint_lookup_index(con, index, 1);
			if (constraint_lookup_ip(con, ip) != 1) {
				abort();
			}
		}
	}
	constraint_free(con);
	return 0;
}
