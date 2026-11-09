// libFuzzer harness for zmap's receive path: a probe module's validate_packet() and, when the
// response is accepted, process_packet() plus the fieldset it fills. The probe-response modules are
// the code zmap runs on attacker-controlled packets from the Internet.
//
// Input: byte 0 selects a module of the compiled-in family (bits 0-6) and, for the ICMP families,
// whether the validation is made to match as recv.c would compute it (bit 7 clear) or left as given (bit 7 set);
// bytes 1..16 are the 128-bit validation value (handle_packet derives it from a per-run AES key, so
// a fuzzer could never satisfy it), the rest is the IPv4 packet exactly as recv.c hands it to the
// module.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../lib/includes.h"
#include "../lib/blocklist.h"
#include "../lib/pbm.h"
#include "../src/state.h"
#include "../src/fieldset.h"
#include "../src/ports.h"
#include "../src/validate.h"
#include "../src/probe_modules/probe_modules.h"

#if defined(FAMILY_TCP)
#define NMODS 2
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"tcp_synscan", "ja4ts,ja4t"},
    {"tcp_synackscan", NULL},
};
#elif defined(FAMILY_UDP)
#define NMODS 3
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"udp", "text:hello"},
    {"bacnet", NULL},
    {"ipip", NULL},
};
#elif defined(FAMILY_DNS)
#define NMODS 1
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"dns", "A,example.com"},
};
#elif defined(FAMILY_NTP_UPNP)
#define NMODS 2
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"ntp", "text:x"},
    {"upnp", NULL},
};
#elif defined(FAMILY_ICMP)
#define NMODS 1
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"icmp_echoscan", NULL},
};
#elif defined(FAMILY_ICMP_TIME)
#define NMODS 1
static const struct {
	const char *name;
	const char *args;
} mods[NMODS] = {
    {"icmp_echo_time", NULL},
};
#else
#error "define FAMILY_TCP, FAMILY_UDP, FAMILY_DNS, FAMILY_NTP_UPNP, FAMILY_ICMP or FAMILY_ICMP_TIME"
#endif

#if defined(FAMILY_ICMP) || defined(FAMILY_ICMP_TIME)
// recv.c derives the validation words from the per-run AES key, which no fuzzer can reproduce, and
// the modules then compare the ICMP id/seq to them. Mirror what zmap itself does when it builds and
// receives a probe: compute the words the same way and store the id/seq they imply where the module
// reads them, so every classification branch is reachable. Offsets mirror the modules'; anything
// that doesn't fit is left untouched.
//  - Reply-type messages (icmp_echoscan: type 0; icmp_echo_time: everything but unreach/time
//    exceeded): validation = validate_gen(outer dst, outer src) as in recv.c, id/seq in the outer
//    ICMP header.
//  - Error messages: the module regenerates the words itself with validate_gen(outer dst, inner dst)
//    and compares the id/seq of the quoted inner ICMP header, so only that header is filled in.
static int icmp_is_error(u_char type)
{
#if defined(FAMILY_ICMP_TIME)
	return type == 3 || type == 11; // ICMP_UNREACH, ICMP_TIMXCEED
#else
	return type != 0;
#endif
}

static void icmp_fix_id_seq(u_char *ip_buf, size_t ip_len, uint32_t *validation)
{
	struct ip *outer = (struct ip *)ip_buf;
	size_t outer_len = 4 * (size_t)outer->ip_hl;
	if (outer->ip_p != IPPROTO_ICMP || outer_len + 8 > ip_len) {
		return;
	}
	u_char type = ip_buf[outer_len];
	uint32_t v[VALIDATE_BYTES / sizeof(uint32_t)];
	size_t at;
	if (!icmp_is_error(type)) {
		validate_gen(outer->ip_dst.s_addr, outer->ip_src.s_addr, 0, (uint8_t *)v);
		memcpy(validation, v, sizeof(v));
		at = outer_len;
	} else {
		if (outer_len + 8 + sizeof(struct ip) > ip_len) {
			return;
		}
		struct ip *inner = (struct ip *)(ip_buf + outer_len + 8);
#if defined(FAMILY_ICMP_TIME)
		at = outer_len + 8 + outer_len; // module_icmp_echo_time.c indexes with the outer ip_hl
#else
		at = outer_len + 8 + 4 * (size_t)inner->ip_hl;
#endif
		if (at + 8 > ip_len) {
			return;
		}
		validate_gen(outer->ip_dst.s_addr, inner->ip_dst.s_addr, 0, (uint8_t *)v);
	}
	uint16_t id = v[1] & 0xFFFF, seq = v[2] & 0xFFFF;
	memcpy(ip_buf + at + 4, &id, sizeof(id));
	memcpy(ip_buf + at + 6, &seq, sizeof(seq));
}
#endif

static probe_module_t *module[NMODS];
static fielddefset_t fds[NMODS];
static int success_index[NMODS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	zconf.source_port_first = 32768;
	zconf.source_port_last = 32768;
	zconf.probes_per_target = 1;
	zconf.validate_source_port_override = VALIDATE_SRC_PORT_UNSET_OVERRIDE;
	zconf.ports = calloc(1, sizeof(struct port_conf));
	zconf.ports->port_bitmap = bm_init();
	parse_ports(strdup("1-1024,1900,5353,47808"), zconf.ports);
	if (blocklist_init(NULL, NULL, NULL, 0, NULL, 0, 0)) {
		abort();
	}
	validate_init();
	for (int i = 0; i < NMODS; i++) {
		module[i] = get_probe_module_by_name(mods[i].name);
		if (!module[i]) {
			abort();
		}
		zconf.probe_module = module[i];
		zconf.probe_args = mods[i].args ? strdup(mods[i].args) : NULL;
		if (module[i]->global_initialize &&
		    module[i]->global_initialize(&zconf)) {
			abort();
		}
		gen_fielddef_set(&fds[i], ip_fields, ip_fields_len);
		gen_fielddef_set(&fds[i], module[i]->fields, module[i]->numfields);
		gen_fielddef_set(&fds[i], sys_fields, sys_fields_len);
		success_index[i] = fds_get_index_by_name(&fds[i], "success");
		if (success_index[i] < 0) {
			abort();
		}
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const size_t hdr = 1 + VALIDATE_BYTES;
	if (size < hdr + sizeof(struct ip)) {
		return -1;
	}
	int m = (data[0] & 0x7f) % NMODS;
	uint32_t validation[VALIDATE_BYTES / sizeof(uint32_t)];
	memcpy(validation, data + 1, sizeof(validation));
	size_t ip_len = size - hdr;

	u_char *frame = malloc(sizeof(struct ether_header) + ip_len);
	if (!frame) {
		return -1;
	}
	memset(frame, 0, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), data + hdr, ip_len);
	struct ip *ip_hdr = (struct ip *)(frame + sizeof(struct ether_header));
#if defined(FAMILY_ICMP) || defined(FAMILY_ICMP_TIME)
	if (!(data[0] & 0x80)) {
		icmp_fix_id_seq((u_char *)ip_hdr, ip_len, validation);
	}
#endif
	uint32_t src_ip = ip_hdr->ip_src.s_addr;

	zconf.probe_module = module[m];
	if (module[m]->validate_packet(ip_hdr, ip_len, &src_ip, validation,
				       zconf.ports)) {
		struct timespec ts = {.tv_sec = 1700000000, .tv_nsec = 123456789};
		fieldset_t *fs = fs_new_fieldset(&fds[m]);
		fs_add_ip_fields(fs, ip_hdr);
		module[m]->process_packet(frame, sizeof(struct ether_header) + ip_len,
					  fs, validation, ts);
		fs_add_system_fields(fs, 0, 0, ts);
		(void)fs_get_uint64_by_index(fs, success_index[m]);
		fs_free(fs);
	}
	free(frame);
	return 0;
}
