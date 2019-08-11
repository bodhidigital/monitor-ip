// packet.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <alloca.h>
#include <stdio.h>

#include "packet.h"

void print_icmphdr (
		const struct sockaddr *addr, ssize_t length, struct icmphdr hdr
) {
	const void *addr_data;
	size_t addr_str_s;
	const char *icmp_version;
	if (addr->sa_family == AF_INET) {
		// four octets as three decimal digits, three dots, null byte.
		addr_str_s = 4 * 3 + 3 + 1;  // 16
		addr_data = &((struct sockaddr_in *)addr)->sin_addr;
		icmp_version = "ICMP";
	} else {
		// eight octet-pairs as four hexadecimal digits, seven colons, null byte.
		addr_str_s = 8 * 4 + 7 + 1;  // 40
		addr_data = &((struct sockaddr_in6 *)addr)->sin6_addr;
		icmp_version = "ICMPv6";
	}

	char *addr_str;
	addr_str = (char *)alloca(addr_str_s);

	inet_ntop(addr->sa_family, addr_data, addr_str, addr_str_s);

	fprintf(stdout, "\tAddress: %s\n", addr_str);
	fprintf(stdout, "\tLength: %zd\n", length);
	fprintf(stdout, "\t%s Type: %hhu\n", icmp_version, (unsigned char)hdr.type);
	fprintf(stdout, "\t%s Code: %hhu\n", icmp_version, (unsigned char)hdr.code);
	if (addr->sa_family == AF_INET) // The kernel handles ICMPv6 checksuming.
		fprintf(stdout,
				"\tChecksum: %hu (BE)\n", (unsigned short)ntohs(hdr.checksum));
	fprintf(stdout, "\tID: %hu\n", (unsigned short)ntohs(hdr.icmp_echo_id));
	fprintf(stdout,
			"\tSequence Number: %hu\n", (unsigned short)ntohs(hdr.icmp_echo_seq));
}

void *get_ip4_payload (
		void *pkt, size_t len, uint8_t *protocol, size_t *payload_len
) {
	struct ip4_pkt *ip4_pkt = (struct ip4_pkt*)pkt;
	void *data;

	if (len < sizeof(struct iphdr)) {
		return NULL;
	}

	size_t pkt_tot_len = ntohs(ip4_pkt->hdr.tot_len);
	size_t pkt_hdr_len = 4 * ip4_pkt->hdr.ihl;
	if (pkt_tot_len < pkt_hdr_len) {
		return NULL;
	}

	size_t offset = pkt_hdr_len;

	*protocol = ip4_pkt->hdr.protocol;
	*payload_len = ((len >= pkt_tot_len) ? pkt_tot_len : len) - offset;
	data = (char *)pkt + offset;

	return data;
}

