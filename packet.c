// packet.c

#include "features.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <alloca.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

#include "packet.h"
#include "log.h"

// MUST FREE return
char *asprint_icmphdr (
		const struct sockaddr *addr, ssize_t length, struct icmphdr hdr
) {
	const char *icmp_version;
	switch (addr->sa_family) {
	case AF_INET:
		icmp_version = "ICMP";
		break;
	case AF_INET6:
		icmp_version = "ICMPv6";
		break;
	default:
		panicf("Unknown address family: %d?", (int)addr->sa_family);
	}

	char *addr_str = packet_format_address(addr);
	if (!addr_str)
		fatalf("Failed to format socket address: %s", strerror(errno));

	// MUST FREE icmphdr_checksum_info_str
	char *icmphdr_checksum_info_str = NULL;
	if (addr->sa_family == AF_INET) // The kernel handles ICMPv6 checksuming.
		if (0 > asprintf(&icmphdr_checksum_info_str,
				"\tChecksum: %hu (BE)\n", (unsigned short)ntohs(hdr.checksum)))
			panics("Failed to allocate ICMP header checksum info string");

	char *icmphdr_info_str;
	int written_bytes = asprintf(&icmphdr_info_str,
			"\tAddress: %s\n" // addr_str
			"\tLength: %zd\n" // length
			"\t%s Type: %hhu\n" // icmp_version, hdr.type
			"\t%s Code: %hhu\n" // icmp_version, hdr.code
			"%s" // icmphdr_checksum_info_str
			"\tID: %hu\n" // hdr.icmp_echo_id
			"\tSequence Number: %hu", // hdr.icmp_echo_seq
			addr_str,
			length,
			icmp_version, (unsigned char)hdr.type,
			icmp_version, (unsigned char)hdr.code,
			icmphdr_checksum_info_str ? icmphdr_checksum_info_str : "",
			(unsigned short)ntohs(hdr.icmp_echo_id),
			(unsigned short)ntohs(hdr.icmp_echo_seq)
	);
	if (0 > written_bytes)
		panics("Failed to allocate ICMP header connection info string.");

	free(icmphdr_checksum_info_str);

	return icmphdr_info_str;
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

void packet_icmp6hdr_compat (
		const struct icmp6_hdr *hdr6, struct icmphdr *hdr_compat_out
) {
	struct icmphdr hdr_compat;
	bzero(&hdr_compat, sizeof(struct icmphdr));

	// Only need to implement compatibility echo request/reply.
	hdr_compat.type = hdr6->icmp6_type;
	hdr_compat.code = hdr6->icmp6_code;
	hdr_compat.checksum = 0; // ICMPv6 checksumming is handled by the kernel.
	hdr_compat.icmp_echo_id = hdr6->icmp6_id;
	hdr_compat.icmp_echo_seq = hdr6->icmp6_seq;

	*hdr_compat_out = hdr_compat;
}
