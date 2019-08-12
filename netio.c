// netio.c

#include "features.h"

#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <glib.h>

#include "record.h"
#include "timeutil.h"
#include "checksum.h"
#include "packet.h"
#include "netio.h"

static struct ping_record_entry netio_send_v4 (
		struct netio_params, int, const struct sockaddr_in, uint16_t);
static struct ping_record_entry netio_send_v6 (
		struct netio_params, int, const struct sockaddr_in6, uint16_t);
static bool netio_select_noblock (int);
static bool netio_select_block (int, struct timespec);
static size_t netio_recvfrom (
		int, void *, size_t, socklen_t, struct sockaddr *);
static bool netio_timeout_remaining (struct timespec, struct timespec *);
static size_t netio_get_payload (
		sa_family_t, size_t, void *, void **, uint8_t *);
__attribute__((always_inline))
static inline size_t netio_get_generic_sockaddr (
		sa_family_t, struct sockaddr **);
static uint8_t netio_expected_protocol (sa_family_t);
static uint8_t netio_echo_reply_icmp_type (sa_family_t);
static bool netio_get_icmp_compat (int, size_t, const void *, struct icmphdr *);

void netio_send (
		const struct netio_params *params, int ping_sockfd,
		const struct sockaddr *ping_addr, uint16_t sequence,
		struct ping_record_entry *entry_data_out
) {
	if (ping_addr->sa_family == AF_INET) {
		*entry_data_out = netio_send_v4(
				*params, ping_sockfd, *(struct sockaddr_in *)ping_addr, sequence);
	} else {
		*entry_data_out = netio_send_v6(
				*params, ping_sockfd, *(struct sockaddr_in6 *)ping_addr, sequence);
	}
}

// TODO: Pass desired end timestamp.
// pongs_out must be freed !
size_t netio_receive (
		struct netio_params *params, int ping_sockfd,
		const struct sockaddr *ping_addr, const struct timespec *time_end,
		struct netio_pong **pongs_out
) {
	GArray *received_pongs = g_array_new(false, false, sizeof(struct netio_pong));

	bool first_select_iter = true;

	struct timespec time_recv;
	clock_gettime(CLOCK_MONOTONIC, &time_recv);
	do {
		// Get the next timeout that would end just after time_end.
		struct timespec timeout;
		if (!netio_timeout_remaining(*time_end, &timeout)) {
			break;
		}

		if (first_select_iter)
			first_select_iter = false;
		else
			fprintf(stdout,
					"Continuing select loop, remaining time %.03fs\n",
					timespec2double(&timeout));

		// If we know a datagram is already available, no need to select again.
		if (!netio_select_noblock(ping_sockfd)) {
			if (!netio_select_block(ping_sockfd, timeout)) {
				fprintf(stdout, "No more pongs available within timeframe.\n");
				break;
			}

			// If a datagram was NOT available, then select returned just after it was
			// received.  Otherwise, it may have been available for as long as select has
			// not blocked.
			clock_gettime(CLOCK_MONOTONIC, &time_recv);
		}

		struct sockaddr *pong_addr;
		socklen_t pong_addr_s = netio_get_generic_sockaddr(
				ping_addr->sa_family, &pong_addr);

		// TODO: better packet size, either just pick the header, or peak to determine
		// packet size.
		size_t pkt_s = (1 << 16) - 1;
		void *pkt = alloca(pkt_s);

		// Receive the next packet.
		size_t recv_bytes = netio_recvfrom(
				ping_sockfd, pkt, pkt_s, pong_addr_s, pong_addr);

		// Get the payload address.
		void *pkt_payload;
		uint8_t pkt_protocol;
		size_t pkt_payload_len = netio_get_payload (
				pong_addr->sa_family, recv_bytes, pkt, &pkt_payload, &pkt_protocol);

		// Should only be NULL if get_ip4_payload fails to parse the IPv4 header.
		if (pkt_payload == NULL) {
			fprintf(stderr, "Received invalid IP(v6) packet!\n");
			continue;
		}

		// Expected packet protocol is dependant on address family.
		uint8_t pkt_protocol_expected = netio_expected_protocol(pong_addr->sa_family);

		// Should really never happen, the socket is set for just ICMP(v6).
		if (pkt_protocol_expected != pkt_protocol) {
			fprintf(stdout,
					"Recieved IP packet, not ICMP(v6): protocol %hhu, payload_length %zu.\n",
					pkt_protocol, pkt_payload_len);
			continue;
		}

		// Convert to IPv4 ICMP echo(-reply) header.
		struct icmphdr icmphdr_compat;
		if (!netio_get_icmp_compat(
					pong_addr->sa_family, pkt_payload_len, pkt_payload, &icmphdr_compat)) {
			fprintf(stderr, "Recieved truncated ICMP packet.\n");
			continue;
		}

		// This will happen all the time, especially for v6.
		// TODO: check for related ICMP messages (unreach, ttl exceeded, etc.).
		if (icmphdr_compat.type != netio_echo_reply_icmp_type(pong_addr->sa_family)) {
			fprintf(stdout,
					"Recieved ICMP(v6) packet, not echo reply: type %hhu, code %hhu.\n",
					icmphdr_compat.type, icmphdr_compat.code);
			continue;
		}

		// Only consider ICMP echo-reply packets with a matching ID.
		if (ntohs(icmphdr_compat.icmp_echo_id) != params->id) {
			fprintf(stdout,
					"Recieved echo reply packet, wrong id: id %hu.\n",
					ntohs(icmphdr_compat.icmp_echo_id));
			continue;
		}

		// TODO: check source IP matches.

		// Print the recieved packet.
		fprintf(stdout, "Recieved packet:\n");
		print_icmphdr(pong_addr, recv_bytes, icmphdr_compat);

		// Save the pong received.
		struct netio_pong netio_pong = {
			.seq = ntohs(icmphdr_compat.icmp_echo_seq),
			.time_recv = time_recv
		};
		received_pongs = g_array_append_val(received_pongs, netio_pong);
	} while (1);

	// Convert to array of pongs.
	size_t pongs_len = received_pongs->len;
	size_t pongs_s = pongs_len * sizeof(struct netio_pong);
	struct netio_pong *pongs = malloc(pongs_s);
	memcpy(pongs, received_pongs->data, pongs_s);

	g_array_free(received_pongs, true);

	*pongs_out = pongs;
	return pongs_len;
}

static struct ping_record_entry netio_send_v4 (
		struct netio_params params, int ping_sockfd,
		const struct sockaddr_in ping_addr, uint16_t sequence
) {
	size_t icmp_pkt_s = sizeof(struct icmphdr) + params.msg_s;
	void *icmp_pkt = alloca(icmp_pkt_s);
	struct icmphdr *icmphdr = (struct icmphdr *)icmp_pkt;

	bzero(icmp_pkt, sizeof(icmp_pkt));

	icmphdr->type = ICMP_ECHO;
	icmphdr->icmp_echo_id = htons(params.id);

	icmphdr->icmp_echo_seq = htons(sequence);
	icmphdr->checksum = checksum16_1s_complement(icmp_pkt, sizeof(icmp_pkt));

	// Send packet
	ssize_t bytes_sent = sendto(
			ping_sockfd, icmp_pkt, sizeof(icmp_pkt), 0, &ping_addr,
			sizeof(struct sockaddr_in));
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	// Immediately after send.
	struct timespec time_sent;
	clock_gettime(CLOCK_MONOTONIC, &time_sent);

	fprintf(stdout, "Sent packet:\n");
	print_icmphdr((const struct sockaddr *)&ping_addr, sizeof(icmp_pkt), *icmphdr);

	return (struct ping_record_entry){
		.sequence = sequence,
		.time_sent = time_sent,
		.pong_cnt = 0
	};
}

static struct ping_record_entry netio_send_v6 (
		struct netio_params params, int ping_sockfd,
		const struct sockaddr_in6 ping_addr, uint16_t sequence
) {
	size_t icmp6_pkt_s = sizeof(struct icmp6_hdr) + params.msg_s;
	void *icmp6_pkt = alloca(icmp6_pkt_s);
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)icmp6_pkt;

	bzero(icmp6_pkt, icmp6_pkt_s);

	icmp6_hdr->icmp6_id = htons(params.id);
	icmp6_hdr->icmp6_seq = htons(sequence);
	icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_hdr->icmp6_code = 0;

	// Send packet.
	ssize_t bytes_sent = sendto(
			ping_sockfd, icmp6_pkt, icmp6_pkt_s, 0, &ping_addr,
			sizeof(struct sockaddr_in6));
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	// Immediately after send.
	struct timespec time_sent;
	clock_gettime(CLOCK_MONOTONIC, &time_sent);

	fprintf(stdout, "Sent packet:\n");

	struct icmphdr icmphdr_compat;

	// Only need to implement compatibility echo request/reply.
	icmphdr_compat.type = icmp6_hdr->icmp6_type;
	icmphdr_compat.code = icmp6_hdr->icmp6_code;
	icmphdr_compat.checksum = 0;  // ICMPv6 checksumming is handled by the kernel.
	icmphdr_compat.icmp_echo_id = icmp6_hdr->icmp6_id;
	icmphdr_compat.icmp_echo_seq = icmp6_hdr->icmp6_seq;

	print_icmphdr((const struct sockaddr *)&ping_addr, icmp6_pkt_s, icmphdr_compat);

	return (struct ping_record_entry){
		.sequence = sequence,
		.time_sent = time_sent,
		.pong_cnt = 0
	};
}

static bool netio_select_noblock (int ping_sockfd) {
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(ping_sockfd, &read_fds);

	// Timeout of zero.
	struct timeval timeout_val = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	int select_avail = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout_val);
	if (0 > select_avail) {
		fprintf(stderr, "Error polling ICMP socket: %s\n", strerror(errno));
		exit(1);
	}

	if (FD_ISSET(ping_sockfd, &read_fds)) {
		return true;
	} else {
		return false;
	}
}

static bool netio_select_block (int ping_sockfd, struct timespec timeout) {
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(ping_sockfd, &read_fds);

	struct timeval timeout_val;
	timespec2val(&timeout, &timeout_val);

	// Block until packet is available or timeout reached.
	int select_avail = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout_val);
	if (0 > select_avail) {
		fprintf(stderr, "Error polling ICMP socket: %s\n", strerror(errno));
		exit(1);
	}

	// Check if a packet was available within the timeout.
	if (FD_ISSET(ping_sockfd, &read_fds)) {
		return true;
	} else {
		return false;
	}
}

static size_t netio_recvfrom (
		int fd, void *pkt, size_t pkt_s, socklen_t addr_s,
		struct sockaddr *addr_out
) {
	ssize_t recv_bytes = recvfrom(
			fd, pkt, pkt_s, 0, addr_out, &addr_s);
	if (0 == recv_bytes) {
		// This shouldn't happen, we should never receive a zero-length packet.
		fprintf(stderr, "Error receiving ICMP packet: %s\n", "Unknown");
		exit(1);
	} else if (0 > recv_bytes) {
		fprintf(stderr, "Error receiving ICMP packet: %s\n", strerror(errno));
		exit(1);
	}

	return (size_t)recv_bytes;
}

static size_t netio_get_payload (
		sa_family_t af, size_t recv_bytes, void *pkt, void **payload_out,
		uint8_t *protocol_out
) {
	void *payload;
	uint8_t protocol;
	size_t payload_len;
	if (af == AF_INET) {
		// Remove IPv4 header and get the pointer to just the payload.
		payload = get_ip4_payload(
				pkt, recv_bytes, &protocol, &payload_len);
	} else {
		// The IP header appears to be stripped for v6 but not v4.
		payload = pkt;
		protocol = IPPROTO_ICMPV6;
		payload_len = recv_bytes;
	}

	*payload_out = payload;
	*protocol_out = protocol;
	return payload_len;
}

static bool netio_timeout_remaining (
		struct timespec time_end, struct timespec *timeout_out
) {
	struct timespec time_now;
	clock_gettime(CLOCK_MONOTONIC, &time_now);

	// time_remaining = time_end - time_now
	struct timespec timeout;
	timespec_diff(&time_now, &time_end, &timeout);

	// timeout > 0
	struct timespec time_zero = {
		.tv_sec = 0,
		.tv_nsec = 0
	};
	if (0 < cmp_timespec(&time_zero, &timeout)) {
		return false;
	}

	*timeout_out  = timeout;
	return true;
}

// Don't free addr_out, only valid withing caller scope.
__attribute__((always_inline))
static inline size_t netio_get_generic_sockaddr (
		sa_family_t af, struct sockaddr **addr_out
) {
	struct sockaddr *addr;
	size_t addr_s;

	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	if (af == AF_INET) {
		addr = (struct sockaddr *)&addr4;
		addr_s = sizeof(struct sockaddr_in);
	} else {
		addr = (struct sockaddr *)&addr6;
		addr_s = sizeof(struct sockaddr_in6);
	}

	*addr_out = addr;
	return addr_s;
}

static uint8_t netio_expected_protocol (sa_family_t af) {
	if (af == AF_INET)
		return IPPROTO_ICMP;
	else
		return IPPROTO_ICMPV6;
}

static uint8_t netio_echo_reply_icmp_type (sa_family_t af) {
	if (af == AF_INET)
		return ICMP_ECHOREPLY;
	else
		return ICMP6_ECHO_REPLY;
}

static bool netio_get_icmp_compat (
		int af, size_t payload_len, const void *payload,
		struct icmphdr *icmphdr_compat_out
) {
	struct icmphdr icmphdr_compat;
	if (af == AF_INET) {
		// Should never happen, given the large packet size.
		if (payload_len < sizeof(struct icmphdr)) {
			return false;
		}

		icmphdr_compat = *(struct icmphdr *)payload;
	} else {
		// Should only happen if extension headers are HUGE.
		// Probably not even possible.
		if (payload_len < sizeof(struct icmp6_hdr)) {
			return false;
		}

		packet_icmp6hdr_compat((struct icmp6_hdr *)payload, &icmphdr_compat);
	}

	*icmphdr_compat_out = icmphdr_compat;
	return true;
}
