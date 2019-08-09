// main.c

#define _POSIX_C_SOURCE (199309L)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <glib.h>
#include <gmodule.h>

#define PING_PKT_S (64)
#define PING_MSG_S (PING_PKT_S - sizeof(struct icmphdr))
#define PING_PORT (0)
#define PING_SLEEP_US (1 * 1000 * 1000)
#define PING_RECV_TIMEOUT_US (1 * 1000 * 1000)
#define PING_TTL (64)

// ping packet structure
struct ping_pkt {
	struct icmphdr hdr;
	char msg[PING_PKT_S];
} __attribute__((packed));

struct ip_pkt {
	unsigned int version:4;
	int _pad:4;
	char remaining[0];
} __attribute__((packed));

struct ip4_pkt {
	struct iphdr hdr;
	char options_and_data[0];
} __attribute__((packed));

//struct ip6_pkt {
//	struct ip6_hdr hdr;
//	char extensions_and_data[0];
//} __attribute__((packed));

//struct ip6_hopopts {
//	struct ip6_hbh hdr;
//	struct ip6_opt opts[0];
//} __attribute__((packed));

//struct icmp6_pseudo_header {
//	uint8_t src[16];
//	uint8_t dst[16];
//	uint32_t len;
//	uint32_t _zero_pad:24;
//	uint8_t nxt;
//} __attribute__((packed));

static uint16_t ping_id;
static GList *sent_ping_list;

__attribute__((constructor))
static void set_ping_id () {
	uint32_t pid = getpid();
	ping_id = (pid >> 16) ^ (pid & 0xffff);
}

//__attribute__((pure))
//static struct timespec timeval2spec (struct timeval t) {
//	return (struct timespec){
//		.tv_sec = t.tv_sec,
//		.tv_nsec = 1000 * t.tv_usec
//	};
//}

__attribute__((pure))
static struct timeval timespec2val (struct timespec t) {
	return (struct timeval){
		.tv_sec = t.tv_sec,
		.tv_usec = t.tv_nsec / 1000
	};
}

//__attribute__((pure))
//static suseconds_t timespec2useconds (struct timespec t) {
//	return (1000 * 1000) * t.tv_sec + t.tv_nsec / 1000;
//}

__attribute__((pure))
static struct timespec useconds2timespec (suseconds_t us) {
	return (struct timespec){
		.tv_sec = us / (1000 * 1000),
		.tv_nsec = 1000 * (us % (1000 * 1000))
	};
}

__attribute__((pure))
static double timespec2double (struct timespec t) {
	return (double)t.tv_sec + (double)t.tv_nsec / (1000.0 * 1000.0 * 1000.0);
}

__attribute__((pure))
static struct timespec diff_timespec (
		struct timespec start, struct timespec end
) {
		struct timespec diff;
		diff.tv_sec = end.tv_sec - start.tv_sec;
		if (end.tv_nsec < start.tv_nsec) {
			diff.tv_sec -= 1;
			diff.tv_nsec = (1000 * 1000 * 1000) + end.tv_nsec - start.tv_nsec;
		} else {
			diff.tv_nsec = end.tv_nsec - start.tv_nsec;
		}

		return diff;
}

__attribute__((pure))
static int cmp_timespec (struct timespec a, struct timespec b) {
	if (a.tv_sec > b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_nsec > b.tv_nsec)) {
		return 1;
	} else if (a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec) {
		return 0;
	} else {
		return -1;
	}
}

// Calculating the Check Sum
static uint16_t checksum (const void *b, uint16_t len) {
	uint16_t *buf = (uint16_t *)b;

	uint32_t sum;
	for (sum = 0; 1 < len; len -= sizeof(uint16_t))
		sum += *buf++;

	if (len-- == 1)
		sum += *(uint8_t*)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	uint16_t result = (uint16_t)~sum;
	return result;
}

static void print_icmp_packet (
		const struct sockaddr *addr, ssize_t length, struct icmphdr hdr
) {
	const void *addr_data;
	size_t addr_str_s;
	const char *icmp_version;
	if (addr->sa_family == AF_INET) {
		addr_str_s = 16;
		addr_data = &((struct sockaddr_in *)addr)->sin_addr;
		icmp_version = "ICMP";
	} else {
		addr_str_s = 40;
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
	if (addr->sa_family == AF_INET) { // The kernel handles ICMPv6 checksuming.
		fprintf(stdout, "\tChecksum: %hu\n", (unsigned short)ntohs(hdr.checksum));
	}
	fprintf(stdout, "\tID: %hu\n", (unsigned short)ntohs(hdr.un.echo.id));
	fprintf(stdout, "\tSequence Number: %hu\n", (unsigned short)ntohs(hdr.un.echo.sequence));
}

struct sent_ping {
	uint16_t sequence;
	struct timespec time_sent;
	unsigned short received_pong;
};

void sent_ping_list_destroy_notify(gpointer data) {
	free(data);
}

gint sent_ping_compare_to_sequence(gconstpointer sent_ping_p, gconstpointer sequence_p) {
	const struct sent_ping *sent_ping = sent_ping_p;
	const uint16_t *sequence = sequence_p;

	if (!sent_ping)
		return -1;

	if (sent_ping->sequence < *sequence)
		return -1;
	else if (sent_ping->sequence == *sequence)
		return 0;
	else
		return 1;
}

static void init_ping_record() {
	sent_ping_list = g_list_alloc();
	if (!sent_ping_list) {
		fprintf(stderr, "Failed to allocate ping record!\n");
		exit(1);
	}
}

static void fini_ping_record() {
	g_list_free_full(sent_ping_list, sent_ping_list_destroy_notify);
}

void save_ping(struct sent_ping sent_ping_src) {
	struct sent_ping *sent_ping_data = malloc(sizeof(struct sent_ping));
	if (!sent_ping_data) {
		fprintf(stderr, "Failed to allocate ping record entry!\n");
		exit(1);
	}
	*sent_ping_data = sent_ping_src;

	sent_ping_list = g_list_append(sent_ping_list, sent_ping_data);
}

// current number of received pings, or 0 if no matching pong exists.
unsigned short update_pong_received(uint16_t sequence) {
	GList *matching_ping = g_list_find_custom(sent_ping_list, &sequence, sent_ping_compare_to_sequence);
	if (!matching_ping)
		return 0;

	struct sent_ping *sent_ping = matching_ping->data;
	sent_ping->received_pong += 1;

	return sent_ping->received_pong;
}

// t should be created *before* the last receive_pong call.
void cleanup_ping_record(struct timespec t) {
	struct timespec timeout = useconds2timespec(PING_RECV_TIMEOUT_US);
	for (GList *node = sent_ping_list->next; node != NULL; node = g_list_next(node)) {
		struct sent_ping *sent_ping = (struct sent_ping *)node->data;

		// t - sent_ping->time_sent
		struct timespec time_elapsed = diff_timespec(sent_ping->time_sent, t);
		// time_elapsed >= t
		if (-1 < cmp_timespec(time_elapsed, timeout)) {
			if (!sent_ping->received_pong)
				fprintf(stdout,
						"No pong received after %.03fs for ping with sequence number %hu.\n",
						timespec2double(timeout), sent_ping->sequence);

			sent_ping_list = g_list_remove_link(sent_ping_list, node);
			sent_ping_list_destroy_notify(sent_ping_list->data);
			g_list_free_1(node);
		} else {
			// Using CLOCK_MONOTONIC, ping sequences will always have time in order.
			// Thus after we've found the first ping that has yet to expire ...
			return;
		}
	}
}

static void *get_ip4_payload (
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

//static void *get_ip6_payload (
//		void *pkt, size_t len, uint8_t *protocol, size_t *payload_len
//) {
//	struct ip6_pkt *ip6_pkt = (struct ip6_pkt*)pkt;
//	void *data;
//
//	size_t offset = sizeof(struct ip6_hdr);
//	if (len < offset) {
//		return NULL;
//	}
//
//	size_t pkt_tot_len = ntohs(ip6_pkt->hdr.ip6_plen);
//	uint8_t nxt = ip6_pkt->hdr.ip6_nxt;
//	if (nxt == IPPROTO_HOPOPTS ||
//			nxt == IPPROTO_ROUTING ||
//			nxt == IPPROTO_FRAGMENT ||
//			nxt == IPPROTO_DSTOPTS ||
//			nxt == IPPROTO_MH) {
//		if (len < offset + sizeof(struct ip6_ext)) {
//			return NULL;
//		}
//
//		struct ip6_ext *ip6_ext = (struct ip6_ext *)((char *)ip6_pkt + 40);
//		if (nxt == IPPROTO_HOPOPTS) {
//			if (len < offset + ip6_ext->ip6e_len + 8) {
//				return NULL;
//			}
//
//			struct ip6_hopopts *ip6_hopopts = (struct ip6_hopopts *)ip6_ext;
//			struct ip6_opt *ip6_opt;
//			for (size_t i = 0;
//					ip6_hopopts->hdr.ip6h_len + 8 > i + sizeof(struct ip6_opt);
//					i += sizeof(struct ip6_opt) + ip6_opt->ip6o_len) {
//				ip6_opt = (struct ip6_opt *)((char *)&ip6_hopopts->opts[0] + i);
//				if (ip6_opt->ip6o_type == IP6OPT_JUMBO) {
//					if (ip6_opt->ip6o_len + 8 < sizeof(struct ip6_opt_jumbo)) {
//						return NULL;
//					}
//
//					struct ip6_opt_jumbo *ip6_opt_jumbo = (struct ip6_opt_jumbo *)ip6_opt;
//					pkt_tot_len = ntohl(*(uint32_t *)&ip6_opt_jumbo->ip6oj_jumbo_len);
//				}
//			}
//
//			offset += ip6_ext->ip6e_len + 8;
//			ip6_ext = (struct ip6_ext *)((char *)ip6_ext + ip6_ext->ip6e_len + 8);
//		}
//
//		nxt = ip6_ext->ip6e_nxt;
//		while (nxt == IPPROTO_ROUTING ||
//				nxt == IPPROTO_FRAGMENT ||
//				nxt == IPPROTO_DSTOPTS ||
//				nxt == IPPROTO_MH) {
//			if (len < offset + ip6_ext->ip6e_len + 8) {
//				return NULL;
//			}
//
//			offset += ip6_ext->ip6e_len + 8;
//			ip6_ext = (struct ip6_ext *)((char *)ip6_ext + ip6_ext->ip6e_len + 8);
//			nxt = ip6_ext->ip6e_nxt;
//		}
//	}
//
//	*protocol = nxt;
//	*payload_len = (len >= pkt_tot_len) ? pkt_tot_len - offset : len;
//	data = (char *)pkt + offset;
//
//	return data;
//}

// make a ping request
static struct sent_ping send_ping_v4 (
		uint16_t sequence, int ping_sockfd, struct sockaddr *ping_addr, size_t ping_addr_s
) {
	struct ping_pkt icmp_ping_pkt;

	//filling packet
	bzero(&icmp_ping_pkt, sizeof(icmp_ping_pkt));

	icmp_ping_pkt.hdr.type = ICMP_ECHO;
	icmp_ping_pkt.hdr.un.echo.id = htons(ping_id);

	int i;
	for (i = 0; i < (int)sizeof(icmp_ping_pkt.msg) - 1; i++)
		icmp_ping_pkt.msg[i] = '\0';

	icmp_ping_pkt.msg[i] = 0;
	icmp_ping_pkt.hdr.un.echo.sequence = htons(sequence);
	icmp_ping_pkt.hdr.checksum = checksum(&icmp_ping_pkt, sizeof(icmp_ping_pkt));

	struct timespec time_sent;
	clock_gettime(CLOCK_MONOTONIC, &time_sent);

	//send packet
	ssize_t bytes_sent = sendto(
			ping_sockfd, &icmp_ping_pkt, sizeof(icmp_ping_pkt), 0, ping_addr,
			ping_addr_s);
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stdout, "Sent packet:\n");
	print_icmp_packet(ping_addr, sizeof(icmp_ping_pkt), icmp_ping_pkt.hdr);

	return (struct sent_ping){
		.sequence = sequence,
		.time_sent = time_sent,
		.received_pong = 0
	};
}

static struct sent_ping send_ping_v6 (
		uint16_t sequence, int ping_sockfd, struct sockaddr *ping_addr,
		size_t ping_addr_s
) {
	size_t icmp6_pkt_s = sizeof(struct icmp6_hdr) + PING_MSG_S;
	void *icmp6_pkt = alloca(icmp6_pkt_s);
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)icmp6_pkt;

	//filling packet
	bzero(icmp6_pkt, icmp6_pkt_s);

	icmp6_hdr->icmp6_id = htons(ping_id);
	icmp6_hdr->icmp6_seq = htons(sequence);
	icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_hdr->icmp6_code = 0;

	//struct icmp6_pseudo_header pseudohdr;
	//memcpy(pseudohdr.src, ((struct sockaddr_in6 *)ping_addr)->sin6_addr.s6_addr, 16);
	//memcpy(pseudohdr.dst, ((struct sockaddr_in6 *)ping_addr)->sin6_addr.s6_addr, 16);
	//pseudohdr._zero_pad = 0;
	//pseudohdr.nxt = 58;
	//icmp6_hdr->icmp6_cksum = checksum(&pseudohdr, sizeof(pseudohdr));

	struct timespec time_sent;
	clock_gettime(CLOCK_MONOTONIC, &time_sent);

	//send packet
	ssize_t bytes_sent = sendto(
			ping_sockfd, icmp6_pkt, icmp6_pkt_s, 0, ping_addr, ping_addr_s);
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stdout, "Sent packet:\n");

	struct icmphdr icmphdr_compat;

	// Only need to implement compatibility echo request/reply.
	icmphdr_compat.type = icmp6_hdr->icmp6_type;
	icmphdr_compat.code = icmp6_hdr->icmp6_code;
	icmphdr_compat.checksum = icmp6_hdr->icmp6_cksum; // ICMPv6 contains no checksum.
	icmphdr_compat.un.echo.id = icmp6_hdr->icmp6_id;
	icmphdr_compat.un.echo.sequence = icmp6_hdr->icmp6_seq;

	print_icmp_packet(ping_addr, icmp6_pkt_s, icmphdr_compat);

	return (struct sent_ping){
		.sequence = sequence,
		.time_sent = time_sent,
		.received_pong = 0
	};
}

// TODO: pass desired end time
static void receive_pong (
		int ping_sockfd, struct sockaddr *ping_addr
) {
	struct sockaddr *pong_addr;
	socklen_t pong_addr_s;

	struct sockaddr_in pong_addr4;
	struct sockaddr_in6 pong_addr6;
	if (ping_addr->sa_family == AF_INET) {
		pong_addr = (struct sockaddr *)&pong_addr4;
		pong_addr_s = sizeof(struct sockaddr_in);
	} else {
		pong_addr = (struct sockaddr *)&pong_addr6;
		pong_addr_s = sizeof(struct sockaddr_in6);
	}

	bzero(pong_addr, pong_addr_s);

	struct timespec timeout;
	fd_set fds;

	timeout.tv_sec = PING_SLEEP_US / (1000 * 1000);
	timeout.tv_nsec = 1000 * (PING_SLEEP_US % (1000 * 1000));

	FD_ZERO(&fds);
	FD_SET(ping_sockfd, &fds);

	struct timespec time_start;
	clock_gettime(CLOCK_MONOTONIC, &time_start);

	do {
		fd_set read_fds = fds;
		struct timeval timeout_val = timespec2val(timeout);
		int select_avail = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout_val);
		if (0 > select_avail) {
			fprintf(stderr, "Error polling ICMP socket: %s\n", strerror(errno));
			exit(1);
		}

		if (!FD_ISSET(ping_sockfd, &read_fds)) {
			fprintf(stdout, "No pongs available within timeframe.\n");
			return;
		}

		size_t pkt_s = (1 << 16) - 1;
		void *pkt = alloca(pkt_s);
		ssize_t recv_bytes = recvfrom(
				ping_sockfd, pkt, pkt_s, 0, pong_addr, &pong_addr_s);
		if (0 == recv_bytes) {
			fprintf(stderr, "Error receiving ICMP packet: %s\n", "Unknown");
			exit(1);
		} else if (0 > recv_bytes) {
			fprintf(stderr, "Error receiving ICMP packet: %s\n", strerror(errno));
			exit(1);
		}

		void *pkt_payload;
		uint8_t pkt_protocol;
		size_t pkt_payload_len;
		if (ping_addr->sa_family == AF_INET) {
			pkt_payload = get_ip4_payload(
					pkt, recv_bytes, &pkt_protocol, &pkt_payload_len);
		} else {
			// The IP header appears to be stripped for v6 but not v4?
			//pkt_payload = get_ip6_payload(
			//		pkt, recv_bytes, &pkt_protocol, &pkt_payload_len);
			pkt_payload = pkt;
			pkt_protocol = IPPROTO_ICMPV6;
			pkt_payload_len = recv_bytes;
		}

		if (pkt_payload == NULL) {
			fprintf(stderr, "Received invalid IP(v6) packet!\n");
			continue;
		}

		uint8_t pkt_protocol_expected;
		if (ping_addr->sa_family == AF_INET) {
			pkt_protocol_expected = IPPROTO_ICMP;
		} else {
			pkt_protocol_expected = IPPROTO_ICMPV6;
		}

		if (pkt_protocol_expected != pkt_protocol) {
			fprintf(stdout,
					"Recieved IP packet, not ICMP: protocol %hhu, payload_length %zu.\n",
					pkt_protocol, pkt_payload_len);
			continue;
		}

		struct icmphdr icmphdr_compat;

		if (ping_addr->sa_family == AF_INET) {
			if (pkt_payload_len < sizeof(struct icmphdr)) {
				fprintf(stderr, "Recieved truncated ICMP packet.\n");
				continue;
			}

			struct icmphdr icmphdr_ip4;
			memcpy(&icmphdr_ip4, pkt_payload, sizeof(struct icmphdr));

			icmphdr_compat.type = icmphdr_ip4.type;
			icmphdr_compat.code = icmphdr_ip4.code;
			icmphdr_compat.checksum = icmphdr_ip4.checksum;
			icmphdr_compat.un = icmphdr_ip4.un;
		} else {
			if (pkt_payload_len < sizeof(struct icmp6_hdr)) {
				fprintf(stderr, "Recieved truncated ICMPv6 packet.\n");
				continue;
			}

			struct icmp6_hdr icmphdr_ip6;
			memcpy(&icmphdr_ip6, pkt_payload, sizeof(struct icmp6_hdr));

			// Only need to implement compatibility echo request/reply.
			icmphdr_compat.type = icmphdr_ip6.icmp6_type;
			icmphdr_compat.code = icmphdr_ip6.icmp6_code;
			icmphdr_compat.checksum = 0; // ICMPv6 checksumming is handled by the kernel.
			icmphdr_compat.un.echo.id = icmphdr_ip6.icmp6_id;
			icmphdr_compat.un.echo.sequence = icmphdr_ip6.icmp6_seq;
		}

		if (pong_addr->sa_family == AF_INET && icmphdr_compat.type != ICMP_ECHOREPLY) {
			fprintf(stdout,
					"Recieved ICMP packet, not echo reply: type %hhu, code %hhu.\n",
					icmphdr_compat.type, icmphdr_compat.code);
			continue;
		} else if (pong_addr->sa_family == AF_INET6 && icmphdr_compat.type != ICMP6_ECHO_REPLY) {
			fprintf(stdout,
					"Recieved ICMPv6 packet, not echo reply: type %hhu, code %hhu.\n",
					icmphdr_compat.type, icmphdr_compat.code);
			continue;
		}

		if (ntohs(icmphdr_compat.un.echo.id) != ping_id) {
			fprintf(stdout,
					"Recieved echo reply packet, wrong id: id %hu.\n",
					ntohs(icmphdr_compat.un.echo.id));
			continue;
		}

		// TODO: check source IP.

		fprintf(stdout, "Recieved packet:\n");
		print_icmp_packet(pong_addr, recv_bytes, icmphdr_compat);

		unsigned short npongs = update_pong_received(ntohs(icmphdr_compat.un.echo.sequence));
		if (npongs) {
			fprintf(stdout, "Received pong for this ping %hu times.\n", npongs);
		} else {
			fprintf(stdout, "Received pong for ping not sent within last %.02fs.\n",
					timespec2double(useconds2timespec(PING_RECV_TIMEOUT_US)));
		}

		struct timespec time_end;
		clock_gettime(CLOCK_MONOTONIC, &time_end);

		// time_end - time_start
		struct timespec time_elapsed = diff_timespec(time_start, time_end);

		// time_elapsed >= timeout
		if (-1 < cmp_timespec(time_elapsed, timeout)) {
			return;
		}

		// timeout - time_elapsed
		timeout = diff_timespec(time_elapsed, timeout);

		fprintf(stdout, "Continuing select loop, remaining time %.03fs\n", timespec2double(timeout));
	} while (1);
}

static void usage(const char *progname) {
	fprintf(stderr, "Usage: %s [-4|-6] <address> [<hook command>]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "       -4      Interpret <address> as an IPv4 address.\n");
	fprintf(stderr, "       -6      Interpret <address> as an IPv6 address.\n");
}

// Driver Code
int main(int argc, const char *argv[])
{
	int ping_sockfd;
	struct sockaddr *ping_addr;
	size_t ping_addr_s;
	//int addrlen = sizeof(addr_con);
	//char net_buf[NI_MAXHOST];

	init_ping_record();

	const char *progname;
	if (0 < argc)
		progname = argv[0];
	else
		progname = "monitor-ip";

	if (4 != argc) {
		fprintf(stderr, "Incorrect arguments!\n");
		usage(progname);
		exit(1);
	}

	struct sockaddr_in ping_addr4;
	struct sockaddr_in6 ping_addr6;
	if (0 == strcmp("-4", argv[1])) {
		int parse_result = inet_pton(AF_INET, argv[2], &ping_addr4.sin_addr);
		if (1 == parse_result) {
			ping_addr4.sin_family = AF_INET;
			ping_addr4.sin_port = PING_PORT;
			ping_addr = (struct sockaddr *)&ping_addr4;
			ping_addr_s = sizeof(ping_addr4);
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv4 address\n");
			return 1;
		} else {
			fprintf(stderr, "Failed to parse IPv4 address: %s\n", strerror(errno));
			return 1;
		}
	} else if (0 == strcmp("-6", argv[1])) {
		int parse_result = inet_pton(AF_INET6, argv[2], &ping_addr6.sin6_addr);
		if (1 == parse_result) {
			ping_addr6.sin6_family = AF_INET6;
			ping_addr6.sin6_port = PING_PORT;
			ping_addr = (struct sockaddr *)&ping_addr6;
			ping_addr_s = sizeof(ping_addr6);
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv6 address\n");
			return 1;
		} else {
			fprintf(stderr, "Failed to parse IPv6 address: %s\n", strerror(errno));
			return 1;
		}
	} else {
		fprintf(stderr, "Unknown address family!\n");
		usage(progname);
		return 1;
	}


	if (ping_addr->sa_family == AF_INET) {
		ping_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	} else {
		ping_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	}
	if (0 > ping_sockfd) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return 0;
	}

	// set socket options at ip to TTL and value to 64,
	if (ping_addr->sa_family == AF_INET) {
		int ttl_val = PING_TTL;
		if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
			fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
			return 0;
		}
	}

	struct timespec time_since_last_receive;
	uint64_t pings_sent = 0;
	do {
		// sequence = pings_sent % (1 << 16) .
		uint16_t sequence = pings_sent;
		struct sent_ping sent_ping;
		if (ping_addr->sa_family == AF_INET) {
			sent_ping = send_ping_v4(sequence, ping_sockfd, ping_addr, ping_addr_s);
		} else {
			sent_ping = send_ping_v6(sequence, ping_sockfd, ping_addr, ping_addr_s);
		}

		if (pings_sent)
			cleanup_ping_record(time_since_last_receive);

		save_ping(sent_ping);
		pings_sent += 1;

		clock_gettime(CLOCK_MONOTONIC, &time_since_last_receive);

		receive_pong(ping_sockfd, ping_addr);
	} while (1);

	fini_ping_record();

	return 0;
}
