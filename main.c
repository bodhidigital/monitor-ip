// main.c

#include "features.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
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

#include "packet.h"
#include "checksum.h"
#include "timeutil.h"
#include "record.h"

#define PING_PKT_S (64)
#define PING_MSG_S (PING_PKT_S - sizeof(struct icmphdr))
#define PING_PORT (0)
#define PING_SLEEP_US (1 * 1000 * 1000)
#define PING_RECV_TIMEOUT_US (1 * 1000 * 1000)
#define PING_TTL (64)
#define PING_MAX_CONSECURIVE_MISSED_COUNT (1)

static uint16_t ping_id;
static struct ping_record *ping_record;

__attribute__((constructor))
static void set_ping_id () {
	uint32_t pid = getpid();
	ping_id = (pid >> 16) ^ (pid & 0xffff);
}

static struct ping_record_entry send_ping_v4 (
		uint16_t sequence, int ping_sockfd, struct sockaddr *ping_addr,
		size_t ping_addr_s
) {
	size_t icmp_pkt_s = sizeof(struct icmphdr) + PING_MSG_S;
	void *icmp_pkt = alloca(icmp_pkt_s);
	struct icmphdr *icmphdr = (struct icmphdr *)icmp_pkt;

	bzero(icmp_pkt, sizeof(icmp_pkt));

	icmphdr->type = ICMP_ECHO;
	icmphdr->icmp_echo_id = htons(ping_id);

	icmphdr->icmp_echo_seq = htons(sequence);
	icmphdr->checksum = checksum16_1s_complement(icmp_pkt, sizeof(icmp_pkt));

	// Send packet
	ssize_t bytes_sent = sendto(
			ping_sockfd, icmp_pkt, sizeof(icmp_pkt), 0, ping_addr,
			ping_addr_s);
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	// Immediately after send.
	struct timespec time_sent;
	clock_gettime(CLOCK_MONOTONIC, &time_sent);

	fprintf(stdout, "Sent packet:\n");
	print_icmphdr(ping_addr, sizeof(icmp_pkt), *icmphdr);

	return (struct ping_record_entry){
		.sequence = sequence,
		.time_sent = time_sent,
		.pong_cnt = 0
	};
}

static struct ping_record_entry send_ping_v6 (
		uint16_t sequence, int ping_sockfd, struct sockaddr *ping_addr,
		size_t ping_addr_s
) {
	size_t icmp6_pkt_s = sizeof(struct icmp6_hdr) + PING_MSG_S;
	void *icmp6_pkt = alloca(icmp6_pkt_s);
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)icmp6_pkt;

	bzero(icmp6_pkt, icmp6_pkt_s);

	icmp6_hdr->icmp6_id = htons(ping_id);
	icmp6_hdr->icmp6_seq = htons(sequence);
	icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_hdr->icmp6_code = 0;

	// Send packet.
	ssize_t bytes_sent = sendto(
			ping_sockfd, icmp6_pkt, icmp6_pkt_s, 0, ping_addr, ping_addr_s);
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

	print_icmphdr(ping_addr, icmp6_pkt_s, icmphdr_compat);

	return (struct ping_record_entry){
		.sequence = sequence,
		.time_sent = time_sent,
		.pong_cnt = 0
	};
}

// TODO: Pass desired end timestamp.
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
		struct timeval timeout_val;
		timespec2val(&timeout, &timeout_val);
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
			// The IP header appears to be stripped for v6 but not v4.
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

			icmphdr_compat = icmphdr_ip4;
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
			icmphdr_compat.icmp_echo_id = icmphdr_ip6.icmp6_id;
			icmphdr_compat.icmp_echo_seq = icmphdr_ip6.icmp6_seq;
		}

		if (pong_addr->sa_family == AF_INET &&
				icmphdr_compat.type != ICMP_ECHOREPLY) {
			fprintf(stdout,
					"Recieved ICMP packet, not echo reply: type %hhu, code %hhu.\n",
					icmphdr_compat.type, icmphdr_compat.code);
			continue;
		} else if (pong_addr->sa_family == AF_INET6 &&
				icmphdr_compat.type != ICMP6_ECHO_REPLY) {
			fprintf(stdout,
					"Recieved ICMPv6 packet, not echo reply: type %hhu, code %hhu.\n",
					icmphdr_compat.type, icmphdr_compat.code);
			continue;
		}

		if (ntohs(icmphdr_compat.icmp_echo_id) != ping_id) {
			fprintf(stdout,
					"Recieved echo reply packet, wrong id: id %hu.\n",
					ntohs(icmphdr_compat.icmp_echo_id));
			continue;
		}

		// TODO: check source IP.

		fprintf(stdout, "Recieved packet:\n");
		print_icmphdr(pong_addr, recv_bytes, icmphdr_compat);

		unsigned short npongs = ping_record_update_pong(
				ping_record, ntohs(icmphdr_compat.icmp_echo_seq));
		if (npongs) {
			fprintf(stdout, "Received pong for this ping %hu times.\n", npongs);
		} else {
			fprintf(stdout, "Received pong for ping not sent within last %.02fs.\n",
					timespec2double(&ping_record->timeout));
		}

		struct timespec time_end;
		clock_gettime(CLOCK_MONOTONIC, &time_end);

		// time_end - time_start
		struct timespec time_elapsed;
		timespec_diff(&time_start, &time_end, &time_elapsed);

		// time_elapsed >= timeout
		if (-1 < cmp_timespec(&time_elapsed, &timeout)) {
			return;
		}

		// timeout - time_elapsed
		struct timespec timeout_next;
		timespec_diff(&time_elapsed, &timeout, &timeout_next);
		timeout = timeout_next;

		fprintf(stdout,
				"Continuing select loop, remaining time %.03fs\n",
				timespec2double(&timeout));
	} while (1);
}

static void trigger_monitor_notify(const char *monitor_notify_cmd) {
	fprintf(stdout,
			"Missed pings exceeds limit of %d.\n", PING_MAX_CONSECURIVE_MISSED_COUNT);

	char *missed_ping_count_str;
	if (0 > asprintf(&missed_ping_count_str, "%llu", ping_record->missed_cnt)) {
		fprintf(stderr,
				"Error allocating missed ping count string: %s\n", strerror(errno));
		exit(1);
	}

	pid_t fork_pid = fork();
	if (0 == fork_pid) {
		fprintf(stdout, "Executing monitor notify as PID %d.\n", getpid());
		execlp(monitor_notify_cmd, monitor_notify_cmd, missed_ping_count_str);
		fprintf(stderr, "Error executing monitor notify: %s.\n", strerror(errno));
		exit(127);
	} else if (0 < fork_pid) {
		free(missed_ping_count_str);

		int child_status;
		fprintf(stdout, "Waiting for child with PID of %d.\n", fork_pid);
		if (-1 >= waitpid(fork_pid, &child_status, 0)) {
			fprintf(stderr, "Failed to wait for child: %s\n", strerror(errno));
			exit(1);
		}

		if (WIFSIGNALED(child_status)) {
			fprintf(stderr,
					"Child terminated by signal: %d (%s)\n", WTERMSIG(child_status),
					strsignal(WTERMSIG(child_status)));
			exit(1);
		} else {
			fprintf(stdout,
					"Child exited with status code: %d\n", WEXITSTATUS(child_status));
		}
	} else {
		fprintf(stderr,
				"Error launching monitor notify child process: %s\n", strerror(errno));
		exit(1);
	}
}

static void usage(const char *progname) {
	fprintf(stderr, "Usage: %s [-4|-6] <address> [<hook command>]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "       -4      Interpret <address> as an IPv4 address.\n");
	fprintf(stderr, "       -6      Interpret <address> as an IPv6 address.\n");
}

int main(int argc, const char *argv[])
{
	int ping_sockfd;
	struct sockaddr *ping_addr;
	size_t ping_addr_s;

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

	const char *af_inet_version = argv[1];
	const char *ip_address_str = argv[2];
	const char *monitor_notify_cmd = argv[3];

	struct sockaddr_in ping_addr4;
	struct sockaddr_in6 ping_addr6;
	if (0 == strcmp("-4", af_inet_version)) {
		int parse_result = inet_pton(AF_INET, ip_address_str, &ping_addr4.sin_addr);
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
	} else if (0 == strcmp("-6", af_inet_version)) {
		int parse_result = inet_pton(AF_INET6, ip_address_str, &ping_addr6.sin6_addr);
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
		return 1;
	}

	// Set socket options.
	if (ping_addr->sa_family == AF_INET) {
		int ttl_val = PING_TTL;
		if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
			fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
			return 1;
		}
	}

	struct timespec ping_receive_timeout;
	useconds2timespec(PING_RECV_TIMEOUT_US, &ping_receive_timeout);
	ping_record = ping_record_init(&ping_receive_timeout);

	struct timespec time_since_last_receive;
	uint64_t pings_sent = 0;
	do {
		// sequence = pings_sent % (1 << 16) .
		uint16_t sequence = pings_sent;
		struct ping_record_entry ping_record_entry;
		if (ping_addr->sa_family == AF_INET) {
			ping_record_entry = send_ping_v4(
					sequence, ping_sockfd, ping_addr, ping_addr_s);
		} else {
			ping_record_entry = send_ping_v6(
					sequence, ping_sockfd, ping_addr, ping_addr_s);
		}

		if (pings_sent)
			ping_record_collect_expired(ping_record, &time_since_last_receive);

		if (PING_MAX_CONSECURIVE_MISSED_COUNT <= ping_record->missed_cnt) {
			trigger_monitor_notify(monitor_notify_cmd);
		}

		ping_record_submit(ping_record, &ping_record_entry);
		pings_sent += 1;

		clock_gettime(CLOCK_MONOTONIC, &time_since_last_receive);

		receive_pong(ping_sockfd, ping_addr);
	} while (1);

	ping_record_free(ping_record);

	return 0;
}
