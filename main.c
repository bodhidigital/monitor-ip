// main.c

#include "features.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "timeutil.h"
#include "record.h"
#include "netio.h"
#include "monitor.h"

#define PING_PKT_S (64)
#define PING_MSG_S (PING_PKT_S - sizeof(struct icmphdr))
#define PING_PORT (0)
#define TIME_PING_DELAY_US (1 * 1000 * 1000)
#define TIMEOUT_PING_EXPIRE_US (1 * 1000 * 1000)
#define PING_TTL (64)
#define PING_MAX_CONSECURIVE_MISSED_COUNT (1)

static uint16_t ping_id;
static struct ping_record *ping_record;

__attribute__((constructor))
static void set_ping_id () {
	uint32_t pid = getpid();
	ping_id = (pid >> 16) ^ (pid & 0xffff);
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

	struct netio_params netio_params = {
		.msg_s = PING_MSG_S,
		.id = ping_id
	};

	struct monitor_params monitor_params = {
		.block = true,
		.missed_max = PING_MAX_CONSECURIVE_MISSED_COUNT,
		.notify_command = monitor_notify_cmd
	};

	struct timespec timeout_ping_expire;
	useconds2timespec(TIMEOUT_PING_EXPIRE_US, &timeout_ping_expire);
	ping_record = ping_record_init(&timeout_ping_expire);

	struct timespec time_ping_delay;
	useconds2timespec(TIME_PING_DELAY_US, &time_ping_delay);

	struct timespec time_since_last_receive;
	uint64_t pings_sent = 0;
	do {
		struct timespec time_ping_start;
		clock_gettime(CLOCK_MONOTONIC, &time_ping_start);

		// sequence = pings_sent % (1 << 16) .
		uint16_t sequence = pings_sent;
		struct ping_record_entry ping_record_entry;
		netio_send(
				&netio_params, ping_sockfd, ping_addr, sequence, &ping_record_entry);

		if (pings_sent)
			ping_record_collect_expired(ping_record, &time_since_last_receive);

		test_monitor_notify_trigger(&monitor_params, ping_record->missed_cnt);

		ping_record_submit(ping_record, &ping_record_entry);
		pings_sent += 1;

		clock_gettime(CLOCK_MONOTONIC, &time_since_last_receive);

		struct timespec time_recv_end;
		timespec_add(&time_ping_start, &time_ping_delay, &time_recv_end);

		struct netio_pong *pongs;
		size_t pongs_s = netio_receive(&netio_params, ping_sockfd, ping_addr,
				&time_recv_end, &pongs);

		for (size_t i = 0; pongs_s > i; ++i) {
			struct netio_pong pong = pongs[i];

			struct ping_record_entry entry_data;
			ping_record_update_pong(ping_record, pong.seq, &entry_data);

			struct timespec time_rtt;
			timespec_diff(&entry_data.time_sent, &pong.time_recv, &time_rtt);

			const char *is_dup_str = (1 < entry_data.pong_cnt) ? " (dup)" : "";
			fprintf(stdout, "Pong for sequence %hu%s, rtt: %.02fms\n",
				entry_data.sequence, is_dup_str, timespec2double(&time_rtt) * 1000.);
		}
	} while (1);

	ping_record_free(ping_record);

	return 0;
}
