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
#include "netio.h"

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

	struct timespec timeout_ping_receive;
	useconds2timespec(PING_RECV_TIMEOUT_US, &timeout_ping_receive);
	ping_record = ping_record_init(&timeout_ping_receive);

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

		if (PING_MAX_CONSECURIVE_MISSED_COUNT <= ping_record->missed_cnt) {
			trigger_monitor_notify(monitor_notify_cmd);
		}

		ping_record_submit(ping_record, &ping_record_entry);
		pings_sent += 1;

		clock_gettime(CLOCK_MONOTONIC, &time_since_last_receive);

		struct timespec time_recv_end;
		timespec_add(&time_ping_start, &timeout_ping_receive, &time_recv_end);

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
