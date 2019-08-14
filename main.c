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

struct monitor_ip_config {
	const struct sockaddr *ping_addr;
	struct netio_params netio_params;
	struct monitor_params monitor_params;
	struct timespec time_ping_delay;
	struct timespec time_ping_expire;
};

static uint16_t monitor_ip_get_ping_id ();
static void monitor_ip_usage (const char *);
static struct monitor_ip_config *monitor_ip_configure (
		int, const char *[]);
static void monitor_ip_config_free (struct monitor_ip_config *);
static int monitor_ip_open_socket (sa_family_t);
static void monitor_ip_set_socket_options (sa_family_t, int);
static void monitor_ip_update_pongs (
		struct ping_record *, size_t, const struct netio_pong *);
static void monitor_ip_loop_iter (
		int, struct monitor_ip_config *, struct ping_record *, unsigned long long *);

int main(int argc, const char *argv[])
{
	// Get config.
	struct monitor_ip_config *cfg = monitor_ip_configure(argc, argv);

	// Open socket.
	int ping_sockfd = monitor_ip_open_socket(cfg->ping_addr->sa_family);

	// Set socket options.
	monitor_ip_set_socket_options(cfg->ping_addr->sa_family, ping_sockfd);

	struct ping_record *ping_record = ping_record_init(&cfg->time_ping_expire);

	unsigned long long pings_sent = 0;
	do {
		monitor_ip_loop_iter(ping_sockfd, cfg, ping_record, &pings_sent);
	} while (1);

	ping_record_free(ping_record);

	monitor_ip_config_free(cfg);

	return 0;
}

__attribute__((constructor))
static uint16_t monitor_ip_get_ping_id () {
	uint32_t pid = getpid();
	uint16_t ping_id = (pid >> 16) ^ (pid & 0xffff);
	return ping_id;
}

static void monitor_ip_usage (const char *progname) {
	fprintf(stderr, "Usage: %s [-4|-6] <address> [<hook command>]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "       -4      Interpret <address> as an IPv4 address.\n");
	fprintf(stderr, "       -6      Interpret <address> as an IPv6 address.\n");
}

static struct monitor_ip_config *monitor_ip_configure (
		int argc, const char *argv[]
) {
	struct sockaddr *ping_addr;

	const char *progname;
	if (0 < argc)
		progname = argv[0];
	else
		progname = "monitor-ip";

	if (4 != argc) {
		fprintf(stderr, "Incorrect arguments!\n");
		monitor_ip_usage(progname);
		exit(1);
	}

	const char *af_inet_version = argv[1];
	const char *ip_address_str = argv[2];
	const char *monitor_notify_cmd = argv[3];

	if (0 == strcmp("-4", af_inet_version)) {
		struct sockaddr_in *ping_addr4 = malloc(sizeof(struct sockaddr_in));
		int parse_result = inet_pton(AF_INET, ip_address_str, &ping_addr4->sin_addr);
		if (1 == parse_result) {
			ping_addr4->sin_family = AF_INET;
			ping_addr4->sin_port = PING_PORT;
			ping_addr = (struct sockaddr *)ping_addr4;
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv4 address\n");
			exit(1);
		} else {
			fprintf(stderr, "Failed to parse IPv4 address: %s\n", strerror(errno));
			exit(1);
		}
	} else if (0 == strcmp("-6", af_inet_version)) {
		struct sockaddr_in6 *ping_addr6 = malloc(sizeof(struct sockaddr_in6));
		int parse_result = inet_pton(
				AF_INET6, ip_address_str, &ping_addr6->sin6_addr);
		if (1 == parse_result) {
			ping_addr6->sin6_family = AF_INET6;
			ping_addr6->sin6_port = PING_PORT;
			ping_addr = (struct sockaddr *)ping_addr6;
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv6 address\n");
			exit(1);
		} else {
			fprintf(stderr, "Failed to parse IPv6 address: %s\n", strerror(errno));
			exit(1);
		}
	} else {
		fprintf(stderr, "Unknown address family specified by: %s\n", af_inet_version);
		monitor_ip_usage(progname);
		exit(1);
	}

	struct netio_params netio_params = {
		.msg_s = PING_MSG_S,
		.id = monitor_ip_get_ping_id()
	};

	size_t monitor_notify_cmd_s = strlen(monitor_notify_cmd) + 1;
	char *monitor_notify_cmd_permenant = malloc(monitor_notify_cmd_s);
	memcpy(monitor_notify_cmd_permenant, monitor_notify_cmd, monitor_notify_cmd_s);

	struct monitor_params monitor_params = {
		.block = true,
		.missed_max = PING_MAX_CONSECURIVE_MISSED_COUNT,
		.notify_command = monitor_notify_cmd_permenant
	};

	struct timespec time_ping_delay;
	useconds2timespec(TIME_PING_DELAY_US, &time_ping_delay);

	struct timespec timeout_ping_expire;
	useconds2timespec(TIMEOUT_PING_EXPIRE_US, &timeout_ping_expire);

	struct monitor_ip_config *cfg = malloc(sizeof(struct monitor_ip_config));
	*cfg = (struct monitor_ip_config){
		.monitor_params = monitor_params,
		.netio_params = netio_params,
		.ping_addr = ping_addr,
		.time_ping_delay = time_ping_delay,
		.time_ping_expire = timeout_ping_expire
	};

	return cfg;
}

static void monitor_ip_config_free (struct monitor_ip_config *cfg) {
	free((void *)cfg->ping_addr);
	free((void *)cfg->monitor_params.notify_command);
	free(cfg);
}

static int monitor_ip_open_socket (sa_family_t af) {
	int ping_sockfd;
	switch (af) {
	case AF_INET:
		ping_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		break;
	case AF_INET6:
		ping_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		break;
	default:
		fprintf(stderr, "Unknown address family: %d\n", (int)af);
		exit(1);
	}

	if (0 > ping_sockfd) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		exit(1);
	}

	return ping_sockfd;
}

static void monitor_ip_set_socket_options (sa_family_t af, int ping_sockfd) {
	static const int ttl_val = PING_TTL;

	switch (af) {
	case AF_INET:
		if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
			fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
			exit(1);
		}
		break;
	case AF_INET6:
		// TODO
		{}
		break;
	default:
		fprintf(stderr, "Unknown address family: %d\n", (int)af);
		exit(1);
	}
}

static void monitor_ip_update_pongs (
		struct ping_record *ping_record, size_t pongs_s,
		const struct netio_pong *pongs
) {
	for (size_t i = 0; pongs_s > i; ++i) {
		struct netio_pong pong = pongs[i];

		struct ping_record_entry entry_data;
		if (!ping_record_update_pong(ping_record, pong.seq, &entry_data)) {
			fprintf(stderr,
					"Pong for sequence %hu received, but not in sent record, possibly "
					"expired or errant?\n", pong.seq);
			continue;
		}

		struct timespec time_rtt;
		timespec_diff(&entry_data.time_sent, &pong.time_recv, &time_rtt);

		const char *is_dup_str = (1 < entry_data.pong_cnt) ? " (dup)" : "";
		const char *is_exp_str =
			(1 > cmp_timespec(&ping_record->timeout, &time_rtt)) ? " (expired)" : "";
		fprintf(stdout, "Pong for sequence %hu%s, rtt: %.02fms%s\n",
			entry_data.sequence, is_dup_str, timespec2double(&time_rtt) * 1000.,
			is_exp_str);
	}
}

static void monitor_ip_loop_iter (
		int ping_sockfd, struct monitor_ip_config *cfg,
		struct ping_record *ping_record, unsigned long long *pings_sent
) {
	struct timespec time_ping_start;
	clock_gettime(CLOCK_MONOTONIC, &time_ping_start);

	// sequence = pings_sent % (1 << 16) .
	uint16_t sequence = (*pings_sent)++;
	struct ping_record_entry ping_record_entry;
	netio_send(
			&cfg->netio_params, ping_sockfd, cfg->ping_addr,
			sequence, &ping_record_entry);

	ping_record_submit(ping_record, &ping_record_entry);

	struct timespec time_recv_end;
	timespec_add(
			&time_ping_start, &cfg->time_ping_delay, &time_recv_end);

	// MUST FREE pongs
	struct netio_pong *pongs;
	size_t pongs_s = netio_receive(
			&cfg->netio_params, ping_sockfd, cfg->ping_addr,
			&time_recv_end, &pongs);

	struct timespec time_since_last_receive;
	clock_gettime(CLOCK_MONOTONIC, &time_since_last_receive);

	monitor_ip_update_pongs(ping_record, pongs_s, pongs);

	// FREED pongs
	free(pongs);

	ping_record_collect_expired(ping_record, &time_since_last_receive);

	test_monitor_notify_trigger(
			&cfg->monitor_params, ping_record->missed_cnt);
}
