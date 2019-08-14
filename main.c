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
#include <getopt.h>
#include <limits.h>

#include "timeutil.h"
#include "record.h"
#include "netio.h"
#include "monitor.h"

#define PING_PORT (0)

struct monitor_ip_config {
	const struct sockaddr *ping_addr;
	uint8_t ttl;
	struct netio_params netio_params;
	struct monitor_params monitor_params;
	struct timespec time_ping_interval;
	struct timespec time_ping_expire;
};

static uint16_t monitor_ip_get_ping_id ();
static void monitor_ip_usage (const char *);
static void monitor_ip_set_default_config (struct monitor_ip_config *);
static struct monitor_ip_config *monitor_ip_configure (int, char *const *);
static void monitor_ip_config_free (struct monitor_ip_config *);
static int monitor_ip_open_socket (sa_family_t);
static void monitor_ip_set_socket_options (struct monitor_ip_config *, int);
static void monitor_ip_update_pongs (
		struct ping_record *, size_t, const struct netio_pong *);
static void monitor_ip_loop_iter (
		int, struct monitor_ip_config *, struct ping_record *, unsigned long long *);

int main(int argc, char *const *argv)
{
	// Get config.
	struct monitor_ip_config *cfg = monitor_ip_configure(argc, argv);

	// Open socket.
	int ping_sockfd = monitor_ip_open_socket(cfg->ping_addr->sa_family);

	// Set socket options.
	monitor_ip_set_socket_options(cfg, ping_sockfd);

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
	fprintf(stderr, "USAGE: %s [OPTIONS] <address> [<hook command>]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Send pings (echo requests) to <address>, excessive missed pongs (echo response)\n"
					"results in <hook command> being run, if it is set.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr, "    -h --help                   Print this message.\n");
	fprintf(stderr, "    -v --verbose                Be verbose (may be specified multiple times).\n");
	fprintf(stderr, "    -4 --ipv4                   Interpret <address> as an IPv4 address.\n"
					"                                (default)\n");
	fprintf(stderr, "    -6 --ipv6                   Interpret <address> as an IPv6 address.\n");
	fprintf(stderr, "    -t --ttl <ttl>              Use <ttl> as IP(v6) TTL/Hop-Limit. (default: 64)\n");
	fprintf(stderr, "    -s --message-size <size>    Use <size> as ICMP message data size.\n"
					"                                (default: 56)\n");
	fprintf(stderr, "    -i --interval <interval>    Use <interval> (may be decimal) as ping\n"
					"                                interval in seconds. (default: 1.0)\n");
	fprintf(stderr, "    -W --expiration <expire>    Use <expire> (may be decimal) as ping interval\n"
					"                                in seconds. (default: 1.99)\n");
	fprintf(stderr, "    -m --missed-max <missed>    Use <missed> as number of missed pongs\n"
					"                                exceeding which triggers the <hook command>.\n"
					"                                (default: 10)\n");
	fprintf(stderr, "    -b --notify-block           Block until <hook command> exits. (default)\n");
	fprintf(stderr, "    -B --no-notify-block        Don't block until <hook command> exits. May\n"
					"                                result in multiple <hook command>s executing\n"
					"                                simultaneously.\n");
}

static void monitor_ip_set_default_config (struct monitor_ip_config *cfg) {
	// TODO: use macros for defaults
	*cfg = (struct monitor_ip_config){
		.ping_addr = NULL,
		.ttl = 64,
		.monitor_params = (struct monitor_params){
			.block = true,
			.missed_max = 10,
			.notify_command = NULL
		},
		.netio_params = (struct netio_params){
			.id = monitor_ip_get_ping_id(),
			.msg_s = 56 // 84 to 104 total bytes IPv4 packet, 104 or more for v6.
		},
		.time_ping_interval = (struct timespec){  // 1.000s
			.tv_sec = 1,
			.tv_nsec = 0
		},
		.time_ping_expire = (struct timespec){  // 1.990s
			.tv_sec = 1,
			.tv_nsec = 990 * 1000 * 1000
		}
	};
}

static struct monitor_ip_config *monitor_ip_configure (
		int argc, char *const *argv
) {
	struct monitor_ip_config *cfg = malloc(sizeof(struct monitor_ip_config));

	// default config
	monitor_ip_set_default_config(cfg);

	const char *progname;
	if (0 < argc)
		progname = argv[0];
	else
		progname = "monitor-ip";

	static const char *const shortopts = "hv46s:t:i:W:m:bB";
	static const struct option longopts[] = {
		{ .name = "help",            .flag = NULL, .has_arg = no_argument,       .val = 'h' },
		{ .name = "verbose",         .flag = NULL, .has_arg = no_argument,       .val = 'v' },
		{ .name = "ipv4",            .flag = NULL, .has_arg = no_argument,       .val = '4' },
		{ .name = "ipv6",            .flag = NULL, .has_arg = no_argument,       .val = '6' },
		{ .name = "ttl",             .flag = NULL, .has_arg = required_argument, .val = 't' },
		{ .name = "message-size",    .flag = NULL, .has_arg = required_argument, .val = 's' },
		{ .name = "interval",        .flag = NULL, .has_arg = required_argument, .val = 'i' },
		{ .name = "expiration",      .flag = NULL, .has_arg = required_argument, .val = 'W' },
		{ .name = "missed-max",      .flag = NULL, .has_arg = required_argument, .val = 'm' },
		{ .name = "notify-block",    .flag = NULL, .has_arg = no_argument,       .val = 'b' },
		{ .name = "no-notify-block", .flag = NULL, .has_arg = no_argument,       .val = 'B' },
		{ .name = NULL,              .flag = NULL, .has_arg = no_argument,       .val = 0 }
	};

	sa_family_t af = AF_INET;
	do {
		int c = getopt_long(argc, argv, shortopts, longopts, NULL);
		if (c == -1)
			break;

		char *str_tmp;
		unsigned long long ull_tmp;
		double d_tmp;
		uint8_t u8_tmp;
		size_t size_tmp;
		struct timespec timespec_tmp;
		switch (c) {
		case 'h':
			monitor_ip_usage(progname);
			exit(0);
		case 'v':
			// TODO
			break;
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 't':
			errno = 0;
			ull_tmp = strtoull(optarg, &str_tmp, 10);
			if (ull_tmp > UINT8_MAX || errno == ERANGE) {
				fprintf(stderr, "Failed to parse TTL: %s\n", strerror(ERANGE));
				exit(1);
			}
			if (errno) {
				fprintf(stderr, "Failed to parse TTL: %s\n", strerror(errno));
				exit(1);
			}
			if (*str_tmp != '\0') {
				fprintf(stderr, "Failed to parse TTL: %s\n", "Trailing characters");
				exit(1);
			}

			u8_tmp = ull_tmp;
			cfg->ttl = u8_tmp;
			break;
		case 's':
			errno = 0;
			ull_tmp = strtoull(optarg, &str_tmp, 10);
			if (ull_tmp > SIZE_MAX || errno == ERANGE) {
				fprintf(stderr, "Failed to parse message size: %s\n", strerror(ERANGE));
				exit(1);
			}
			if (errno) {
				fprintf(stderr, "Failed to parse message size: %s\n", strerror(errno));
				exit(1);
			}
			if (*str_tmp != '\0') {
				fprintf(stderr, "Failed to parse message size: %s\n", "Trailing characters");
				exit(1);
			}

			size_tmp = ull_tmp;
			cfg->netio_params.msg_s = size_tmp;
			break;
		case 'i':
			errno = 0;
			d_tmp = strtod(optarg, &str_tmp);
			if (d_tmp <= 0 || errno == ERANGE) {
				fprintf(stderr, "Failed to parse interval: %s\n", strerror(ERANGE));
				exit(1);
			}
			if (errno) {
				fprintf(stderr, "Failed to parse interval: %s\n", strerror(errno));
				exit(1);
			}
			if (*str_tmp != '\0') {
				fprintf(stderr, "Failed to parse interval: %s\n", "Trailing characters");
				exit(1);
			}

			useconds2timespec((1000 * 1000) * d_tmp, &timespec_tmp);
			cfg->time_ping_interval = timespec_tmp;
			break;
		case 'W':
			errno = 0;
			d_tmp = strtod(optarg, &str_tmp);
			if (d_tmp <= 0 || errno == ERANGE) {
				fprintf(stderr, "Failed to parse expire: %s\n", strerror(ERANGE));
				exit(1);
			}
			if (errno) {
				fprintf(stderr, "Failed to parse expire: %s\n", strerror(errno));
				exit(1);
			}
			if (*str_tmp != '\0') {
				fprintf(stderr, "Failed to parse expire: %s\n", "Trailing characters");
				exit(1);
			}

			useconds2timespec((1000 * 1000) * d_tmp, &timespec_tmp);
			cfg->time_ping_expire = timespec_tmp;
			break;
		case 'm':
			errno = 0;
			ull_tmp = strtoull(optarg, &str_tmp, 10);
			if (errno) {
				fprintf(stderr, "Failed to parse max missed pongs: %s\n", strerror(errno));
				exit(1);
			}
			if (*str_tmp != '\0') {
				fprintf(stderr, "Failed to parse max missed pongs: %s\n", "Trailing characters");
				exit(1);
			}

			cfg->monitor_params.missed_max = ull_tmp;
			break;
		case 'b':
			cfg->monitor_params.block = true;
			break;
		case 'B':
			cfg->monitor_params.block = false;
			break;
		case '?':
			exit(1);
			break;
		default:
			fprintf(stderr, "Unknown argument?\n");
			exit(1);
		}
	} while (1);

	if (argc <= optind) {
		fprintf(stderr, "No IP address specified!\n");
		monitor_ip_usage(progname);
		exit(1);
	}

	const char *ip_address_str = argv[optind];
	if (AF_INET == af) {
		struct sockaddr_in *ping_addr4 = malloc(sizeof(struct sockaddr_in));
		int parse_result = inet_pton(AF_INET, ip_address_str, &ping_addr4->sin_addr);
		if (1 == parse_result) {
			ping_addr4->sin_family = AF_INET;
			ping_addr4->sin_port = PING_PORT;
			cfg->ping_addr = (struct sockaddr *)ping_addr4;
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv4 address\n");
			exit(1);
		} else {
			fprintf(stderr, "Failed to parse IPv4 address: %s\n", strerror(errno));
			exit(1);
		}
	} else if (AF_INET6 == af) {
		struct sockaddr_in6 *ping_addr6 = malloc(sizeof(struct sockaddr_in6));
		int parse_result = inet_pton(
				AF_INET6, ip_address_str, &ping_addr6->sin6_addr);
		if (1 == parse_result) {
			ping_addr6->sin6_family = AF_INET6;
			ping_addr6->sin6_port = PING_PORT;
			cfg->ping_addr = (struct sockaddr *)ping_addr6;
		} else if (0 == parse_result) {
			fprintf(stderr, "Invalid IPv6 address\n");
			exit(1);
		} else {
			fprintf(stderr, "Failed to parse IPv6 address: %s\n", strerror(errno));
			exit(1);
		}
	}

	if (argc > optind + 1) {
		const char *monitor_notify_cmd = argv[optind + 1];
		size_t monitor_notify_cmd_s = strlen(monitor_notify_cmd) + 1;
		char *monitor_notify_cmd_permenant = malloc(monitor_notify_cmd_s);
		memcpy(monitor_notify_cmd_permenant, monitor_notify_cmd, monitor_notify_cmd_s);

		cfg->monitor_params.notify_command = monitor_notify_cmd_permenant;
	}

	return cfg;
}

static void monitor_ip_config_free (struct monitor_ip_config *cfg) {
	free((void *)cfg->ping_addr);
	if (cfg->monitor_params.notify_command)
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

static void monitor_ip_set_socket_options (struct monitor_ip_config *cfg, int ping_sockfd) {
	sa_family_t af = cfg->ping_addr->sa_family;

	int ttl_val = cfg->ttl;

	int sol;
	switch (af) {
	case AF_INET:
		sol = SOL_IP;
		if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
			fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
			exit(1);
		}
		break;
	case AF_INET6:
		sol = SOL_IPV6;
		break;
	default:
		fprintf(stderr, "Unknown address family: %d\n", (int)af);
		exit(1);
	}

	if (setsockopt(ping_sockfd, sol, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
		fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
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
			&time_ping_start, &cfg->time_ping_interval, &time_recv_end);

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
