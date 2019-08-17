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
#include "log.h"

#define PING_PORT (0)

struct monitor_ip_config {
	const struct sockaddr *ping_addr;
	uint8_t ttl;
	bool reset_after_monitor_notify;
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
	printf("USAGE: %s [OPTIONS] <address> [<hook command> [<arg> [...]]\n", progname);
	printf("\n");
	printf("Send pings (echo requests) to <address>, excessive missed pongs (echo response)\n"
		   "results in <hook command> being run with provided arguments, if it is set.\n");
	printf("\n");
	printf("OPTIONS:\n");
	printf("    -h --help                   Print this message.\n");
	printf("    -v --verbose                Be verbose (may be specified multiple times).\n");
	printf("    -q --quiet                  Be less verbose (may be specified multiple times).\n");
	printf("    -4 --ipv4                   Interpret <address> as an IPv4 address.\n"
		   "                                (default)\n");
	printf("    -6 --ipv6                   Interpret <address> as an IPv6 address.\n");
	printf("    -t --ttl <ttl>              Use <ttl> as IP(v6) TTL/Hop-Limit. (default: 64)\n");
	printf("    -s --message-size <size>    Use <size> as ICMP message data size.\n"
		   "                                (default: 56)\n");
	printf("    -i --interval <interval>    Use <interval> (may be decimal) as ping\n"
		   "                                interval in seconds. (default: 1.0)\n");
	printf("    -W --expiration <expire>    Use <expire> (may be decimal) as ping interval\n"
		   "                                in seconds. (default: 1.99)\n");
	printf("    -m --missed-max <missed>    Use <missed> as number of missed pongs\n"
		   "                                exceeding which triggers the <hook command>.\n"
		   "                                (default: 10)\n");
	printf("    -b --notify-block           Block until <hook command> exits. (default)\n");
	printf("    -B --no-notify-block        Don't block until <hook command> exits. May\n"
		   "                                result in multiple <hook command>s executing\n"
		   "                                simultaneously.\n");
	printf("    -r --reset                  Reset missed ping count after successful run of\n"
		   "                                notify command.  Only valid with --notify-block.\n");
}

static void monitor_ip_set_default_config (struct monitor_ip_config *cfg) {
	// TODO: use macros for defaults
	*cfg = (struct monitor_ip_config){
		.ping_addr = NULL,
		.ttl = 64,
		.reset_after_monitor_notify = false,
		.monitor_params = (struct monitor_params){
			.block = true,
			.missed_max = 10,
			.notify_command = NULL,
			.notify_command_arguments = NULL
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

	static const char *const shortopts = "hvq46s:t:i:W:m:bBr";
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
		{ .name = "reset",           .flag = NULL, .has_arg = no_argument,       .val = 'r' },
		{ .name = NULL,              .flag = NULL, .has_arg = no_argument,       .val = 0 }
	};

	sa_family_t af = AF_INET;
	int logging_level = log_logging_level;
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
			if (logging_level > LOG_LEVEL_MIN)
				logging_level -= 1;
			break;
		case 'q':
			if (logging_level < LOG_LEVEL_MAX_INC)
				logging_level += 1;
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
			if (ull_tmp > UINT8_MAX && !errno)
				errno = ERANGE;
			if (errno)
				fatalf("Failed to parse TTL: %s", strerror(errno));
			if (*str_tmp != '\0')
				fatalf("Failed to parse TTL: %s", "Trailing characters");

			u8_tmp = ull_tmp;
			cfg->ttl = u8_tmp;
			break;
		case 's':
			errno = 0;
			ull_tmp = strtoull(optarg, &str_tmp, 10);
			if (ull_tmp > SIZE_MAX && !errno)
				errno = ERANGE;
			if (errno)
				fatalf("Failed to parse message size: %s", strerror(errno));
			if (*str_tmp != '\0')
				fatalf("Failed to parse message size: %s", "Trailing characters");

			size_tmp = ull_tmp;
			cfg->netio_params.msg_s = size_tmp;
			break;
		case 'i':
			errno = 0;
			d_tmp = strtod(optarg, &str_tmp);
			if (d_tmp <= 0 && !errno)
				errno = ERANGE;
			if (errno)
				fatalf("Failed to parse interval: %s", strerror(errno));
			if (*str_tmp != '\0')
				fatalf("Failed to parse interval: %s", "Trailing characters");

			useconds2timespec((1000 * 1000) * d_tmp, &timespec_tmp);
			cfg->time_ping_interval = timespec_tmp;
			break;
		case 'W':
			errno = 0;
			d_tmp = strtod(optarg, &str_tmp);
			if (d_tmp <= 0 && !errno)
				errno = ERANGE;
			if (errno)
				fatalf("Failed to parse expire: %s", strerror(errno));
			if (*str_tmp != '\0')
				fatalf("Failed to parse expire: %s", "Trailing characters");

			useconds2timespec((1000 * 1000) * d_tmp, &timespec_tmp);
			cfg->time_ping_expire = timespec_tmp;
			break;
		case 'm':
			errno = 0;
			ull_tmp = strtoull(optarg, &str_tmp, 10);
			if (errno)
				fatalf("Failed to parse max missed pongs: %s", strerror(errno));
			if (*str_tmp != '\0')
				fatalf("Failed to parse max missed pongs: %s", "Trailing characters");

			cfg->monitor_params.missed_max = ull_tmp;
			break;
		case 'b':
			cfg->monitor_params.block = true;
			break;
		case 'B':
			cfg->monitor_params.block = false;
			break;
		case 'r':
			cfg->reset_after_monitor_notify = true;
			break;
		case '?':
			exit(1);
			break;
		default:
			panics("getopt provided an unknown argument value?");
		}
	} while (1);

	if (cfg->reset_after_monitor_notify && !cfg->monitor_params.block)
		fatalf("--reset specified, but monitor notify command is not configured to "
			   "block! See: %s -h", progname);

	log_logging_level = logging_level;

	if (argc <= optind)
		fatalf("No IP address specified on the command line! See: %s -h", progname);

	size_t ping_addr_impl_s, inx_addr_offset, port_offset;
	// Get size of sockaddr implementation, and Compute offsets from (void *)0x0.
	switch (af) {
	case AF_INET:
		ping_addr_impl_s = sizeof(struct sockaddr_in);
		inx_addr_offset = (size_t)&((struct sockaddr_in *)0)->sin_addr;
		port_offset = (size_t)&((struct sockaddr_in *)0)->sin_port;
		break;
	case AF_INET6:
		ping_addr_impl_s = sizeof(struct sockaddr_in6);
		inx_addr_offset = (size_t)&((struct sockaddr_in6 *)0)->sin6_addr;
		port_offset = (size_t)&((struct sockaddr_in6 *)0)->sin6_port;
		break;
	default:
		panicf("Unknown address family: %d?", (int)af);
	}

	// Is freed as part of cfg using monitor_ip_config_free.
	struct sockaddr *ping_addr_impl = malloc(ping_addr_impl_s);
	if (!ping_addr_impl)
		panics("Failed to allocate ping socket address implementation!");

	// Zero the address out since we can't gurentee setting the corresponding
	// sin*_zero field.
	bzero(ping_addr_impl, ping_addr_impl_s);

	const char *ip_address_str = argv[optind++];
	void *inx_addr_p = (char *)ping_addr_impl + inx_addr_offset;
	int parse_result = inet_pton(af, ip_address_str, inx_addr_p);
	if (0 == parse_result) {
		fatals("Failed to parse: Invalid format");
	} else if (0 > parse_result) {
		fatalf("Failed to parse: %s", strerror(errno));
	}

	ping_addr_impl->sa_family = af;
	in_port_t *port_p = (in_port_t *)((char *)ping_addr_impl + port_offset);
	*port_p = PING_PORT;
	cfg->ping_addr = ping_addr_impl;

	if (argc > optind) {
		const char *monitor_notify_cmd = argv[optind++];
		size_t monitor_notify_cmd_s = strlen(monitor_notify_cmd) + 1;
		// Is freed as part of cfg using monitor_ip_config_free.
		char *monitor_notify_cmd_perm = malloc(monitor_notify_cmd_s);
		if (!monitor_notify_cmd_perm)
			panics("Failed to allocate monitor notify command string.");

		memcpy(monitor_notify_cmd_perm, monitor_notify_cmd, monitor_notify_cmd_s);

		size_t monitor_notify_cmd_args_s = argc - optind + 2;
		char **monitor_notify_cmd_args = malloc(
				sizeof(char *) * monitor_notify_cmd_args_s);
		if (!monitor_notify_cmd_args)
			panics("Failed to allocate monitor notify command arguments array.");

		monitor_notify_cmd_args[0] = monitor_notify_cmd_perm;
		for (size_t i = 1; monitor_notify_cmd_args_s - 1 > i; ++i) {
			const char *arg = argv[optind++];
			size_t arg_s = strlen(arg) + 1;
			char *arg_perm = malloc(arg_s);
			if (!arg_perm)
				panicf("Failed to allocate monitor notify command argument (%zu), %s.",
						i, arg_perm);

			memcpy(arg_perm, arg, arg_s);
			monitor_notify_cmd_args[i] = arg_perm;
		}
		monitor_notify_cmd_args[monitor_notify_cmd_args_s - 1] = NULL;

		cfg->monitor_params.notify_command = monitor_notify_cmd_perm;
		cfg->monitor_params.notify_command_arguments = monitor_notify_cmd_args;
	}

	if (argc > optind + 2)
		fatals("Extra arguments detected!");

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
		panicf("Unknown address family: %d?", (int)af);
	}

	if (0 > ping_sockfd)
		fatalf("Error opening socket: %s", strerror(errno));

	return ping_sockfd;
}

static void monitor_ip_set_socket_options (struct monitor_ip_config *cfg, int ping_sockfd) {
	sa_family_t af = cfg->ping_addr->sa_family;

	int ttl_val = cfg->ttl;

	int sol;
	switch (af) {
	case AF_INET:
		sol = SOL_IP;
		break;
	case AF_INET6:
		sol = SOL_IPV6;
		break;
	default:
		panicf("Unknown address family: %d?", (int)af);
		exit(1);
	}

	if (setsockopt(ping_sockfd, sol, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
		fatalf("Failed setting socket TTL: %s", strerror(errno));
}

static void monitor_ip_update_pongs (
		struct ping_record *ping_record, size_t pongs_s,
		const struct netio_pong *pongs
) {
	for (size_t i = 0; pongs_s > i; ++i) {
		struct netio_pong pong = pongs[i];

		// TODO: don't add expired pings to the record at all!
		struct ping_record_entry *entry_data = ping_record_get_entry(
				ping_record, pong.seq);
		if (!entry_data) {
			warnf("Pong for sequence %hu received, but not in sent record, possibly "
				  "expired or errant.", pong.seq);
			continue;
		}

		struct timespec time_rtt;
		timespec_diff(&entry_data->time_sent, &pong.time_recv, &time_rtt);

		const char *is_exp_str = "";
		if (1 > cmp_timespec(&ping_record->timeout, &time_rtt)) {
			warnf("Pong for sequence %hu received after expiration time "
				  "(%.03f ms >= %.03f ms).", entry_data->sequence,
					1000. * timespec2double(&time_rtt),
					1000. * timespec2double(&ping_record->timeout));
			is_exp_str = " (expired)";
		} else {
			// Only imcrement pong count if not expired.
			entry_data->pong_cnt += 1;
		}

		const char *is_dup_str = "";
		if (1 < entry_data->pong_cnt)
			is_dup_str = " (dup)";

		infof("pong: icmp_seq=%d%s time=%.03f ms%s",
				entry_data->sequence, is_dup_str,
				1000. * timespec2double(&time_rtt), is_exp_str);
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

	if (monitor_notify_test(&cfg->monitor_params, ping_record->missed_cnt)) {
		int notify_ret = monitor_notify_trigger(
				&cfg->monitor_params, ping_record->missed_cnt, cfg->ping_addr);
		if (0 > notify_ret) {
			errorf("Failed to trigger monitor notify: %s", strerror(errno));
		} else if (0 == notify_ret && cfg->reset_after_monitor_notify) {
			ping_record->missed_cnt = 0;
		}

		if (cfg->monitor_params.block) {
			// May have blocked for arbitrary amount of time, some pings may seem expired
			// even though they are not.
			ping_record_clear(ping_record);
		}
	}
}
