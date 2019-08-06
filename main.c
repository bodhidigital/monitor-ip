// main.c

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#define PING_PKT_S (64)
#define PING_MSG_S (PING_PKT_S - sizeof(struct icmphdr))
#define PING_PORT (0)
#define PING_SLEEP_US (1 * 1000 * 1000)
#define RECV_TIMEOUT_US (1 * 1000 * 1000)
#define PING_TTL (64)

// ping packet structure
struct ping_pkt {
	struct icmphdr hdr;
	char msg[PING_PKT_S];
} __attribute__((packed));

static uint16_t ping_id;

__attribute__((constructor)) void set_ping_id() {
	uint32_t pid = getpid();
	ping_id = (pid >> 16) ^ (pid & 0xffff);
}

// Calculating the Check Sum
uint16_t checksum (void *b, uint16_t len) {
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

void print_icmp_packet (struct sockaddr *addr, ssize_t length, struct ping_pkt pkt) {
	void *addr_data;
	size_t addr_str_s;
	if (addr->sa_family == AF_INET) {
		addr_str_s = 16;
		addr_data = &((struct sockaddr_in *)addr)->sin_addr;
	} else {
		addr_str_s = 40;
		addr_data = &((struct sockaddr_in6 *)addr)->sin6_addr;
	}

	char *addr_str;
	addr_str = (char *)malloc(addr_str_s);

	inet_ntop(addr->sa_family, addr_data, addr_str, addr_str_s);

	fprintf(stdout, "\tAddress: %s\n", addr_str);
	fprintf(stdout, "\tLength: %zd\n", length);
	fprintf(stdout, "\tType: %hhu\n", (unsigned char)pkt.hdr.type);
	fprintf(stdout, "\tCode: %hhu\n", (unsigned char)pkt.hdr.code);
	fprintf(stdout, "\tChecksum: %hu\n", (unsigned short)pkt.hdr.checksum);
	fprintf(stdout, "\tID: %hu\n", (unsigned short)pkt.hdr.un.echo.id);
	fprintf(stdout, "\tSequence Number: %hu\n", (unsigned short)pkt.hdr.un.echo.sequence);

	free(addr_str);
}

// make a ping request
void send_ping (
		int msg_count, int ping_sockfd, struct sockaddr *ping_addr, size_t ping_addr_s
) {
	struct ping_pkt icmp_ping_pkt;

	//filling packet
	bzero(&icmp_ping_pkt, sizeof(icmp_ping_pkt));

	icmp_ping_pkt.hdr.type = ICMP_ECHO;
	icmp_ping_pkt.hdr.un.echo.id = ping_id;

	int i;
	for (i = 0; i < (int)sizeof(icmp_ping_pkt.msg) - 1; i++)
		icmp_ping_pkt.msg[i] = '\0';

	icmp_ping_pkt.msg[i] = 0;
	icmp_ping_pkt.hdr.un.echo.sequence = msg_count;
	icmp_ping_pkt.hdr.checksum = checksum(&icmp_ping_pkt, sizeof(icmp_ping_pkt));

	//send packet
	ssize_t bytes_sent = sendto(
			ping_sockfd, &icmp_ping_pkt, sizeof(icmp_ping_pkt), 0, ping_addr, ping_addr_s);
	if (bytes_sent < 0) {
		fprintf(stderr, "Error sending packet: %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stdout, "Sent packet:\n");
	print_icmp_packet(ping_addr, sizeof(icmp_ping_pkt), icmp_ping_pkt);
}

void receive_pong (
		int ping_sockfd,
		struct sockaddr *ping_addr
) {
	struct sockaddr *pong_addr;
	socklen_t pong_addr_s;
	struct {
		struct iphdr hdr;
		struct ping_pkt icmp_ping_pkt;
	} pkt;

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

	struct timeval timeout;
	fd_set fds;

	timeout.tv_sec = PING_SLEEP_US / (1000 * 1000);
	timeout.tv_usec = PING_SLEEP_US % (1000 * 1000);

	FD_ZERO(&fds);
	FD_SET(ping_sockfd, &fds);

	struct timespec time_start;
	clock_gettime(CLOCK_MONOTONIC, &time_start);

	do {
		fd_set read_fds = fds;
		int select_avail = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
		if (0 > select_avail) {
			fprintf(stderr, "Error polling ICMP socket: %s\n", strerror(errno));
			exit(1);
		}

		if (!FD_ISSET(ping_sockfd, &read_fds)) {
			fprintf(stdout, "No pongs available within timeframe.\n");
			return;
		}

		ssize_t recv_bytes = recvfrom(
				ping_sockfd, &pkt, sizeof(pkt), 0, pong_addr, &pong_addr_s);
		if (0 == recv_bytes) {
			fprintf(stderr, "Error receiving ICMP packet: %s\n", "Unknown");
			exit(1);
		} else if (0 > recv_bytes) {
			fprintf(stderr, "Error receiving ICMP packet: %s\n", strerror(errno));
			exit(1);
		}

		if (pkt.icmp_ping_pkt.hdr.type != ICMP_ECHOREPLY || pkt.icmp_ping_pkt.hdr.un.echo.id != ping_id) {
			fprintf(stdout, "Recieved ICMP packet, not pong\n");
			continue;
		}

		fprintf(stdout, "Recieved packet:\n");
		print_icmp_packet(pong_addr, recv_bytes, pkt.icmp_ping_pkt);

		struct timespec time_end;
		clock_gettime(CLOCK_MONOTONIC, &time_end);

		struct timeval time_elapsed;
		time_elapsed.tv_sec = time_end.tv_sec - time_start.tv_sec;
		if (time_end.tv_nsec < time_start.tv_nsec) {
			time_elapsed.tv_sec -= 1;
			time_elapsed.tv_usec = ((1000 * 1000 * 1000) + time_end.tv_nsec - time_start.tv_nsec) / 1000;
		} else {
			time_elapsed.tv_usec = (time_end.tv_nsec - time_start.tv_nsec) / 1000;
		}

		if ((timeout.tv_sec < time_elapsed.tv_sec) ||
			(timeout.tv_sec == time_elapsed.tv_sec &&
			 timeout.tv_usec < time_elapsed.tv_usec)) {
			return;
		}

		timeout.tv_sec -= time_elapsed.tv_sec;
		if (timeout.tv_usec < time_elapsed.tv_usec) {
			timeout.tv_sec -= 1;
			timeout.tv_usec += (1000 * 1000);
		}
		timeout.tv_usec -= time_elapsed.tv_usec;

		double timeout_secs = (double)timeout.tv_sec + (double)timeout.tv_usec / (1000.0 * 1000.0);
		fprintf(stdout, "Continuing select loop, remaining time %.03fs\n", timeout_secs);

		usleep(timeout.tv_usec + timeout.tv_sec * (1000 * 1000));
	} while (1);
}

void usage(const char *progname) {
	fprintf(stderr, "Usage: %s [-4|-6] <address> [<hook command>]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "       -4      Interpret <address> as an IPv4 address.\n");
	fprintf(stderr, "       -6      Interpret <address> as an IPv6 address.\n");
}

// Driver Code
int main(int argc, const char *argv[])
{
	int ping_sockfd = -1;
	struct sockaddr *ping_addr;
	size_t ping_addr_s;
	//int addrlen = sizeof(addr_con);
	//char net_buf[NI_MAXHOST];

	const char *progname;
	if (0 < argc)
		progname = argv[0];
	else
		progname = "monitor-ip";

	if (4 != argc) {
		fprintf(stderr, "Incorrect arguments!\n");
		usage(progname);
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
			fprintf(stderr, "Invalid IPv4 address\n");
			return 1;
		} else {
			fprintf(stderr, "Failed to parse IPv4 address: %s\n", strerror(errno));
			return 1;
		}
	} else {
		fprintf(stderr, "Unknown address family!\n");
		usage(progname);
		return 1;
	}

	ping_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (0 > ping_sockfd) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return 0;
	}

	// set socket options at ip to TTL and value to 64,
	int ttl_val = PING_TTL;
	if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
	{
		fprintf(stderr, "Failed setting socket TTL: %s\n", strerror(errno));
		return 0;
	}

	int msg_count = 0;
	do {
		send_ping(msg_count++, ping_sockfd, ping_addr, ping_addr_s);
		receive_pong(ping_sockfd, ping_addr);
	} while (1);

	return 0;
}
