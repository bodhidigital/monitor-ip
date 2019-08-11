// packet.h

#include "features.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define icmp_echo_seq un.echo.sequence
#define icmp_echo_id un.echo.id

struct ip4_pkt {
	struct iphdr hdr;
	char options_and_data[0];
} __attribute__((packed));

void print_icmphdr (const struct sockaddr *, ssize_t, struct icmphdr);
void *get_ip4_payload (void *, size_t, uint8_t *, size_t *);
