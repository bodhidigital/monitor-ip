// packet.h

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define icmp_echo_seq un.echo.sequence
#define icmp_echo_id un.echo.id

struct ip_pkt {
	unsigned int version:4;
	int _pad:4;
	char remaining[0];
} __attribute__((packed));

struct ip4_pkt {
	struct iphdr hdr;
	char options_and_data[0];
} __attribute__((packed));