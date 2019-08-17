// packet.h

#include "features.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <alloca.h>

#define icmp_echo_seq un.echo.sequence
#define icmp_echo_id un.echo.id

struct ip4_pkt {
	struct iphdr hdr;
	char options_and_data[0];
} __attribute__((packed));

char *asprint_icmphdr (const struct sockaddr *, ssize_t, struct icmphdr);
void *get_ip4_payload (void *, size_t, uint8_t *, size_t *);
void packet_icmp6hdr_compat (const struct icmp6_hdr *, struct icmphdr *);

__attribute__((__always_inline__))
static inline char *packet_format_address (const struct sockaddr *addr) {
	const void *addr_data;
	size_t addr_str_s;
	if (addr->sa_family == AF_INET) {
		// four octets as three decimal digits, three dots, null byte.
		addr_str_s = 4 * 3 + 3 + 1;  // 16
		addr_data = &((struct sockaddr_in *)addr)->sin_addr;
	} else {
		// eight octet-pairs as four hexadecimal digits, seven colons, null byte.
		addr_str_s = 8 * 4 + 7 + 1;  // 40
		addr_data = &((struct sockaddr_in6 *)addr)->sin6_addr;
	}

	char *addr_str;
	addr_str = (char *)alloca(addr_str_s);

	if (!inet_ntop(addr->sa_family, addr_data, addr_str, addr_str_s))
		return NULL;

	return addr_str;
}
