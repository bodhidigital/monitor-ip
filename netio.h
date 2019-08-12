// netio.h

#include "features.h"

#include <sys/time.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct netio_params {
	size_t msg_s;
	uint16_t id;
};

struct netio_pong {
	uint16_t seq;
	struct timespec time_recv;
};

void netio_send (
		const struct netio_params *, int, const struct sockaddr *, uint16_t,
		struct ping_record_entry *);
size_t netio_receive (
		struct netio_params *, int, const struct sockaddr *,
		const struct timespec *, struct netio_pong **);
