// monitor.h

#include "features.h"

#include <sys/socket.h>
#include <stdbool.h>

struct monitor_params {
	unsigned long long missed_max;
	bool block;
	const char *notify_command;
	char *const *notify_command_arguments;
};

bool monitor_notify_test (struct monitor_params *, unsigned long long);
int monitor_notify_trigger (
		struct monitor_params *, unsigned long long, const struct sockaddr *);
