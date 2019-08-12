// monitor.h

#include "features.h"

#include <stdbool.h>

struct monitor_params {
	unsigned long long missed_max;
	bool block;
	const char *notify_command;
};

void test_monitor_notify_trigger (struct monitor_params *, unsigned long long);
