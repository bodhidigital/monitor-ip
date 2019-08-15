// monitor.c

#include "features.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "monitor.h"
#include "log.h"

// TODO: pass address
// Triggers monitor notify if missed_cnt exceeds params->missed_max.
void test_monitor_notify_trigger (
		struct monitor_params *params, unsigned long long missed_cnt
) {
	if (params->missed_max > missed_cnt) {
		return;
	}

	errorf("Missed pings (%llu) exceeds limit of %llu.",
			missed_cnt, params->missed_max);

	if (!params->notify_command) {
		warns("No notify command set.");
		return;
	}

	char *missed_ping_count_str;
	if (0 > asprintf(&missed_ping_count_str, "%llu", missed_cnt))
		panics("Failed to allocate missed poing count string to execute notify "
			   "command.");

	infof("Running notify command: %s %s",
			params->notify_command, missed_ping_count_str);

	pid_t fork_pid = fork();
	if (0 == fork_pid) {
		// Child:
		tracef("Executing notify command with PID: %d", getpid());

		execlp(params->notify_command,
				params->notify_command, missed_ping_count_str, NULL);
		errorf("Could not executing notify command: %s", strerror(errno));
		exit(127);
	} else if (0 < fork_pid) {
		// Parent:
		free(missed_ping_count_str);

		if (!params->block) {
			tracef("Not waiting for notify command to exit: configured to not block.");
			return;
		}

		int child_status;
		tracef("Waiting for notify command with PID: %d", fork_pid);
		if (-1 >= waitpid(fork_pid, &child_status, 0))
			panicf("Could not wait(2) for child to exit: %s", strerror(errno));

		if (WIFSIGNALED(child_status))
			warnf("Notify command terminated by signal: %d (%s)",
					WTERMSIG(child_status), strsignal(WTERMSIG(child_status)));
		else
			infof("Notify command exited with status code: %d", WEXITSTATUS(child_status));
	} else {
		// Error:
		panicf("Error running notify command: %s", strerror(errno));
	}
}
