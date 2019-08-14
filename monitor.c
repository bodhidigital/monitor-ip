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

// Triggers monitor notify if missed_cnt exceeds params->missed_max.
void test_monitor_notify_trigger (
		struct monitor_params *params, unsigned long long missed_cnt
) {
	if (params->missed_max > missed_cnt) {
		return;
	}

	fprintf(stdout,
			"Missed pings (%llu) exceeds limit of %llu.\n",
			missed_cnt, params->missed_max);

	if (!params->notify_command) {
		fprintf(stderr, "Warning: no notify command set.\n");
		return;
	}

	char *missed_ping_count_str;
	assert(0 <= asprintf(&missed_ping_count_str, "%llu", missed_cnt));

	pid_t fork_pid = fork();
	if (0 == fork_pid) {
		// Child:
		fprintf(stdout, "Executing monitor notify as PID %d.\n", getpid());
		execlp(params->notify_command, params->notify_command, missed_ping_count_str);
		fprintf(stderr, "Error executing monitor notify: %s.\n", strerror(errno));
		exit(127);
	} else if (0 < fork_pid) {
		// Parent:
		free(missed_ping_count_str);

		if (!params->block) {
			return;
		}

		int child_status;
		fprintf(stdout, "Waiting for child with PID of %d.\n", fork_pid);
		if (-1 >= waitpid(fork_pid, &child_status, 0)) {
			fprintf(stderr, "Failed to wait for child: %s\n", strerror(errno));
			exit(1);
		}

		if (WIFSIGNALED(child_status)) {
			fprintf(stderr,
					"Child terminated by signal: %d (%s)\n", WTERMSIG(child_status),
					strsignal(WTERMSIG(child_status)));
			exit(1);
		} else {
			fprintf(stdout,
					"Child exited with status code: %d\n", WEXITSTATUS(child_status));
		}
	} else {
		// Error:
		fprintf(stderr,
				"Error launching monitor notify child process: %s\n", strerror(errno));
		exit(1);
	}
}
