// monitor.c

#include "features.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "monitor.h"
#include "packet.h"
#include "log.h"

static void monitor_notify_exec (
		struct monitor_params, unsigned long long, const struct sockaddr *);
static void monitor_notify_exec_set_env (
		unsigned long long, const struct sockaddr *);
static int monitor_notify_proccess_child_status (int);
static char *monitor_format_notify_command (struct monitor_params);

// Returns true if monitor_notify_trigger must be run.
bool monitor_notify_test (
		struct monitor_params *params, unsigned long long missed_cnt
) {
	if (params->missed_max <= missed_cnt) {
		return true;
	} else {
		return false;
	}
}

// Runs the monitor notify command, returns the exit code if command is set and
// configured to block, otherwise 0.  Returns -1 on error and sets errno.
int monitor_notify_trigger (
		struct monitor_params *params, unsigned long long missed_cnt,
		const struct sockaddr *addr
) {
	errorf("Missed pings (%llu) exceeds limit of %llu.",
			missed_cnt, params->missed_max);

	if (!params->notify_command) {
		warns("No notify command set.");
		return 0;
	}

	char *notify_command_str = monitor_format_notify_command(*params);
	infof("Running notify command: %s", notify_command_str);
	free(notify_command_str);

	pid_t fork_pid = fork();
	if (0 == fork_pid) { // Child:
		monitor_notify_exec(*params, missed_cnt, addr);
	} else if (0 < fork_pid) {

		if (!params->block) {
			tracef("Not waiting for notify command to exit: configured to not block.");
			return 0;
		}

		int child_status;
		tracef("Waiting for notify command with PID: %d", fork_pid);
		if (-1 >= waitpid(fork_pid, &child_status, 0))
			panicf("Could not wait(2) for child to exit: %s", strerror(errno));

		return monitor_notify_proccess_child_status(child_status);
	} else {
		// Error:
		panicf("Error running notify command: %s", strerror(errno));
	}

	panics("Control reached end of non-void function?");
}

__attribute__((noreturn))
static void monitor_notify_exec (
		struct monitor_params params, unsigned long long missed_cnt,
		const struct sockaddr *addr
) {
	tracef("Executing notify command with PID: %d", getpid());

	monitor_notify_exec_set_env(missed_cnt, addr);

	execvp(params.notify_command, params.notify_command_arguments);
	errorf("Could not executing notify command: %s", strerror(errno));
	exit(127);
}

static void monitor_notify_exec_set_env (
		unsigned long long missed_cnt, const struct sockaddr *addr
) {
	char *missed_ping_count_str;
	if (0 > asprintf(&missed_ping_count_str, "%llu", missed_cnt))
		panics("Failed to allocate missed poing count string to execute notify "
			   "command.");

	char *addr_str = packet_format_address(addr);
	if (!addr_str)
		fatalf("Failed to format socket address: %s", strerror(errno));

	setenv("MONITOR_NOTIFY_MISSED_PING_COUNT", missed_ping_count_str, 1);
	setenv("MONITOR_NOTIFY_REMOTE_ADDRESS", addr_str, 1);

	free(missed_ping_count_str);

	debugf("Executing notify command with environment:\n"
		   "\tMONITOR_NOTIFY_MISSED_PING_COUNT=%s\n"
		   "\tMONITOR_NOTIFY_REMOTE_ADDRESS=%s",
		   getenv("MONITOR_NOTIFY_MISSED_PING_COUNT"),
		   getenv("MONITOR_NOTIFY_REMOTE_ADDRESS"));
}

static int monitor_notify_proccess_child_status (int child_status) {
	if (WIFSIGNALED(child_status)) {
		warnf("Notify command terminated by signal: %d (%s)",
				WTERMSIG(child_status), strsignal(WTERMSIG(child_status)));
		return 128 + WTERMSIG(child_status);
	} else {
		debugf("Notify command exited with code: %d",
				WEXITSTATUS(child_status));

		if (0 == WEXITSTATUS(child_status)) {
			infos("Notify command executed successfuly.");
			return 0;
		} else if (127 == WEXITSTATUS(child_status)) {
			errors("Notify command does not exist, or can not be executed.");
			errno = ENOENT;
			return -1;
		} else {
			warnf("Notify failed with status code: %d", WEXITSTATUS(child_status));
			// Get ABS of possible negative exit status.
			int exit_status = WEXITSTATUS(child_status);
			if (exit_status < 0)
				exit_status *= -1;

			return exit_status;
		}
	}
}

static char *monitor_format_notify_command (struct monitor_params params) {
	char *notify_command_str = NULL;
	size_t notify_command_str_s = 0;
	for (size_t i = 0; params.notify_command_arguments[i]; ++i) {
		char *arg = params.notify_command_arguments[i];
		size_t arg_s = strlen(arg) + 1;

		bool write_space = false;
		if (notify_command_str_s != 0) {
			notify_command_str_s += 1;
			write_space = true;
		}
		notify_command_str_s += arg_s;

		char *new_notify_command_str = realloc(
				notify_command_str, notify_command_str_s);
		if (!new_notify_command_str)
			panics("Failed to allocate or extend notify command string.");

		notify_command_str = new_notify_command_str;

		if (write_space)
			strcat(notify_command_str, " ");

		strcat(notify_command_str, arg);
	}

	return notify_command_str;
}
