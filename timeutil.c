// timeutil.c

#include "features.h"

#include <sys/time.h>
#include <time.h>

#include "timeutil.h"

void timespec2val (const struct timespec *ts, struct timeval *tv) {
	*tv = (struct timeval){
		.tv_sec = ts->tv_sec,
		.tv_usec = ts->tv_nsec / 1000
	};
}

void useconds2timespec (suseconds_t us, struct timespec *t) {
	*t = (struct timespec){
		.tv_sec = us / (1000 * 1000),
		.tv_nsec = 1000 * (us % (1000 * 1000))
	};
}

double timespec2double (const struct timespec *t) {
	return (double)t->tv_sec + (double)t->tv_nsec / (1000.0 * 1000.0 * 1000.0);
}

void timespec_diff (
		const struct timespec *start, const struct timespec *end,
		struct timespec *diff
) {
	diff->tv_sec = end->tv_sec - start->tv_sec;
	if (end->tv_nsec < start->tv_nsec) {
		diff->tv_sec -= 1;
		diff->tv_nsec = (1000 * 1000 * 1000) + end->tv_nsec - start->tv_nsec;
	} else {
		diff->tv_nsec = end->tv_nsec - start->tv_nsec;
	}
}

int cmp_timespec (const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec > b->tv_sec ||
			(a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec)) {
		return 1;
	} else if (a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec) {
		return 0;
	} else {
		return -1;
	}
}
