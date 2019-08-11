// timeutil.h

#include "features.h"

#include <sys/time.h>
#include <time.h>

void timespec2val (const struct timespec *, struct timeval *);
void useconds2timespec (suseconds_t, struct timespec *);
double timespec2double (const struct timespec *);
void timespec_diff (const struct timespec *, const struct timespec *,
		struct timespec *);
int cmp_timespec (const struct timespec *, const struct timespec *);
