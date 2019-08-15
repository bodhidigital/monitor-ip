// log.h

#include "features.h"

#include <stdio.h>
#include <stdlib.h>

enum log_level {
	LOG_TRACE = 0,
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARN,
	LOG_ERROR,
	LOG_FATAL,
	LOG_PANIC,
};

#define LOG_LEVEL_MIN (LOG_TRACE)
#define LOG_LEVEL_MAX_INC (LOG_PANIC + 1)

extern enum log_level log_logging_level;

// These functions automatically add a newline.

int log_printf (
		const char *, const char *, unsigned long long, enum log_level, const char *, ...);

#define logf(lvl, fmt, ...) (log_printf(__FILE__, __func__, __LINE__, lvl, fmt, ##__VA_ARGS__))
#define tracef(fmt, ...) (log_printf(__FILE__, __func__, __LINE__, LOG_TRACE, fmt, ##__VA_ARGS__))
#define debugf(fmt, ...) (log_printf(__FILE__, __func__, __LINE__, LOG_DEBUG, fmt, ##__VA_ARGS__))
#define infof(fmt, ...) (log_printf(__FILE__, __func__, __LINE__, LOG_INFO, fmt, ##__VA_ARGS__))
#define warnf(fmt, ...) (log_printf(__FILE__, __func__, __LINE__, LOG_WARN, fmt, ##__VA_ARGS__))
#define errorf(fmt, ...) (log_printf(__FILE__, __func__, __LINE__, LOG_ERROR, fmt, ##__VA_ARGS__))
#define fatalf(fmt, ...) { \
	log_printf(__FILE__, __func__, __LINE__, LOG_FATAL, fmt, ##__VA_ARGS__); \
	exit(1); \
}
#define panicf(fmt, ...) { \
	log_printf(__FILE__, __func__, __LINE__, LOG_PANIC, fmt, ##__VA_ARGS__); \
	abort(); \
}

#define logs(lvl, s) (log_printf(__FILE__, __func__, __LINE__, lvl, "%s", s))
#define traces(s) (log_printf(__FILE__, __func__, __LINE__, LOG_TRACE, "%s", s))
#define debugs(s) (log_printf(__FILE__, __func__, __LINE__, LOG_DEBUG, "%s", s))
#define infos(s) (log_printf(__FILE__, __func__, __LINE__, LOG_INFO, "%s", s))
#define warns(s) (log_printf(__FILE__, __func__, __LINE__, LOG_WARN, "%s", s))
#define errors(s) (log_printf(__FILE__, __func__, __LINE__, LOG_ERROR, "%s", s))
#define fatals(s) { \
	log_printf(__FILE__, __func__, __LINE__, LOG_FATAL, "%s", s); \
	exit(1); \
}
#define panics(s) { \
	log_printf(__FILE__, __func__, __LINE__, LOG_PANIC, "%s", s); \
	abort(); \
}
