// log.c

#include "features.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <alloca.h>

#include "log.h"

#define PAD_FUNC_LEN (31)
#define PAD_FILE_LEN (10)
#define PAD_LINE_LEN (3)

struct log_lvl_name_pair {
	enum log_level value;
	const char *name;
};

enum log_level log_logging_level = LOG_INFO;

static size_t log_lvl_name_max;
static const struct log_lvl_name_pair log_lvl_names[] = {
	{ LOG_TRACE, "TRACE" },
	{ LOG_DEBUG, "DEBUG" },
	{ LOG_INFO,  "INFO"  },
	{ LOG_WARN,  "WARN"  },
	{ LOG_ERROR, "ERROR" },
	{ LOG_FATAL, "FATAL" },
	{ LOG_PANIC, "PANIC" }
};

static const char *log_get_lvl_name (enum log_level);

__attribute__((constructor))
void log_set_lvl_name_max_strlen () {
	size_t n_lvls = sizeof(log_lvl_names) / sizeof(struct log_lvl_name_pair);
	size_t max = 0;
	for (size_t i = 0; n_lvls > i; ++i) {
		size_t len = strlen(log_lvl_names[i].name);
		if (max < len)
			max = len;
	}

	log_lvl_name_max = max;
}

__attribute__((__always_inline__))
static inline char *log_trunc_str (const char *s, size_t l) {
	char *s_trunc = alloca(l <= strlen(s) ? l + 1 : strlen(s));
	strncpy(s_trunc, s, l);
	bzero(&s_trunc[l], 1);  // Ensure null terminates truncated src.
	return s_trunc;
}

__attribute__((__always_inline__))
static inline char *log_get_pad (char const *s, size_t l) {
	size_t s_pad_s = l >= strlen(s) ? l - strlen(s) : 0;
	char *s_pad = alloca(s_pad_s + 1);
	memset(s_pad, ' ', s_pad_s);
	bzero(&s_pad[s_pad_s], 1);
	return s_pad;
}

int log_printf (
		const char *src, const char *func, unsigned long long line,
		enum log_level lvl, const char *fmt, ...
) {
	if (lvl < log_logging_level)
		return 0;

	const char *lvl_name = log_get_lvl_name(lvl);

	char *lvl_name_pad = log_get_pad(lvl_name, log_lvl_name_max);

	int result = fprintf(stderr,
			"%s%s (%s:%llu %s): ", lvl_name, lvl_name_pad, src, line, func);

	va_list ap, aq;
	va_start(ap, fmt);
	va_copy(aq, ap);

	result += vfprintf(stderr, fmt, ap);

	va_end(aq);

	result += fprintf(stderr, "\n");

	return result;
}

static const char *log_get_lvl_name (enum log_level lvl) {
	size_t n_lvls = sizeof(log_lvl_names) / sizeof(struct log_lvl_name_pair);

	for (size_t i = 0; n_lvls > i; ++i)
		if (lvl == log_lvl_names[i].value)
			return log_lvl_names[i].name;

	// Don't call panicf to avoid possible recursive loop.
	assert(!"Unknown log level passed, no matching name!");
}
