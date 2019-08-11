// record.h

#include "features.h"

#include <stdint.h>
#include <glib.h>

struct ping_record {
	struct timespec timeout;
	unsigned long long int missed_cnt;
	GList *l;
};

struct ping_record_entry {
	uint16_t sequence;
	struct timespec time_sent;
	unsigned short pong_cnt;
};

struct ping_record *ping_record_init (struct timespec *);
void ping_record_free (struct ping_record *);
void ping_record_submit (struct ping_record *, struct ping_record_entry *);
unsigned short ping_record_update_pong (struct ping_record *, uint16_t);
void ping_record_collect_expired (struct ping_record *, struct timespec *);
