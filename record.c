// record.c

#include "features.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <glib.h>
#include <gmodule.h>

#include "timeutil.h"
#include "record.h"

static void ping_record_destroy_notify (gpointer data);
static gint ping_record_compare_to_sequence (gconstpointer, gconstpointer);

struct ping_record *ping_record_init (struct timespec *timeout) {
	struct ping_record *ping_record = malloc(sizeof(struct ping_record));
	assert(ping_record);

	*ping_record = (struct ping_record){
		.timeout = *timeout,
		.missed_cnt = 0,
		.l = NULL // NULL is a perfectly valid GList.
	};

	return ping_record;
}

void ping_record_free (struct ping_record *ping_record) {
	g_list_free_full(ping_record->l, ping_record_destroy_notify);
	free(ping_record);
}

void ping_record_submit (
		struct ping_record *ping_record, struct ping_record_entry *ping_record_entry
) {
	struct ping_record_entry *entry_data = malloc(sizeof(struct ping_record_entry));
	assert(entry_data);
	*entry_data = *ping_record_entry;

	ping_record->l = g_list_append(ping_record->l, entry_data);
}

// Returns current number of received pings, or 0 if no matching pong exists.
bool ping_record_update_pong (
		struct ping_record *ping_record, uint16_t sequence,
		struct ping_record_entry *entry_data_out
) {
	GList *matching_entry_node = g_list_find_custom(
			ping_record->l, &sequence, ping_record_compare_to_sequence);
	if (!matching_entry_node)
		return false;

	struct ping_record_entry *entry_data = matching_entry_node->data;
	entry_data->pong_cnt += 1;

	assert(sequence == entry_data->sequence);
	*entry_data_out = *entry_data;
	return true;
}

// Time t should be created *before* the last receive_pong call.
void ping_record_collect_expired (struct ping_record *ping_record, struct timespec *t) {
	for (GList *node = ping_record->l; node != NULL; node = node->next) {
		struct ping_record_entry *entry_data = (struct ping_record_entry *)node->data;

		// t - sent_ping->time_sent
		struct timespec time_expiration;
		timespec_add(&entry_data->time_sent, &ping_record->timeout, &time_expiration);

		// t >= time_expiration
		if (-1 < cmp_timespec(t, &time_expiration)) {
			if (!entry_data->pong_cnt) {
				ping_record->missed_cnt += 1;
				fprintf(stdout,
						"No pong received after %.03fs for ping with sequence number %hu.\n",
						timespec2double(&ping_record->timeout), entry_data->sequence);
				fprintf(stdout,
						"Consecuritve missed pings %llu.\n", ping_record->missed_cnt);
			} else {
				ping_record->missed_cnt = 0;
				fprintf(stdout, "Reset missed pings.\n");
			}

			ping_record->l = g_list_remove_link(ping_record->l, node);
			ping_record_destroy_notify(node->data);
			g_list_free_1(node);
		} else {
			// Using CLOCK_MONOTONIC, ping sequences will always have time in order.
			// Thus after we've found the first ping that has yet to expire ...
			return;
		}
	}
}

static void ping_record_destroy_notify (gpointer data) {
	free(data);
}

static gint ping_record_compare_to_sequence (
		gconstpointer ping_record_entry_data_p, gconstpointer sequence_p
) {
	const struct ping_record_entry *entry_data = ping_record_entry_data_p;
	const uint16_t *sequence = sequence_p;

	if (entry_data->sequence < *sequence)
		return -1;
	else if (entry_data->sequence == *sequence)
		return 0;
	else
		return 1;
}
