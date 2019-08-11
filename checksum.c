// checksum.c

#include <stdint.h>

#include "checksum.h"

uint16_t checksum16_1s_complement (const void *b, uint16_t len) {
	uint16_t *b16 = (uint16_t *)b;

	// Using uint32_t prevents overflow, allowing us to emulate it.
	uint32_t sum = 0;
	while (1 < len) {
		sum += *b16++;
		len -= 2;  // 2 == sizeof(uint16_t)
	}

	if (len == 1) {
		sum += *(uint8_t*)b16;
		len = 0;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	uint16_t result = (uint16_t)~sum;
	return result;
}
