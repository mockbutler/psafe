#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>

struct sha256_state {
	uint32_t W[8];
	uint8_t buf[64];
	size_t buflen;
	uint64_t bitlen;
};

void sha256_init(struct sha256_state *state);
void sha256_update(struct sha256_state *state,
		   const void *in, size_t inlen);
void sha256_finalize(struct sha256_state *state, uint8_t h[64]);

#endif
