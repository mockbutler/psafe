/* Copyright 2013-2015 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */
#include <assert.h>

#include "sha256.h"

#include "internals.h"

void sha256_init(struct sha256_state *state)
{
	int i;
	for (i = 0; i < 16; i++)
		state->W[i] = H[i];
	memset(&state->buf, 0, sizeof(state->buf));
	state->buflen = 0;
	state->bitlen = 0;
}

void sha256_update(struct sha256_state *state, void *in, size_t inlen)
{
	while (inlen > 0) {
		size_t n = fill(state, (uint8_t**)&in, &inlen);
		state->buflen += n;
		state->bitlen += n * 8;
		if (state->buflen == 64)
			compute_hash(state);
	}
}

void sha256_finalize(struct sha256_state *state, uint8_t hash[64])
{
	if (rem(state) > 8) {
		append(state, 0x80);
		pad_zero(state, rem(state) - 8);
		append_size(state);
		compute_hash(state);
		extract_hash(state, hash);
	} else {
		append(state, 0x80);
		pad_zero(state, rem(state));
		compute_hash(state);
		pad_zero(state, rem(state) - 8);
		append_size(state);
		compute_hash(state);
		extract_hash(state, hash);
	}
}
