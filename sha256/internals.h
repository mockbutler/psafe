#ifndef INTERNALS_H
#define INTERNALS_H

#include <string.h>

#ifndef TEST
#define STATIC static
#else
#define STATIC
#endif

STATIC const uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

STATIC const uint32_t H[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* circular rotate right */
STATIC uint32_t rotr(uint32_t a, int n)
{
	return (a >> n) | (a << (32-n));
}

/* shift right */
#define shr(a, n) ((a) >> (n))

STATIC uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (~x & z);
}

STATIC uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

STATIC uint32_t SIG0(uint32_t x)
{
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

STATIC uint32_t SIG1(uint32_t x)
{
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

STATIC uint32_t sig0(uint32_t x)
{
	return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

STATIC uint32_t sig1(uint32_t x)
{
	return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

STATIC uint32_t be32h(uint8_t *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

STATIC void decompose_block(struct sha256_state *state, uint32_t M[64])
{
	int i;
	for (i = 0; i<16; i++) {
		M[i] = be32h(&state->buf[i*4]);
	}
	for (; i<64; i++) {
		M[i] = sig1(M[i-2]) + M[i-7] + sig0(M[i-15]) + M[i-16];
	}
}

STATIC void compute_hash(struct sha256_state *state)
{
	assert(state != NULL);
	assert(state->buflen == 64);

	uint32_t M[64];
	decompose_block(state, M);

	uint32_t a = state->W[0];
	uint32_t b = state->W[1];
	uint32_t c = state->W[2];
	uint32_t d = state->W[3];
	uint32_t e = state->W[4];
	uint32_t f = state->W[5];
	uint32_t g = state->W[6];
	uint32_t h = state->W[7];

	int i;
	uint32_t T1, T2;
	for (i=0; i<64; i++) {
		T1 = h + SIG1(e) + Ch(e, f, g) + K[i] + M[i];
		T2 = SIG0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	state->W[0] += a;
	state->W[1] += b;
	state->W[2] += c;
	state->W[3] += d;
	state->W[4] += e;
	state->W[5] += f;
	state->W[6] += g;
	state->W[7] += h;

	/* buffer has been consumed */
	state->buflen = 0;
}

STATIC size_t rem(struct sha256_state *state)
{
	return 64 - state->buflen;
}

STATIC size_t fill(struct sha256_state *state, uint8_t **in, size_t *inlen)
{
	size_t spare = rem(state);
	size_t n = (*inlen < spare) ? *inlen : spare;
	memcpy(&state->buf[state->buflen], *in, n);
	*in += n;
	*inlen -= n;
	return n;
}

STATIC void append(struct sha256_state *state, uint8_t b)
{
	assert(rem(state)>0);
	state->buf[state->buflen++] = b;
}

STATIC void pad_zero(struct sha256_state *state, size_t cnt)
{
	while (cnt-- > 0)
		state->buf[state->buflen++] = 0;
}

STATIC void append_size(struct sha256_state *state)
{
	state->buf[56] = state->bitlen >> 56;
	state->buf[57] = state->bitlen >> 48;
	state->buf[58] = state->bitlen >> 40;
	state->buf[59] = state->bitlen >> 32;
	state->buf[60] = state->bitlen >> 24;
	state->buf[61] = state->bitlen >> 16;
	state->buf[62] = state->bitlen >> 8;
	state->buf[63] = state->bitlen;
	state->buflen += 8;
}

STATIC void extract_hash(struct sha256_state *state, uint8_t *hash)
{
	int i;
	for (i = 0; i < 32; i++)
		hash[i] = state->W[i/4] >> (24 - 8 * (i%4));
}

#endif
