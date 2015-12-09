/* Copyright 2013-2015 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */
#include <assert.h>
#include <stdlib.h>

#include "sha256.h"
#define TEST
#include "internals.h"

int main(int argc, char **argv)
{
	assert(rotr(1, 1) == 0x80000000);
	assert(rotr(0x80000000, 31) == 1);
	assert(rotr(0x80000000, 32) == 0x80000000);
	assert(rotr(0x80, 7) == 1);

	assert(shr(1, 1) == 0);
	assert(shr(0x80, 7) == 1);

	uint8_t b1[] = { 1, 0, 0, 0 };
	assert(be32h(b1) == 0x01000000);
	uint8_t b2[] = { 7, 8, 9, 0 };
	assert(be32h(b2) == 0x07080900 );

	struct sha256_state sha256;
	sha256_init(&sha256);
	char test[] = { 0x61, 0x62, 0x63 };
	sha256_update(&sha256, test, 3);
	uint8_t hash[32];
	sha256_finalize(&sha256, hash);

	static const uint8_t testvec[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	assert(memcmp(hash, testvec, sizeof(testvec)) == 0);

	sha256_init(&sha256);
	char *test2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	sha256_update(&sha256, test2, strlen(test2));
	sha256_finalize(&sha256, hash);

	static const uint8_t testvec2[] = {
		0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
	};
	assert(memcmp(hash, testvec2, sizeof(testvec2)) == 0);

	return 0;
}
