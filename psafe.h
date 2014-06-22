#ifndef PSAFE_H
#define PSAFE_H

#include <gcrypt.h>
#include <inttypes.h>

#include "psafe_const.h"

enum {
	READ_OK,
	READ_END
};

struct field {
	struct field *prev, *next;
	uint8_t type;
	uint32_t len;
	char data[];
};

struct record {
	struct record *prev, *next;
	struct field *first, *last;
};

struct safeio {
	FILE *file;
	gcry_cipher_hd_t cipher;
	gcry_md_hd_t hmac;
};

struct safe {
	uint8_t salt[SALT_SIZE];
	uint32_t iter;
	uint8_t hash_p_prime[32];
	uint8_t b[4][16];
	uint8_t iv[16];

	uint8_t p_prime[32];	/* stretched pass phrase */
	uint8_t rand_k[32];	/* key to decrypt the database */
	uint8_t rand_l[32];	/* key to calculate hmac */

	struct field *hdr_first, *hdr_last;
	struct record *rec_first, *rec_last;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#endif
