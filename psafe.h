#ifndef PSAFE_H
#define PSAFE_H

#include <gcrypt.h>
#include <inttypes.h>

#define BLK_SIZE 16
#define FLD_HDR_SIZE 5
#define SALT_SIZE 32
#define STRETCHED_KEY_SIZE 32

enum {
	READ_OK,
	READ_END
};

struct field {
	uint8_t type;
	uint32_t len;
	char data[];
};

struct safeio {
	FILE *file;
	gcry_cipher_hd_t cipher;
	gcry_md_hd_t hmac;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#endif
