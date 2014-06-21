#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#include <gcrypt.h>

void gcrypt_fatal(gcry_error_t err);
void * secure_malloc(size_t n);
void secure_free(void *p);
void stretch_key(const char *pass, size_t passlen,
		 const uint8_t *salt, uint32_t iter,
		 uint8_t *skey);

#endif
