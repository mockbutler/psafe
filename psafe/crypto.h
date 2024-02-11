#ifndef CRYPTO_H
#define CRYPTO_H

#include <gcrypt.h>

/* Deprecate / rename. */
void gcrypt_fatal(gcry_error_t err);

void crypto_init(size_t secmem_pool_size);
void crypto_term(void);

#endif
