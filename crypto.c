#include <err.h>
#include <stdio.h>
#include <wchar.h>

#include "crypto.h"

#include "psafe_const.h"

void gcrypt_fatal(gcry_error_t err)
{
	fwprintf(stderr, L"gcrypt error %s/%s\n",
		 gcry_strsource(err), gcry_strerror(err));
	exit(EXIT_FAILURE);
}

void * secure_malloc(size_t n)
{
	void *p = gcry_malloc_secure(n);
	if (p == NULL)
		errx(1, "exhausted secure memory allocating %zu bytes", n);
	return p;
}

void secure_free(void *p)
{
	gcry_free(p);
}

/* Ref: 3.1
 *
 * Note: the skey input buffer must have capacity of at least
 * STRETCHED_KEY_SIZE bytes.
 */
void stretch_key(const char *pass, size_t passlen,
		 const uint8_t *salt, uint32_t iter,
		 uint8_t *skey)
{
  gcry_error_t gerr;
  gcry_md_hd_t sha256;
  gerr = gcry_md_open(&sha256, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
  if (gerr != GPG_ERR_NO_ERROR)
    gcrypt_fatal(gerr);

  gcry_md_write(sha256, pass, passlen);
  gcry_md_write(sha256, salt, SALT_SIZE);
  gcry_md_final(sha256);
  memmove(skey, gcry_md_read(sha256, 0), STRETCHED_KEY_SIZE);

  while (iter-- > 0) {
    gcry_md_reset(sha256);
    gcry_md_write(sha256, skey, STRETCHED_KEY_SIZE);
    gcry_md_final(sha256);
    memmove(skey, gcry_md_read(sha256, 0), STRETCHED_KEY_SIZE);
  }
  gcry_md_close(sha256);
}
