/* Copyright 2013-2015 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */

#include <assert.h>
#include <err.h>
#include <gcrypt.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "mapfile.h"
#include "psafe.h"

#define TWOF_BLKSIZE 16		/* Twofish cipher block size bytes. */
#define SHA256_SIZE 32		/* SHA-256 size in bytes. */

void gcrypt_fatal(gcry_error_t err)
{
	fwprintf(stderr, L"gcrypt error %s/%s\n",
		 gcry_strsource(err), gcry_strerror(err));
	exit(EXIT_FAILURE);
}

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
	gcry_md_write(sha256, salt, 32);
	memmove(skey, gcry_md_read(sha256, 0), 32);

	while (iter-- > 0) {
		gcry_md_reset(sha256);
		gcry_md_write(sha256, skey, 32);
		memmove(skey, gcry_md_read(sha256, 0), 32);
	}
	gcry_md_close(sha256);
}

void sha256_block32(const uint8_t *in, uint8_t *out)
{
	gcry_md_hd_t hd;
	gcry_error_t gerr;
	gerr = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gcry_md_write(hd, in, 32);
	gcry_md_final(hd);
	memmove(out, gcry_md_read(hd, 0), 32);
	gcry_md_close(hd);
}

void extract_random_key(const uint8_t *stretchkey,
			const uint8_t *fst, const uint8_t *snd,
			uint8_t *randkey)
{
	gcry_error_t gerr;
	gcry_cipher_hd_t hd;
	gerr = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH,
				GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gerr = gcry_cipher_setkey(hd, stretchkey, 32);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gcry_cipher_decrypt(hd, randkey, 16, fst, 16);
	gcry_cipher_reset(hd);
	gcry_cipher_decrypt(hd, randkey + 16, 16, snd, 16);
	gcry_cipher_close(hd);
}

void print_time(uint8_t *val)
{
	struct tm lt;
	time_t time;
	time = val[0] | val[1] << 8 | val[2] << 16 | val[3] << 24;
	gmtime_r(&time, &lt);
	wprintf(L"%d-%d-%d %02d:%02d:%02d",
		1900 + lt.tm_year, lt.tm_mon, lt.tm_mday,
		lt.tm_hour, lt.tm_min, lt.tm_sec);
}

void printhex(FILE *f, uint8_t *ptr, unsigned cnt)
{
	unsigned i;
	for (i = 0; i < cnt; i++)
		fwprintf(f, L"%02x", *ptr++);
}

void print_uuid(uint8_t *uuid)
{
	printhex(stdout, uuid, 4);
	putwc('-', stdout);
	printhex(stdout, uuid + 4, 2);
	putwc('-', stdout);
	printhex(stdout, uuid + 6, 2);
	putwc('-', stdout);
	printhex(stdout, uuid + 8, 2);
	putwc('-', stdout);
	printhex(stdout, uuid + 10, 6);
}

/* Print out utf-8 string. */
void pws(FILE *f, uint8_t *bp, size_t len)
{
    mbstate_t state;
    memset(&state, 0, sizeof(state));
    wchar_t *tmp;
    tmp = malloc((len + 1) * sizeof(wchar_t));
    size_t n;
    const char *ptr = (const char *)bp;
    n = mbsnrtowcs(tmp, &ptr, len, len, &state);
    tmp[n] = L'\0';
    fputws(tmp, stdout);
    free(tmp);
}

void hd_print(FILE *f, struct field *fld)
{
	switch (fld->type) {
	case 0x2 ... 0x3:
	case 0x5 ... 0xb:
	case 0xf ... 0x11:
		pws(f, fld->val, fld->len);
		break;
	case 0x1:
		print_uuid(fld->val);
		break;
	case 0x4:
		print_time(fld->val);
		break;
	}
}

void db_print(FILE *f, struct field *fld)
{

	switch (fld->type) {
	case 0x2 ... 0x6:
	case 0xd ... 0x10:
	case 0x14: case 0x16:
		pws(f, fld->val, fld->len);
		break;
	case 0x7 ... 0xa:
	case 0xc:
		print_time(fld->val);
		break;
	case 0x1:
		print_uuid(fld->val);
		break;
	}
}

int init_decrypt_ctx(struct decrypt_ctx *ctx, struct psafe3_pro *pro,
		     struct safe_sec *sec)
{
	gcry_error_t gerr;

	assert(ctx != NULL);
	assert(pro != NULL);
	assert(sec != NULL);

	gerr = gcry_cipher_open(&ctx->cipher, GCRY_CIPHER_TWOFISH,
				GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (gerr != GPG_ERR_NO_ERROR) goto err_cipher;

	ctx->gerr = gcry_cipher_setkey(ctx->cipher, sec->rand_k, 32);
	if (gerr != GPG_ERR_NO_ERROR) goto err_cipher;

	ctx->gerr = gcry_cipher_setiv(ctx->cipher, pro->iv, 16);
	if (gerr != GPG_ERR_NO_ERROR) goto err_cipher;

	gerr = gcry_md_open(&ctx->hmac, GCRY_MD_SHA256,
			    GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC);
	if (gerr != GPG_ERR_NO_ERROR) goto err_hmac;

	gerr = gcry_md_setkey(ctx->hmac, sec->rand_l, 32);
	if (gerr != GPG_ERR_NO_ERROR) goto err_hmac;

	return 0;

err_hmac:
	gcry_cipher_close(ctx->cipher);
err_cipher:
	ctx->gerr = gerr;
	return -1;
}

void term_decrypt_ctx(struct decrypt_ctx *ctx)
{
	gcry_cipher_close(ctx->cipher);
	gcry_md_close(ctx->hmac);
}

void print_prologue(FILE *f, struct psafe3_pro *pro)
{
	int i;
#define EOL() fputwc('\n', f)
	fputws(L"SALT   ", f); printhex(f, pro->salt, 32); EOL();
	fwprintf(f, L"ITER   %u\n", pro->iter);
	fputws(L"H(P')  ", f); printhex(f, pro->h_pprime, 32); EOL();
	for (i = 0; i < 4; i++) {
		fwprintf(f, L"B%d     ", i);
		printhex(f, pro->b[i], 16); EOL();
	}
	fputws(L"IV     ", f); printhex(f, pro->iv, 16); EOL();
#undef EOL
}

void * map_header(struct field **hdr, size_t *hdr_fcnt, uint8_t *raw, size_t rawsize)
{
	uint8_t *ptr;
	size_t i, fcnt;
	struct field *fld;

	for (ptr = raw, fcnt = 0; ptr < raw + rawsize; ptr += TWOF_BLKSIZE) {
		fld = (struct field *) ptr;
		fcnt++;
		if (fld->type == 0xff)
			break;
	}

	*hdr = malloc(sizeof(struct field *) * fcnt);
	for (ptr = raw, i = 0; ptr < raw + rawsize; ptr += TWOF_BLKSIZE) {
		hdr[i++] = (struct field *) ptr;
		if (fld->type == 0xff)
			break;
	}
	*hdr_fcnt = fcnt;

	return fld + TWOF_BLKSIZE;
}

int stretch_and_check_pass(const char *pass, size_t passlen,
			   struct psafe3_pro *pro, struct safe_sec *sec)
{
	stretch_key(pass, passlen, pro->salt, pro->iter, sec->pprime);
	uint8_t hkey[32];
	sha256_block32(sec->pprime, hkey);
	if (memcmp(pro->h_pprime, hkey, 32) != 0)
		return -1;
	extract_random_key(sec->pprime, pro->b[0], pro->b[1], sec->rand_k);
	extract_random_key(sec->pprime, pro->b[2], pro->b[3], sec->rand_l);
	return 0;
}

void init_crypto(size_t secmem_pool_size)
{
	gcry_error_t gerr;
	if (!gcry_check_version(GCRYPT_VERSION)) {
		fputws(L"Fatal libgcrypt version mismatch.\n", stdout);
		exit(EXIT_FAILURE);
	}

	/* Create a pool of secure memory. */
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gerr = gcry_control(GCRYCTL_INIT_SECMEM, secmem_pool_size, 0);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
}

int main(int argc, char **argv)
{
	int ret;
	setlocale(LC_ALL, "");

	if (argc != 3) {
		wprintf(L"Usage: psafe file.psafe3 passphrase");
		exit(EXIT_FAILURE);
	}

	init_crypto(64*1024);

	size_t sz;
	uint8_t *ptr;
	ptr = mapfile_ro(argv[1], &sz);
	if (ptr == NULL)
		err(1, "%s", argv[1]);

	struct psafe3_pro *pro;
	pro = (struct psafe3_pro *)(ptr + 4);
	struct safe_sec *sec;
	sec = gcry_malloc_secure(sizeof(*sec));
	ret = stretch_and_check_pass(argv[2], strlen(argv[2]), pro, sec);
	if (ret != 0) {
		gcry_free(sec);
		wprintf(L"Invalid password.\n");
		exit(1);
	}

	uint8_t *safe;
	size_t safe_size;
	safe_size = sz - (4 + sizeof(*pro) + 48);
	assert(safe_size > 0);
	assert(safe_size % TWOF_BLKSIZE == 0);
	safe = gcry_malloc_secure(safe_size);
	assert(safe != NULL);

	gcry_error_t gerr;
	struct decrypt_ctx ctx;
	if (init_decrypt_ctx(&ctx, pro, sec) < 0)
		gcrypt_fatal(ctx.gerr);

	size_t bcnt;
	bcnt = safe_size / TWOF_BLKSIZE;
	assert(bcnt > 0);
	uint8_t *encp;
	uint8_t *safep;
	encp = ptr + 4 + sizeof(*pro);
	safep = safe;
	while (bcnt--) {
		gerr = gcry_cipher_decrypt(ctx.cipher, safep, TWOF_BLKSIZE, encp, TWOF_BLKSIZE);
		if (gerr != GPG_ERR_NO_ERROR)
			gcrypt_fatal(gerr);
		safep += TWOF_BLKSIZE;
		encp += TWOF_BLKSIZE;
	}

	enum { HDR, DB };
	int state = HDR;
	safep = safe;
	while (safep < safe + safe_size) {
		struct field *fld;
		fld = (struct field *)safep;
		wprintf(L"len=%-3u  type=%02x  ", fld->len, fld->type);
		if (state == DB)
			db_print(stdout, fld);
		else
			hd_print(stdout, fld);
		if (fld->type == 0xff)
			state = DB;
		putwc('\n', stdout);
		if (fld->len)
			gcry_md_write(ctx.hmac, safep + sizeof(*fld), fld->len);
		safep += ((fld->len + 5 + 15) / TWOF_BLKSIZE) * TWOF_BLKSIZE;
	}

	assert(memcmp(ptr + (sz - 48), "PWS3-EOFPWS3-EOF", TWOF_BLKSIZE) == 0);

#define EOL() putwc('\n', stdout)
	EOL();
	print_prologue(stdout, pro);
	wprintf(L"KEY    "); printhex(stdout, sec->pprime, 32); EOL();
	wprintf(L"H(KEY) "); printhex(stdout, pro->h_pprime, 32); EOL();

	gcry_md_final(ctx.hmac);
	wprintf(L"HMAC'  ");
	uint8_t hmac[32];
	memmove(hmac, gcry_md_read(ctx.hmac, GCRY_MD_SHA256), 32);
	printhex(stdout, hmac, 32);
	EOL();

	wprintf(L"HMAC   ");
	printhex(stdout, ptr + (sz - 32), 32);
	EOL();
#undef EOL

	gcry_free(safe);
	gcry_free(sec);
	unmapfile(ptr, sz);
	term_decrypt_ctx(&ctx);

	exit(0);
}
