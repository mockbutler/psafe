/* Copyright 2013 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 *
 * Todo
 *
 * - Use gcry_malloc_secure() in more places?
 * - Fix memory leaks.
 */

#include <assert.h>
#include <err.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "psafe.h"

struct psafe_secure {
	uint8_t p[32];
	uint8_t k[32];
	uint8_t l[32];
};

void freadn(void *buf, size_t n, FILE *f)
{
	size_t rd, r;
	rd = 0;
	while (rd < n) {
		r = fread(buf, 1, n - rd, f);
		if (r == 0) {
			if (ferror(f))
				err(1, "error reading file");
			else
				errx(1, "premature end of file");
		}
		rd += r;
	}
}

uint32_t xlu32(void *buf)
{
	uint8_t *b = buf;
	return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
}

size_t pad_to_block(size_t n)
{
	return (n + BLK_SIZE - 1) / BLK_SIZE;
}

int verify_v3(FILE *f)
{
	char tag[4];
	freadn(tag, 4, f);
	return strncmp(tag, "PWS3", 4) == 0;
}

void gcrypt_fatal(gcry_error_t err)
{
	fwprintf(stderr, L"gcrypt error %s/%s\n", gcry_strsource(err), gcry_strerror(err));
	exit(EXIT_FAILURE);
}

void stretch_key(const char *pass, const uint8_t *salt, uint32_t iter, uint8_t *skey)
{
	gcry_error_t gerr;
	gcry_md_hd_t hd;
	gerr = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	gcry_md_write(hd, pass, strlen(pass));
	gcry_md_write(hd, salt, SALT_SIZE);
	gcry_md_final(hd);
	uint8_t tmp[STRETCHED_KEY_SIZE];
	memmove(tmp, gcry_md_read(hd, 0), STRETCHED_KEY_SIZE);

	uint32_t i;
	for (i = 0; i < iter; i++) {
		gcry_md_reset(hd);
		gcry_md_write(hd, tmp, sizeof(tmp));
		gcry_md_final(hd);
		memmove(tmp, gcry_md_read(hd, 0), sizeof(tmp));
	}
	gcry_md_close(hd);
	memmove(skey, tmp, STRETCHED_KEY_SIZE);
}

void sha256_block32(const uint8_t *bin, uint8_t *bout)
{
	gcry_md_hd_t hd;
	gcry_error_t gerr;
	gerr = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gcry_md_write(hd, bin, 32);
	gcry_md_final(hd);
	memmove(bout, gcry_md_read(hd, 0), 32);
	gcry_md_close(hd);
}

void extract_random_key(const uint8_t *p, const uint8_t *a, const uint8_t *b, uint8_t *rk)
{
	gcry_error_t gerr;
	gcry_cipher_hd_t hd;
	gerr = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gerr = gcry_cipher_setkey(hd, p, 32);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	gcry_cipher_decrypt(hd, rk, 16, a, 16);
	gcry_cipher_reset(hd);
	gcry_cipher_decrypt(hd, rk + 16, 16, b, 16);
	gcry_cipher_close(hd);
}

void print_time(void *field)
{
	struct tm lt;
	localtime_r((time_t*)field, &lt);
	wprintf(L"%d-%d-%d %02d:%02d:%02d",
		1900 + lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);
}

void print_guid(char *guid)
{
	int i;
	unsigned char *gp;
	gp = (unsigned char*)guid;
	for (i = 0; i < 16; i++)
		wprintf(L"%02x", gp[i]);
}

int read_block(struct safeio *io, char *block)
{
	char tmp[BLK_SIZE];
	freadn(tmp, sizeof(tmp), io->file);
	if (memcmp(tmp, "PWS3-EOFPWS3-EOF", sizeof(tmp)) == 0)
		return READ_END;

	gcry_error_t gerr;
	gerr = gcry_cipher_decrypt(io->cipher, block, BLK_SIZE, tmp, BLK_SIZE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);
	return READ_OK;
}

void update_hmac(struct safeio *io, const char *data, size_t sz)
{
	gcry_md_write(io->hmac, data, sz);
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

int read_field(struct safeio *io, char *blktmp, struct field **fld)
{
	int ret;
	ret = read_block(io, blktmp);
	if (ret == READ_END)
		return READ_END;

	uint32_t len = xlu32(blktmp);
	uint8_t type = blktmp[4];
	size_t datasz = (pad_to_block(len + FLD_HDR_SIZE) * BLK_SIZE) - FLD_HDR_SIZE;
	assert(datasz >= len);
	struct field *f = secure_malloc(sizeof(*f) + datasz);

	if (len > 0) {
		memcpy(f->data, &blktmp[FLD_HDR_SIZE], MIN(BLK_SIZE - FLD_HDR_SIZE, len));
		uint32_t rdcnt = MIN(BLK_SIZE - FLD_HDR_SIZE, len);
		while (rdcnt < len) {
			ret = read_block(io, blktmp);
			if (ret == READ_END)
				errx(1, "premature end of database");

			/* Copy all the data including the trailing
			 * random bytes. 
			 */
			memcpy(&f->data[rdcnt], blktmp, BLK_SIZE);
			rdcnt += MIN(BLK_SIZE, len);
		}
	}
	f->len = len;
	f->type = type;
	update_hmac(io, f->data, f->len);
	*fld = f;
	return READ_OK;
}

void prstr(const char *str, size_t len, FILE *fh)
{
	size_t i;
	for (i = 0; i < len; i++)
		putwc(str[i], fh);
}

void decrypt_hdr(gcry_cipher_hd_t hd, gcry_md_hd_t hmac, FILE *pwdb)
{
	char *ptext = secure_malloc(BLK_SIZE);

	struct safeio io;
	io.file = pwdb;
	io.cipher = hd;
	io.hmac = hmac;
	struct field *fld;
	while (read_field(&io, ptext, &fld) == READ_OK) {
		wprintf(L"%02x %4u  ", fld->type, fld->len);
		if (fld->type != 0 && fld->type != 1 && fld->type != 4 && fld->type != 0xff)
			prstr(fld->data, fld->len, stdout);
		else if (fld->type == 0)
			wprintf(L"%d.%d", (int)fld->data[1], (int)fld->data[0]);
		else if (fld->type == 4)
			print_time(fld->data);
		else if (fld->type == 1)
			print_guid(fld->data);

		putwc('\n', stdout);
		if (fld->type == 0xff)
			break;
		secure_free(fld);
	}
	secure_free(fld);
	secure_free(ptext);
}

void decrypt_db(gcry_cipher_hd_t hd, gcry_md_hd_t hmac, FILE *pwdb)
{
	char *ptext = secure_malloc(BLK_SIZE);

	struct safeio io;
	io.file = pwdb;
	io.cipher = hd;
	io.hmac = hmac;
	struct field *fld;
	while (read_field(&io, ptext, &fld) == READ_OK) {
		wprintf(L"%02x %4u  ", fld->type, fld->len);
		switch (fld->type) {
		case 0x2: case 0x3: case 0x4: case 0x5: case 0x6:
		case 0xd: case 0xe: case 0xf: case 0x10: case 0x14: case 0x16:
			prstr(fld->data, fld->len, stdout);
			break;
		case 0x7: case 0x8: case 0x9: case 0xa: case 0xc:
			print_time(fld->data);
			break;
		case 0x1:
			print_guid(fld->data);
		}

		putwc('\n', stdout);
		if (fld->type == 0xff)
			putwc('\n', stdout);

		secure_free(fld);
	}
	secure_free(ptext);
}

void decrypt(FILE *pwdb, const uint8_t *k, const uint8_t *iv, const uint8_t *l)
{
	gcry_error_t gerr;
	gcry_cipher_hd_t hd;
	gerr = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	gerr = gcry_cipher_setkey(hd, k, 32);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	gerr = gcry_cipher_setiv(hd, iv, 16);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	gcry_md_hd_t hmac_hd;
	gerr = gcry_md_open(&hmac_hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	gerr = gcry_md_setkey(hmac_hd, l, 32);
	if (gerr != GPG_ERR_NO_ERROR)
		gcrypt_fatal(gerr);

	fputws(L"--- header ---\n", stdout);
	decrypt_hdr(hd, hmac_hd, pwdb);
	fputws(L"--- database ---\n", stdout);
	decrypt_db(hd, hmac_hd, pwdb);

	gcry_md_final(hmac_hd);
	uint8_t hmac[32];
	freadn(hmac, sizeof(hmac), pwdb);
	uint8_t calc_hmac[32];
	memmove(calc_hmac, gcry_md_read(hmac_hd, GCRY_MD_SHA256), sizeof(hmac));
	if (memcmp(calc_hmac, hmac, sizeof(hmac)) != 0) {
		printf("error hmac verification failed\n");
	} else {
		printf("hmac verification successful\n");
	}

	gcry_md_close(hmac_hd);
	gcry_cipher_close(hd);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		puts("Usage: pws [password file] [password]");
		exit(EXIT_FAILURE);
	}

	setlocale(LC_ALL, "");

	FILE *pwdb;
	pwdb = fopen(argv[1], "r");
	if (!pwdb) {
		perror(argv[1]);
		exit(EXIT_FAILURE);
	}

	if (!verify_v3(pwdb)) {
		goto exit_error;
	}

	uint8_t salt[32];
	freadn(salt, sizeof(salt), pwdb);

	uint32_t iter;
	freadn(&iter, sizeof(iter), pwdb);

	uint8_t hp[32];
	freadn(hp, sizeof(hp), pwdb);

	uint8_t b[4][16];
	int i;
	for (i = 0; i < 4; i++)
		freadn(b[i], sizeof(b[i]), pwdb);

	uint8_t iv[16];
	freadn(iv, sizeof(iv), pwdb);

	struct psafe_secure *pss;
	pss = gcry_malloc_secure(sizeof(*pss));
	if (!pss) {
		fwprintf(stderr, L"error allocating secure memory\n");
		goto exit_error;
	}
	stretch_key(argv[2], salt, iter, pss->p);

	uint8_t hpgen[32];
	sha256_block32(pss->p, hpgen);
	if (memcmp(hp, hpgen, sizeof(hp)) != 0) {
		fwprintf(stderr, L"invalid password or corrupt file\n");
		goto exit_error;
	}

	extract_random_key(pss->p, b[0], b[1], pss->k);
	extract_random_key(pss->p, b[2], b[3], pss->l);

	decrypt(pwdb, pss->k, iv, pss->l);
	gcry_free(pss);
	fclose(pwdb);
	return 0;

 exit_error:
	fclose(pwdb);
	exit(EXIT_FAILURE);
	return 0;
}
