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

#include <ios>

#include <crypto++/sha.h>
#include <crypto++/modes.h>
#include <crypto++/twofish.h>

#include "mapfile.h"
#include "psafe.h"
#include <iostream>

#define TWOF_BLKSIZE 16		/* Twofish cipher block size bytes. */
#define SHA256_SIZE 32		/* SHA-256 size in bytes. */


void stretch_key(const char *pass, size_t passlen,
                 const uint8_t *salt, uint32_t iter,
                 uint8_t *skey)
{
    using namespace CryptoPP;
    SHA256 sha256;
    sha256.Update(reinterpret_cast<const byte*>(pass), passlen);
    sha256.Update(salt, 32);
    sha256.Final(skey);
    byte digest[SHA256::DIGESTSIZE];
    while (iter-- > 0) {
        sha256.Restart();
        sha256.CalculateDigest(digest, skey, 32);
        memcpy(skey, digest, sizeof(digest));
    }
}

void sha256_block32(const uint8_t *in, uint8_t *out)
{
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(out, in, 32);
}

void extract_random_key(const uint8_t *stretchkey,
                        const uint8_t *fst, const uint8_t *snd,
                        uint8_t *randkey)
{
    using namespace CryptoPP;
    ECB_Mode< Twofish >::Decryption ctx;
    ctx.SetKey(stretchkey, SHA256::DIGESTSIZE);
    ctx.ProcessData(randkey, fst, 16);
    ctx.ProcessData(randkey + 16, snd, 16);
}

void print_time(uint8_t *val)
{
    struct tm *lt;
    time_t time;
    time = val[0] | val[1] << 8 | val[2] << 16 | val[3] << 24;
    lt = gmtime(&time);
    wprintf(L"%d-%d-%d %02d:%02d:%02d",
            1900 + lt->tm_year, lt->tm_mon, lt->tm_mday,
            lt->tm_hour, lt->tm_min, lt->tm_sec);
}

void printhex(FILE *f, uint8_t *ptr, unsigned cnt)
{
    unsigned i;
    for (i = 0; i < cnt; i++) {
        fwprintf(f, L"%02x", *ptr++);
    }
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
    wchar_t *tmp = new wchar_t[len + 1];
    size_t n;
    const char *ptr = (const char *)bp;
    n = mbsrtowcs(tmp, &ptr, len, &state);
    tmp[n] = L'\0';
    fputws(tmp, f);
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
    case 0x14:
    case 0x16:
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

int init_decrypt_ctx(psafe::Decrypt* ctx, psafe3_pro* pro, safe_sec* sec)
{
    ctx->decrypt.SetKeyWithIV(sec->rand_k, 32, pro->iv, 16);
    ctx->hmac.SetKey(sec->rand_l, 32);
    return 0;
}

void print_prologue(FILE *f, struct psafe3_pro *pro)
{
    int i;
#define EOL() fputwc('\n', f)
    fputws(L"SALT   ", f);
    printhex(f, pro->salt, 32);
    EOL();
    fwprintf(f, L"ITER   %u\n", pro->iter);
    fputws(L"H(P')  ", f);
    printhex(f, pro->h_pprime, 32);
    EOL();
    for (i = 0; i < 4; i++) {
        fwprintf(f, L"B%d     ", i);
        printhex(f, pro->b[i], 16);
        EOL();
    }
    fputws(L"IV     ", f);
    printhex(f, pro->iv, 16);
    EOL();
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
        if (fld->type == 0xff) {
            break;
        }
    }

    *hdr = reinterpret_cast<field*>(new field*[fcnt]);
    for (ptr = raw, i = 0; ptr < raw + rawsize; ptr += TWOF_BLKSIZE) {
        hdr[i++] = (struct field *) ptr;
        if (fld->type == 0xff) {
            break;
        }
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
    if (memcmp(pro->h_pprime, hkey, 32) != 0) {
        return -1;
    }
    extract_random_key(sec->pprime, pro->b[0], pro->b[1], sec->rand_k);
    extract_random_key(sec->pprime, pro->b[2], pro->b[3], sec->rand_l);
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    setlocale(LC_ALL, "");

    if (argc != 3) {
        wprintf(L"Usage: psafe file.psafe3 passphrase");
        exit(EXIT_FAILURE);
    }

    size_t sz;
    uint8_t *ptr;
    ptr = reinterpret_cast<uint8_t *>(mapfile_ro(argv[1], &sz));
    if (ptr == NULL) {
        err(1, "%s", argv[1]);
    }

    struct psafe3_pro *pro;
    pro = (struct psafe3_pro *)(ptr + 4);
    CryptoPP::SecBlock<safe_sec> safeSecMem(1);
    struct safe_sec *sec;
    sec = reinterpret_cast<safe_sec *>(safeSecMem.BytePtr());
    ret = stretch_and_check_pass(argv[2], strlen(argv[2]), pro, sec);
    if (ret != 0) {
        wprintf(L"Invalid password.\n");
        exit(1);
    }

    uint8_t *safe;
    size_t safe_size;
    safe_size = sz - (4 + sizeof(*pro) + 48);
    assert(safe_size > 0);
    assert(safe_size % TWOF_BLKSIZE == 0);
    CryptoPP::SecBlock<byte> safeMem(safe_size);
    safe = safeMem.BytePtr();
    assert(safe != NULL);

    psafe::Decrypt ctx;
    if (init_decrypt_ctx(&ctx, pro, sec) < 0) {
        std::cerr << "Failed to init decryption context.\n";
        exit(1);
    }

    size_t bcnt;
    bcnt = safe_size / TWOF_BLKSIZE;
    assert(bcnt > 0);
    uint8_t *encp;
    uint8_t *safep;
    encp = ptr + 4 + sizeof(*pro);
    safep = safe;
    while (bcnt--) {
        ctx.decrypt.ProcessData(safep, encp, TWOF_BLKSIZE);
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
        if (state == DB) {
            db_print(stdout, fld);
        } else {
            hd_print(stdout, fld);
        }
        if (fld->type == 0xff) {
            state = DB;
        }
        putwc('\n', stdout);

        if (fld->len) {
            ctx.hmac.Update(safep + sizeof(*fld), fld->len);
        }

        safep += ((fld->len + 5 + 15) / TWOF_BLKSIZE) * TWOF_BLKSIZE;
    }

    assert(memcmp(ptr + (sz - 48), "PWS3-EOFPWS3-EOF", TWOF_BLKSIZE) == 0);

#define EOL() putwc('\n', stdout)
    EOL();
    print_prologue(stdout, pro);
    wprintf(L"KEY    ");
    printhex(stdout, sec->pprime, 32);
    EOL();
    wprintf(L"H(KEY) ");
    printhex(stdout, pro->h_pprime, 32);
    EOL();

    byte hmac_digest[32];
    ctx.hmac.Final(hmac_digest);
    wprintf(L"HMAC'  ");
    printhex(stdout, hmac_digest, 32);
    EOL();

    wprintf(L"HMAC   ");
    printhex(stdout, ptr + (sz - 32), 32);
    EOL();
#undef EOL

    unmapfile(ptr, sz);

    exit(0);
}
