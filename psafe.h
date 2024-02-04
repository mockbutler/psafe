/* Copyright 2013-2024 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */
#ifndef PSAFE_H
#define PSAFE_H

#include <gcrypt.h>
#include <stdint.h>


/* The format defines the header as being the first set of records, so
 * call this the prologue.
 */
struct psafe3_pro {
    /* Starts with the fixed tag "PWS3". */
    uint8_t     salt[32];
    uint32_t    iter;
    uint8_t     h_pprime[32];
    uint8_t     b[4][16];
    uint8_t     iv[16];
} __attribute__((packed));

#define PSAFE3_PRO_SIZE (sizeof(safe_proxs) + 4)

struct psafe3_epi {
    uint8_t eof_block[16];
    uint8_t hmac[32];
} __attribute__((packed));

#define PSAFE3_EPI_SIZE (sizeof (safe_epi))

/* Field header. */
struct field {
    uint32_t    len;
    uint8_t     type;
    uint8_t     val[];
} __attribute__((packed));

/* Secure safe information. */
struct safe_sec {
    uint8_t pprime[32];
    uint8_t rand_k[32];
    uint8_t rand_l[32];
};

/** Cryptographic context */
struct crypto_ctx {
    gcry_error_t        gerr;
    gcry_cipher_hd_t    cipher;
    gcry_md_hd_t        hmac;
};

#endif
