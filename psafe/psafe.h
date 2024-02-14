/* Copyright 2013-2024 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */
#ifndef PSAFE_H
#define PSAFE_H

#include <gcrypt.h>
#include <stdint.h>

/* Twofish cipher block size bytes. */
#define TWOFISH_SIZE 16

/* SHA-256 size in bytes. */
#define SHA256_SIZE 32

/* Field header. */
struct field {
    u32 len;
    u8  type;
    u8  val[];
} __attribute__((packed));

/* Secure safe information. */
struct safe_sec {
    u8 pprime[32];
    u8 rand_k[32];
    u8 rand_l[32];
};

/** Cryptographic context */
struct crypto_ctx {
    gcry_error_t     gerr;
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t     hmac;
};

#endif
