#ifndef PWS3_H
#define PWS3_H

/* The format defines the header as being the first set of records, so
 * call this the prologue.
 */
struct psafe3_header {
    /* Starts with the fixed tag "PWS3". */
    u8  salt[32];
    u32 iter;
    u8  h_pprime[32];
    u8  b[4][16];
    u8  iv[16];
};

int pws3_read_header(struct ioport* port, struct psafe3_header* hdr);

#endif
