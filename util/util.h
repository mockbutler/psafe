#ifndef UTIL_H
#define UTIL_H

#include "basictypes.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/**
 * Load Little Endian 32 bit integer from memory location.
 * Memory is not required to be 4 byte aligned.
 */
static inline u32 load_le32(void* mem)
{
    u8* p = mem;
    u32 val = p[0];
    val = val + (p[1] << UINT32_C(8));
    val = val + (p[2] << UINT32_C(16));
    val = val + (p[3] << UINT32_C(24));
    return val;
}

#define STRIFY(txt) #txt

#define crash() \
    crash_helper(__FILE__, __LINE__, __func__)

#define crash_helper(path, line, func) \
    crash_actual(path ":" STRIFY(line) " ", func)

void crash_actual(const char* path, const char* func);

void util_close_fd(int fd);

int read_from_terminal(const char* prompt, char* buf, size_t* bufsize);

#endif
