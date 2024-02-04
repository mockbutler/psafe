#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/**
 * Load Little Endian 32 bit integer from memory location.
 */
static inline uint32_t load_le32(void *mem)
{
    uint8_t *p = mem;
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

#define strify(lno) #lno

#define crash() \
    crash_helper(__FILE__, __LINE__, __func__)

#define crash_helper(path, line, func) \
    crash_actual(path ":" strify(line) " ", func)

void crash_actual(const char *path, const char *func);

void util_close_fd(int fd);

#endif