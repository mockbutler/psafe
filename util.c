#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

#include "util.h"

void crash_actual(const char *path, const char *func)
{
    fputs("CRASH ", stderr);
    fputs(path, stderr);
    fputs(func, stderr);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

void util_close_fd(int fd)
{
    int ret;
    
call_again:
    ret = close(fd);
    if (ret != 0) {
        switch (errno) {
            case EINTR:
            goto call_again;
            default:
            crash();
        }
    }
}
