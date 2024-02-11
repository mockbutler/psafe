#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include "util.h"

void crash_actual(const char* path, const char* func)
{
    fputws(L"CRASH ", stderr);
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

int mkwstr(const char *str, wchar_t *wstr_out)
{
    size_t len;
    const char *ccp;
    wchar_t *wcp;

    len = strlen(str);
    if (len == 0)
        return -1;

    wstr_out = calloc(len + 1, sizeof(wchar_t));
    if (wstr_out == NULL) 
        return -1;

    for (ccp = str, wcp = wstr_out; *ccp != '\0'; ccp++, wcp++) {
        *wcp = btowc(*ccp);
    }
    *wcp = L'\0';
    return 0;
}
