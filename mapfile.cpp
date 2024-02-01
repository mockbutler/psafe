/* Copyright 2013-2015 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */

#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

#include "mapfile.h"

void * mapfile(const char *path, size_t *size, int oflg, int prot, int mflg)
{
    int fd;
    struct stat nfo;
    void *ptr;

    assert(path != NULL);
    assert(size != NULL);

    fd = open(path, oflg);
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &nfo) != 0) {
        goto exit_err;
    }

    ptr = mmap(NULL, nfo.st_size, prot, mflg, fd, 0);
    if (ptr == MAP_FAILED) {
        goto exit_err;
    }

    *size = nfo.st_size;
    return ptr;

exit_err:
    close(fd);
    return NULL;
}

int unmapfile(void *ptr, size_t sz)
{
    assert(ptr != NULL);
    return munmap(ptr, sz);
}
