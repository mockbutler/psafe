#include <assert.h>
#include <fcntl.h>
#include <malloc/_malloc.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util.h"

#include "io_port.h"

static int _mmap_read(struct io_port *port, void *buf, const size_t len, size_t *actual)
{
    assert(port != NULL && buf != NULL && actual != NULL);

    struct io_port_mmap *ctx;
    ctx = (void *)port;

    if (ctx->rdpos >= ctx->mem_size) {
        return 0;
    }
    size_t rdamt = MIN(ctx->mem_size - ctx->rdpos, len);
    uintptr_t loc = (uintptr_t)ctx->mem + ctx->rdpos;
    memmove(buf, (void *)loc, rdamt);
    ctx->rdpos += len;
    return 0;
}

static int _mmap_close(struct io_port *port)
{
    assert(port != NULL);

    struct io_port_mmap *ctx;
    ctx = (void *)port;

    int ret = munmap(ctx->mem, ctx->mem_size);
    if (ret == 0) {
        ctx->mem = NULL;
        ctx->mem_size = 0;
        ctx->rdpos = ctx->wrpos = 0;
    }
    return ret;
}

int io_port_mmap_open(const char *path, struct io_port **port)
{
    assert(path != NULL && port != NULL);

    int fd;
    if ((fd = open(path, O_RDWR)) < 0) {
        return -1;
    }

    struct stat nfo;
    if (fstat(fd, &nfo) != 0) {
        goto close_on_err;
    }

    void *memptr;
    memptr = mmap(NULL, nfo.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (memptr == MAP_FAILED) {
        goto close_on_err;
    }

    struct io_port_mmap *mmp;
    if (posix_memalign((void**)&mmp, sizeof(void*), sizeof(*mmp)) != 0) {
        goto close_on_err;
    }

    mmp->mem = memptr;
    mmp->mem_size = nfo.st_size;
    mmp->rdpos = mmp->wrpos = 0;
    mmp->port.read = _mmap_read;
    mmp->port.close = _mmap_close;
    *port = &mmp->port;
    return 0;

close_on_err:
    do {
        int errtmp = errno;
        util_close_fd(fd);
        errno = errtmp;
    } while (0);
    return -1;
}
