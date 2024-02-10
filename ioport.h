#ifndef IOPORT_H
#define IOPORT_H

#include <stdint.h>
#include <unistd.h>

struct ioport {
    int (*read)(struct ioport* port, void* buf, const size_t len, size_t* actual);
    int (*close)(struct ioport* port);
    int (*drained)(struct ioport* port);
};

struct ioport_mmap {
    struct ioport port;
    void* mem;
    size_t mem_size;
    size_t pos;
};

int ioport_mmap_open(const char* path, struct ioport** port);

int ioport_read_exactly(struct ioport* port, void* buf, const size_t len);
int ioport_read_le32(struct ioport* port, uint32_t* val);

#define IO_PORT_READ(port, buf, len, p_actual) \
    ((port)->read(port, buf, len, p_actual))

#endif
