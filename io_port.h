#ifndef IOPORT_H
#define IOPORT_H

#include <stdint.h>
#include <unistd.h>

struct io_port {
    int (*read)(struct io_port *port, void *buf, const size_t len, size_t *actual);
    int (*close)(struct io_port *port);
};

struct io_port_mmap {
    struct io_port port;
    void *mem;
    size_t mem_size;
    size_t rdpos;
    size_t wrpos;
};

int io_port_mmap_open(const char *path, struct io_port **port);

#endif