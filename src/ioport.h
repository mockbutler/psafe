#pragma once

typedef struct ioport {
    int (*read)(struct ioport *port, void *buf, const size_t len,
                size_t *actual);
    int (*close)(struct ioport *port);
    int (*can_read)(struct ioport *port);
    int (*can_write)(struct ioport *port);
    off_t (*where)(struct ioport *port);
} IOPort;

int ioport_read_exactly(IOPort *port, void *buf, const size_t len);
int ioport_read_le32(IOPort *port, uint32_t *val);

struct ioport_mmap {
    IOPort port;
    void  *mem;
    size_t mem_size;
    size_t pos;
};

int ioport_mmap_open(const char *path, IOPort **port);

struct ioport_str {
    IOPort port;
    char  *str;     /* storage buffer */
    size_t str_cap; /* capacity : bytes */
    size_t pos;     /* cursor position : bytes */
};

enum ioport_str_opts { IOPORT_STR_CLEAR = 0, IOPORT_STR_ };

int ioport_str_open(char *str, size_t cap, enum ioport_str_opts opts);

#define IOPORT_READ(port, buf, len, p_actual)                                  \
    ((port)->read(port, buf, len, p_actual))
