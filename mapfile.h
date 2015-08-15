/* Copyright 2013-2015 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved
 */

#include <sys/mman.h>
#include <fcntl.h>

void * mapfile(const char *path, size_t *size, int oflg, int prot, int mflg);
int unmapfile(void *ptr, size_t sz);

#define mapfile_rw(p, s) \
  mapfile(p, s, O_RDWR, PROT_READ|PROT_WRITE, MAP_SHARED)

#define mapfile_ro(p, s) \
  mapfile(p, s, O_RDONLY, PROT_READ, MAP_PRIVATE)
