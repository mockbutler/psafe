#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

int main(int argc, char **argv)
{
    uint32_t v;

    assert(argc == 1);
    assert(argv[0] != NULL);

    static const uint8_t testv1[] = { 1, 0, 0, 0 };
    v = load_le32((void *)testv1);
    assert(v == 1);

    static const uint8_t testv2[] = { 254, 255, 255, 255 };
    v = load_le32((void *)testv2);
    assert(v == UINT32_MAX - 1);

    return 0;
}
