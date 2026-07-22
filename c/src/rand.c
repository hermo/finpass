#include "rand.h"

#include <errno.h>
#include <sys/random.h>

int rand_bytes(void *buf, size_t n) {
    unsigned char *p = buf;
    while (n > 0) {
        ssize_t got = getrandom(p, n, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        p += got;
        n -= (size_t)got;
    }
    return 0;
}

int rand_below(uint32_t upper, uint32_t *out) {
    if (upper == 0)
        return -1;

    /* arc4random_uniform algorithm: reject draws in the partial-final-bucket
     * range so every value in [0, upper) is equally likely. */
    uint32_t min = (uint32_t)(-upper) % upper; /* == 2^32 mod upper */
    for (;;) {
        uint32_t draw;
        if (rand_bytes(&draw, sizeof(draw)) != 0)
            return -1;
        if (draw >= min) {
            *out = draw % upper;
            return 0;
        }
    }
}
