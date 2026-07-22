#ifndef FINPASS_RAND_H
#define FINPASS_RAND_H

#include <stddef.h>
#include <stdint.h>

/* Fills buf with n cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure. */
int rand_bytes(void *buf, size_t n);

/* Stores a uniform random integer from [0, upper) in *out without modulo
 * bias. upper must be nonzero. Returns 0 on success, -1 on failure. */
int rand_below(uint32_t upper, uint32_t *out);

#endif
