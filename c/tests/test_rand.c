/* Standalone test program for rand.c. Exits 0 on pass, 1 on fail. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/rand.h"

static int failures = 0;

static void check(int cond, const char *name) {
    if (cond) {
        printf("PASS: %s\n", name);
    } else {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

static void test_rand_bytes_differs(void) {
    unsigned char a[32] = {0};
    unsigned char b[32] = {0};

    int ok = rand_bytes(a, sizeof(a)) == 0 && rand_bytes(b, sizeof(b)) == 0;
    check(ok, "rand_bytes: two calls succeed");
    check(memcmp(a, b, sizeof(a)) != 0, "rand_bytes: consecutive buffers differ");

    /* Sanity: not all-zero (would indicate getrandom didn't actually fill it). */
    unsigned char zero[32] = {0};
    check(memcmp(a, zero, sizeof(a)) != 0, "rand_bytes: buffer is not all-zero");
}

static void test_rand_below_zero_fails(void) {
    uint32_t out = 0xdeadbeef;
    int rc = rand_below(0, &out);
    check(rc == -1, "rand_below(0): returns -1");
}

static void test_rand_below_one(void) {
    int ok = 1;
    for (int i = 0; i < 1000; i++) {
        uint32_t out = 0xffffffffu;
        if (rand_below(1, &out) != 0 || out != 0) {
            ok = 0;
            break;
        }
    }
    check(ok, "rand_below(1): always returns 0");
}

static void test_rand_below_bounds(void) {
    uint32_t uppers[] = {2, 3, 91443, UINT32_MAX};
    for (size_t u = 0; u < sizeof(uppers) / sizeof(uppers[0]); u++) {
        uint32_t upper = uppers[u];
        int iterations = (upper == UINT32_MAX) ? 2000 : 20000;
        int ok = 1;
        for (int i = 0; i < iterations; i++) {
            uint32_t out;
            if (rand_below(upper, &out) != 0 || out >= upper) {
                ok = 0;
                break;
            }
        }
        char name[64];
        snprintf(name, sizeof(name), "rand_below: results < upper=%u", upper);
        check(ok, name);
    }
}

/* Chi-square-style uniformity smoke test. 60000 draws with upper=6:
 * expected count per bucket is 10000, stddev = sqrt(n*p*(1-p)) ~= 91.3.
 * Using a +-6 sigma window (+-550) gives a false-failure probability well
 * under 1e-9 per bucket, so this should never flake in practice. */
static void test_rand_below_uniformity(void) {
    const uint32_t upper = 6;
    const int n = 60000;
    long counts[6] = {0};
    int ok = 1;

    for (int i = 0; i < n; i++) {
        uint32_t out;
        if (rand_below(upper, &out) != 0 || out >= upper) {
            ok = 0;
            break;
        }
        counts[out]++;
    }
    check(ok, "rand_below: uniformity test draws succeed and stay in range");

    long expected = n / (long)upper; /* 10000 */
    long tolerance = 550;
    int uniform = 1;
    for (uint32_t i = 0; i < upper; i++) {
        printf("  bucket %u: count=%ld\n", i, counts[i]);
        if (counts[i] < expected - tolerance || counts[i] > expected + tolerance) {
            uniform = 0;
        }
    }
    check(uniform, "rand_below: bucket counts within +-6 sigma of expected");
}

int main(void) {
    test_rand_bytes_differs();
    test_rand_below_zero_fails();
    test_rand_below_one();
    test_rand_below_bounds();
    test_rand_below_uniformity();

    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    } else {
        printf("%d test(s) failed.\n", failures);
        return 1;
    }
}
