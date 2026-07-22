/* Standalone test for passphrase.c. Requires the real embedded wordlist
 * (via wordlist_load) and links against words.c and rand.c.
 * Exits 0 if all checks pass, 1 otherwise. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/passphrase.h"
#include "../src/words.h"

static int failed = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
            failed = 1;                                                    \
        }                                                                   \
    } while (0)

/* Splits s on every non-overlapping occurrence of delim (delim must be
 * non-empty). Returns a malloc'd array of malloc'd, NUL-terminated pieces
 * and sets *out_count; caller must free each piece and the array. Returns
 * NULL on allocation failure. */
static char **split(const char *s, const char *delim, size_t *out_count) {
    size_t delim_len = strlen(delim);
    size_t cap = 8, cnt = 0;
    char **parts = malloc(cap * sizeof(*parts));
    if (!parts) return NULL;

    const char *start = s;
    for (;;) {
        const char *found = strstr(start, delim);
        size_t len = found ? (size_t)(found - start) : strlen(start);
        if (cnt == cap) {
            cap *= 2;
            char **np = realloc(parts, cap * sizeof(*parts));
            if (!np) {
                for (size_t i = 0; i < cnt; i++) free(parts[i]);
                free(parts);
                return NULL;
            }
            parts = np;
        }
        char *piece = malloc(len + 1);
        if (!piece) {
            for (size_t i = 0; i < cnt; i++) free(parts[i]);
            free(parts);
            return NULL;
        }
        memcpy(piece, start, len);
        piece[len] = '\0';
        parts[cnt++] = piece;
        if (!found) break;
        start = found + delim_len;
    }
    *out_count = cnt;
    return parts;
}

static void free_parts(char **parts, size_t count) {
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts);
}

/* True if s is exactly ALNUM_SEGMENT_LENGTH bytes, drawn only from
 * [0-9A-Z], and contains at least one letter and one digit. No real
 * wordlist entry can match this (words are lowercase/accented Finnish;
 * the handful of 3-letter uppercase entries like "DNA" have no digit). */
static bool is_segment(const char *s) {
    size_t len = strlen(s);
    if (len != ALNUM_SEGMENT_LENGTH) return false;
    bool has_letter = false, has_digit = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= '0' && c <= '9') {
            has_digit = true;
        } else if (c >= 'A' && c <= 'Z') {
            has_letter = true;
        } else {
            return false;
        }
    }
    return has_letter && has_digit;
}

static bool in_wordlist(const Wordlist *wl, const char *s) {
    for (size_t i = 0; i < wl->count; i++) {
        if (strcmp(wl->words[i], s) == 0) return true;
    }
    return false;
}

/* Non-NULL for word_count 1..6; splitting yields word_count+1 parts. */
static void test_basic_shapes(const Wordlist *wl) {
    for (int wc = 1; wc <= 6; wc++) {
        char *pass = generate_passphrase(wl, wc, 0, "-");
        CHECK(pass != NULL, "generate_passphrase returned NULL for valid input");
        if (!pass) continue;

        size_t count = 0;
        char **parts = split(pass, "-", &count);
        CHECK(parts != NULL, "split allocation failed");
        if (parts) {
            CHECK(count == (size_t)wc + 1, "wrong number of parts for word_count");
            free_parts(parts, count);
        }
        free(pass);
    }
}

/* word_count=1 gives exactly 2 parts. */
static void test_word_count_one(const Wordlist *wl) {
    char *pass = generate_passphrase(wl, 1, 0, "-");
    CHECK(pass != NULL, "generate_passphrase returned NULL for word_count=1");
    if (!pass) return;
    size_t count = 0;
    char **parts = split(pass, "-", &count);
    CHECK(parts != NULL, "split allocation failed");
    if (parts) {
        CHECK(count == 2, "word_count=1 did not yield 2 parts");
        free_parts(parts, count);
    }
    free(pass);
}

/* Exactly one part is a valid segment; the rest are real wordlist words. */
static void test_parts_membership(const Wordlist *wl) {
    for (int iter = 0; iter < 20; iter++) {
        char *pass = generate_passphrase(wl, 3, 0, "-");
        CHECK(pass != NULL, "generate_passphrase returned NULL");
        if (!pass) continue;

        size_t count = 0;
        char **parts = split(pass, "-", &count);
        CHECK(parts != NULL, "split allocation failed");
        if (parts) {
            CHECK(count == 4, "expected 4 parts for word_count=3");
            size_t segments = 0;
            for (size_t i = 0; i < count; i++) {
                if (is_segment(parts[i])) {
                    segments++;
                } else {
                    CHECK(in_wordlist(wl, parts[i]), "non-segment part not found in wordlist");
                }
            }
            CHECK(segments == 1, "expected exactly one alphanumeric segment part");
            free_parts(parts, count);
        }
        free(pass);
    }
}

/* With max_length=5, every word part has byte length <= 5. */
static void test_max_length(const Wordlist *wl) {
    for (int iter = 0; iter < 20; iter++) {
        char *pass = generate_passphrase(wl, 4, 5, "-");
        CHECK(pass != NULL, "generate_passphrase returned NULL for max_length=5");
        if (!pass) continue;

        size_t count = 0;
        char **parts = split(pass, "-", &count);
        CHECK(parts != NULL, "split allocation failed");
        if (parts) {
            for (size_t i = 0; i < count; i++) {
                if (!is_segment(parts[i])) {
                    CHECK(strlen(parts[i]) <= 5, "word part exceeds max_length");
                }
            }
            free_parts(parts, count);
        }
        free(pass);
    }
}

/* Multi-char delimiter "--" splits into the expected number of parts. */
static void test_multichar_delimiter(const Wordlist *wl) {
    char *pass = generate_passphrase(wl, 3, 0, "--");
    CHECK(pass != NULL, "generate_passphrase returned NULL for delimiter \"--\"");
    if (!pass) return;

    size_t count = 0;
    char **parts = split(pass, "--", &count);
    CHECK(parts != NULL, "split allocation failed");
    if (parts) {
        CHECK(count == 4, "wrong number of parts with multi-char delimiter");
        size_t segments = 0;
        for (size_t i = 0; i < count; i++) {
            if (is_segment(parts[i])) segments++;
        }
        CHECK(segments == 1, "expected exactly one segment with multi-char delimiter");
        free_parts(parts, count);
    }
    free(pass);
}

/* Smoke test: over many generations with word_count=2 (3 possible
 * positions), the segment should land in each position roughly evenly.
 * sigma = sqrt(6000 * (1/3) * (2/3)) ~= 36.5; use a generous +/-6 sigma
 * (~220) band to keep flakiness negligible. */
static void test_positional_uniformity(const Wordlist *wl) {
    const int total = 6000;
    const double expected = total / 3.0;
    const double band = 220.0;
    long counts[3] = {0, 0, 0};

    for (int i = 0; i < total; i++) {
        char *pass = generate_passphrase(wl, 2, 0, "-");
        if (!pass) {
            CHECK(false, "generate_passphrase returned NULL during uniformity test");
            continue;
        }
        size_t count = 0;
        char **parts = split(pass, "-", &count);
        if (parts && count == 3) {
            for (size_t p = 0; p < count; p++) {
                if (is_segment(parts[p])) counts[p]++;
            }
        } else {
            CHECK(false, "unexpected part count during uniformity test");
        }
        if (parts) free_parts(parts, count);
        free(pass);
    }

    for (int p = 0; p < 3; p++) {
        double diff = (double)counts[p] - expected;
        if (diff < 0) diff = -diff;
        char msg[128];
        snprintf(msg, sizeof(msg), "position %d segment count out of expected band", p);
        CHECK(diff <= band, msg);
    }
}

static int cmp_str(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

/* 1000 generations should not produce duplicate passphrases. */
static void test_no_duplicates(const Wordlist *wl) {
    const int total = 1000;
    char **results = malloc((size_t)total * sizeof(*results));
    CHECK(results != NULL, "allocation failed for duplicate check");
    if (!results) return;

    int produced = 0;
    for (int i = 0; i < total; i++) {
        char *pass = generate_passphrase(wl, 4, 0, "-");
        if (!pass) {
            CHECK(false, "generate_passphrase returned NULL during duplicate check");
            continue;
        }
        results[produced++] = pass;
    }

    qsort(results, (size_t)produced, sizeof(*results), cmp_str);
    for (int i = 1; i < produced; i++) {
        CHECK(strcmp(results[i - 1], results[i]) != 0, "duplicate passphrase generated");
    }

    for (int i = 0; i < produced; i++) free(results[i]);
    free(results);
}

int main(void) {
    Wordlist wl;
    if (wordlist_load(&wl) != 0) {
        fprintf(stderr, "FAIL: wordlist_load failed\n");
        return 1;
    }

    test_basic_shapes(&wl);
    test_word_count_one(&wl);
    test_parts_membership(&wl);
    test_max_length(&wl);
    test_multichar_delimiter(&wl);
    test_positional_uniformity(&wl);
    test_no_duplicates(&wl);

    wordlist_free(&wl);

    if (failed) {
        fprintf(stderr, "FAILED\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}
