#include "passphrase.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rand.h"

static const char ALNUM_CHARS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
#define ALNUM_CHARS_COUNT 36

/* Draws one word uniformly from wl->words, redrawing until its byte length
 * is <= max_length (max_length == 0 means no limit). Caller must have
 * already confirmed at least one word in wl satisfies the limit, or this
 * can loop forever. Returns NULL on RNG failure. */
static const char *random_word(const Wordlist *wl, size_t max_length) {
    for (;;) {
        uint32_t idx;
        if (rand_below((uint32_t)wl->count, &idx) != 0) return NULL;
        const char *word = wl->words[idx];
        if (max_length == 0 || strlen(word) <= max_length) return word;
    }
}

/* Fills out[0..ALNUM_SEGMENT_LENGTH) with random chars from ALNUM_CHARS,
 * rejecting and redrawing the whole segment until it has >=1 letter and
 * >=1 digit. Returns 0 on success, -1 on RNG failure. */
static int random_alnum_segment(char *out) {
    for (;;) {
        bool has_letter = false;
        bool has_digit = false;
        for (int i = 0; i < ALNUM_SEGMENT_LENGTH; i++) {
            uint32_t idx;
            if (rand_below(ALNUM_CHARS_COUNT, &idx) != 0) return -1;
            char c = ALNUM_CHARS[idx];
            out[i] = c;
            if (c >= '0' && c <= '9') {
                has_digit = true;
            } else {
                has_letter = true;
            }
        }
        if (has_letter && has_digit) return 0;
    }
}

char *generate_passphrase(const Wordlist *wl, int word_count, size_t max_length, const char *delimiter) {
    if (!wl || !wl->words || wl->count == 0 || word_count <= 0 || !delimiter) return NULL;

    size_t wc = (size_t)word_count;
    size_t total_parts = wc + 1;

    if (max_length > 0) {
        bool any_fits = false;
        for (size_t i = 0; i < wl->count; i++) {
            if (strlen(wl->words[i]) <= max_length) {
                any_fits = true;
                break;
            }
        }
        if (!any_fits) return NULL;
    }

    /* parts[0..wc-1] point into wl->words (not owned); parts[wc] points at
     * the local segment buffer, which stays alive for the whole function. */
    const char **parts = malloc(total_parts * sizeof(*parts));
    if (!parts) return NULL;

    char segment[ALNUM_SEGMENT_LENGTH + 1];
    segment[ALNUM_SEGMENT_LENGTH] = '\0';

    for (size_t i = 0; i < wc; i++) {
        const char *word = random_word(wl, max_length);
        if (!word) {
            free(parts);
            return NULL;
        }
        parts[i] = word;
    }

    if (random_alnum_segment(segment) != 0) {
        free(parts);
        return NULL;
    }
    parts[wc] = segment;

    uint32_t x;
    if (rand_below((uint32_t)total_parts, &x) != 0) {
        free(parts);
        return NULL;
    }
    const char *tmp = parts[x];
    parts[x] = parts[total_parts - 1];
    parts[total_parts - 1] = tmp;

    size_t delim_len = strlen(delimiter);
    size_t total_len = delim_len * (total_parts - 1);
    for (size_t i = 0; i < total_parts; i++) total_len += strlen(parts[i]);

    char *result = malloc(total_len + 1);
    if (!result) {
        free(parts);
        return NULL;
    }

    char *p = result;
    for (size_t i = 0; i < total_parts; i++) {
        size_t len = strlen(parts[i]);
        memcpy(p, parts[i], len);
        p += len;
        if (i + 1 != total_parts && delim_len > 0) {
            memcpy(p, delimiter, delim_len);
            p += delim_len;
        }
    }
    *p = '\0';

    free(parts);
    return result;
}
