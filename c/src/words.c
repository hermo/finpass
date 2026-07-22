#include "words.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORDLIST_PATH "/zip/words.fc"

/* Reads the whole file into a growable heap buffer. zipos does not support
 * fseek/ftell for size discovery, so we grow by doubling as we read. */
static int read_whole_file(FILE *f, unsigned char **out_buf, size_t *out_len) {
    size_t cap = 1u << 16;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return -1;

    for (;;) {
        if (len == cap) {
            size_t new_cap = cap * 2;
            unsigned char *new_buf = realloc(buf, new_cap);
            if (!new_buf) {
                free(buf);
                return -1;
            }
            buf = new_buf;
            cap = new_cap;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            if (ferror(f)) {
                free(buf);
                return -1;
            }
            break; /* EOF */
        }
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}

/* The embedded wordlist is front-coded (see c/tools/wordenc.c): each entry
 * is one control byte P < 32 giving the number of leading bytes shared with
 * the previous word, followed by the differing suffix in bytes >= 32. The
 * control byte doubles as the entry delimiter, so decoding is a single
 * classification of each byte: < 32 starts a word, >= 32 extends it. */
int wordlist_load(Wordlist *wl) {
    if (!wl) return -1;

    FILE *f = fopen(WORDLIST_PATH, "rb");
    if (!f) return -1;

    unsigned char *enc = NULL;
    size_t elen = 0;
    int rc = read_whole_file(f, &enc, &elen);
    fclose(f);
    if (rc != 0) return -1;

    /* Pass 1: count words and total decoded bytes so pass 2 can fill
     * exactly-sized allocations without reallocation. */
    size_t count = 0;
    size_t total = 0;
    size_t prev_len = 0;
    size_t pos = 0;
    while (pos < elen) {
        size_t p = enc[pos];
        if (p >= 32 || p > prev_len) { /* stray suffix byte / bad prefix */
            free(enc);
            return -1;
        }
        pos++;
        size_t suffix = 0;
        while (pos < elen && enc[pos] >= 32) {
            suffix++;
            pos++;
        }
        size_t len = p + suffix;
        if (len == 0) {
            free(enc);
            return -1;
        }
        total += len + 1; /* word + NUL */
        count++;
        prev_len = len;
    }
    if (count == 0) {
        free(enc);
        return -1;
    }

    char *data = malloc(total);
    const char **words = malloc(count * sizeof(*words));
    if (!data || !words) {
        free(data);
        free(words);
        free(enc);
        return -1;
    }

    /* Pass 2: decode. Each word copies its shared prefix from the previous
     * decoded word, which is already in the output buffer. */
    char *out = data;
    const char *prev = NULL;
    size_t idx = 0;
    pos = 0;
    while (pos < elen) {
        size_t p = enc[pos++];
        char *w = out;
        if (p > 0) memcpy(w, prev, p);
        out += p;
        while (pos < elen && enc[pos] >= 32) *out++ = (char)enc[pos++];
        *out++ = '\0';
        words[idx++] = w;
        prev = w;
    }
    free(enc);

    wl->data = data;
    wl->words = words;
    wl->count = count;
    return 0;
}

int wordlist_subset(const Wordlist *src, size_t max_length, Wordlist *subset) {
    if (!src || !subset || max_length == 0) return -1;

    size_t match_count = 0;
    for (size_t i = 0; i < src->count; i++) {
        if (strlen(src->words[i]) <= max_length) match_count++;
    }

    const char **words = NULL;
    if (match_count > 0) {
        words = malloc(match_count * sizeof(*words));
        if (!words) return -1;

        size_t j = 0;
        for (size_t i = 0; i < src->count; i++) {
            if (strlen(src->words[i]) <= max_length) words[j++] = src->words[i];
        }
    }

    subset->data = NULL;
    subset->words = words;
    subset->count = match_count;
    return 0;
}

void wordlist_free(Wordlist *wl) {
    if (!wl) return;
    free(wl->words);
    wl->words = NULL;
    free(wl->data);
    wl->data = NULL;
    wl->count = 0;
}
