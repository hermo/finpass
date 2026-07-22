#include "words.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORDLIST_PATH "/zip/words.txt"

/* ASCII whitespace only, matching the byte set strings.TrimSpace collapses
 * for the plain-ASCII wordlist (space, tab, newline, vtab, formfeed, CR). */
static int is_ascii_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
           c == '\r';
}

/* Reads the whole file into a NUL-terminated, growable heap buffer.
 * zipos does not support fseek/ftell for size discovery, so we grow by
 * doubling as we read. *out_len excludes the trailing sentinel NUL. */
static int read_whole_file(FILE *f, char **out_buf, size_t *out_len) {
    size_t cap = 1u << 16;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return -1;

    for (;;) {
        if (len == cap) {
            size_t new_cap = cap * 2;
            char *new_buf = realloc(buf, new_cap);
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

    /* Reserve one extra byte for a sentinel NUL used as an in-place
     * terminator for the final line even when it lacks a trailing '\n'. */
    char *final_buf = realloc(buf, len + 1);
    if (!final_buf) {
        free(buf);
        return -1;
    }
    final_buf[len] = '\0';

    *out_buf = final_buf;
    *out_len = len;
    return 0;
}

int wordlist_load(Wordlist *wl) {
    if (!wl) return -1;

    FILE *f = fopen(WORDLIST_PATH, "rb");
    if (!f) return -1;

    char *buf = NULL;
    size_t len = 0;
    int rc = read_whole_file(f, &buf, &len);
    fclose(f);
    if (rc != 0) return -1;

    size_t words_cap = 1u << 10;
    const char **words = malloc(words_cap * sizeof(*words));
    if (!words) {
        free(buf);
        return -1;
    }
    size_t count = 0;

    size_t pos = 0;
    while (pos < len) {
        char *nl = memchr(buf + pos, '\n', len - pos);
        size_t line_end = nl ? (size_t)(nl - buf) : len;

        char *start = buf + pos;
        char *end = buf + line_end;
        while (start < end && is_ascii_space((unsigned char)*start)) start++;
        while (end > start && is_ascii_space((unsigned char)end[-1])) end--;

        if (start != end) {
            if (count == words_cap) {
                size_t new_cap = words_cap * 2;
                const char **new_words =
                    realloc(words, new_cap * sizeof(*new_words));
                if (!new_words) {
                    free(words);
                    free(buf);
                    return -1;
                }
                words = new_words;
                words_cap = new_cap;
            }
            *end = '\0';
            words[count++] = start;
        }

        pos = nl ? line_end + 1 : len;
    }

    wl->data = buf;
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
