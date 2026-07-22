#ifndef FINPASS_WORDS_H
#define FINPASS_WORDS_H

#include <stddef.h>

typedef struct {
    char *data;         /* owned backing buffer; NULL for subset views */
    const char **words; /* owned array of NUL-terminated word pointers */
    size_t count;
} Wordlist;

/* Loads the embedded wordlist from /zip/words.fc, a front-coded stream
 * produced at build time by c/tools/wordenc.c. Returns 0 on success, -1 on
 * failure (including a malformed stream). */
int wordlist_load(Wordlist *wl);

/* Fills *subset with pointers to the words of src whose byte length is
 * <= max_length (max_length must be > 0). The subset shares storage with
 * src and must be freed before src. Returns 0 on success, -1 on failure. */
int wordlist_subset(const Wordlist *src, size_t max_length, Wordlist *subset);

void wordlist_free(Wordlist *wl);

#endif
