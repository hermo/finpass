#ifndef FINPASS_PASSPHRASE_H
#define FINPASS_PASSPHRASE_H

#include <stddef.h>

#include "words.h"

/* Length of the mandatory alphanumeric segment (must contain both a
 * letter and a digit) appended to every generated passphrase. */
#define ALNUM_SEGMENT_LENGTH 3

/* Generates a passphrase of word_count words from wl (each word no longer
 * than max_length bytes if max_length > 0) plus one alphanumeric segment,
 * joined with delimiter, with the segment placed at a random position.
 * Returns a malloc'd NUL-terminated string, or NULL on error (invalid
 * arguments, empty wordlist subset, or RNG failure). Caller must free(). */
char *generate_passphrase(const Wordlist *wl, int word_count, size_t max_length, const char *delimiter);

#endif
