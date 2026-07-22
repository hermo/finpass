#include <stdio.h>
#include <string.h>

#include "../src/words.h"

#define EXPECTED_COUNT 91427

static int failures = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

int main(void) {
    Wordlist wl = {0};
    int rc = wordlist_load(&wl);
    CHECK(rc == 0, "wordlist_load should succeed");
    if (rc != 0) {
        return 1;
    }

    CHECK(wl.count == EXPECTED_COUNT, "word count should be 91427");
    CHECK(strcmp(wl.words[0], "aakkonen") == 0, "first word should be aakkonen");
    CHECK(strcmp(wl.words[wl.count - 1], "zulu") == 0,
          "last word should be zulu");

    /* Front-coded decoding reconstructs each word from its predecessor, so
     * corruption compounds; spot-check a word deep in the list. */
    int found_kissa = 0;
    for (size_t i = 0; i < wl.count; i++) {
        if (strcmp(wl.words[i], "kissa") == 0) {
            found_kissa = 1;
            break;
        }
    }
    CHECK(found_kissa, "mid-list word 'kissa' should decode intact");

    for (size_t i = 0; i < wl.count; i++) {
        const char *w = wl.words[i];
        size_t len = strlen(w);
        CHECK(len > 0, "word should not be empty");
        if (len > 0) {
            char last = w[len - 1];
            CHECK(last != '\r' && last != ' ', "word should not end with \\r or space");
        }
    }

    Wordlist subset = {0};
    rc = wordlist_subset(&wl, 5, &subset);
    CHECK(rc == 0, "wordlist_subset should succeed");
    if (rc == 0) {
        CHECK(subset.data == NULL, "subset should not own a backing buffer");
        CHECK(subset.count > 0, "subset should be non-empty");
        CHECK(subset.count < wl.count, "subset should be smaller than the full list");

        for (size_t i = 0; i < subset.count; i++) {
            CHECK(strlen(subset.words[i]) <= 5, "subset word should be <= 5 bytes");
        }

        /* Subset pointers must alias the source's storage, not copies. */
        if (subset.count > 0) {
            CHECK(subset.words[0] == wl.words[0] ||
                      subset.words[0] != NULL,
                  "subset should hold non-null pointers");
        }
        int aliasing_checked = 0;
        for (size_t i = 0; i < subset.count && !aliasing_checked; i++) {
            for (size_t j = 0; j < wl.count; j++) {
                if (subset.words[i] == wl.words[j]) {
                    aliasing_checked = 1;
                    break;
                }
            }
        }
        CHECK(aliasing_checked, "subset words should share pointers with src");
    }

    /* Freeing the subset before the source it aliases must not crash, and
     * freeing either twice (or a zeroed struct) must be safe. */
    wordlist_free(&subset);
    wordlist_free(&subset);
    wordlist_free(&wl);
    wordlist_free(&wl);

    Wordlist zeroed = {0};
    wordlist_free(&zeroed);

    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d test(s) failed.\n", failures);
    return 1;
}
