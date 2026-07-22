/* wordenc: build-time encoder for the embedded wordlist.
 *
 * Converts a newline-separated wordlist into a self-delimiting front-coded
 * stream. Each entry is one control byte P (0..31) giving the number of
 * leading bytes shared with the previous word, followed by the bytes that
 * differ. Word bytes are restricted to printable ASCII (>= 33), so any byte
 * below 32 unambiguously starts a new entry and no terminators are needed.
 *
 * The format requires every word to be 1..31 bytes of printable ASCII and
 * consecutive lines to differ; violations are hard build errors so a future
 * wordlist change fails here instead of producing a corrupt embedding.
 *
 * Usage: wordenc <words.txt> <out.fc>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_WORD_LEN 31

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <words.txt> <out.fc>\n", argv[0]);
        return 2;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "wordenc: cannot open %s\n", argv[1]);
        return 1;
    }
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        fprintf(stderr, "wordenc: cannot open %s\n", argv[2]);
        fclose(in);
        return 1;
    }

    char line[256];
    char prev[MAX_WORD_LEN + 1] = "";
    size_t prev_len = 0;
    size_t lineno = 0;
    size_t count = 0;

    while (fgets(line, sizeof(line), in)) {
        lineno++;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            fprintf(stderr, "wordenc: %s:%zu: empty line\n", argv[1], lineno);
            return 1;
        }
        if (len > MAX_WORD_LEN) {
            fprintf(stderr,
                    "wordenc: %s:%zu: word '%s' is %zu bytes; format allows "
                    "at most %d\n",
                    argv[1], lineno, line, len, MAX_WORD_LEN);
            return 1;
        }
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)line[i];
            if (c < 33 || c > 126) {
                fprintf(stderr,
                        "wordenc: %s:%zu: word '%s' has byte 0x%02x outside "
                        "printable ASCII\n",
                        argv[1], lineno, line, c);
                return 1;
            }
        }

        size_t p = 0;
        while (p < prev_len && p < len && prev[p] == line[p]) p++;
        if (p == len && len == prev_len) {
            fprintf(stderr, "wordenc: %s:%zu: duplicate word '%s'\n", argv[1],
                    lineno, line);
            return 1;
        }

        if (fputc((int)p, out) == EOF ||
            fwrite(line + p, 1, len - p, out) != len - p) {
            fprintf(stderr, "wordenc: write error on %s\n", argv[2]);
            return 1;
        }

        memcpy(prev, line, len + 1);
        prev_len = len;
        count++;
    }

    if (ferror(in)) {
        fprintf(stderr, "wordenc: read error on %s\n", argv[1]);
        return 1;
    }
    fclose(in);
    if (fclose(out) != 0) {
        fprintf(stderr, "wordenc: write error on %s\n", argv[2]);
        return 1;
    }

    fprintf(stderr, "wordenc: %zu words encoded\n", count);
    return 0;
}
