#include "entropy.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Character set sizes, mirroring internal/entropy/entropy.go's constants. */
#define LOWERCASE_CHARS 26
#define UPPERCASE_CHARS 26
#define DIGIT_CHARS 10
#define SYMBOL_CHARS 32
#define WORD_CHARS 26

/* Length of the mandatory alphanumeric segment; must match
 * ALNUM_SEGMENT_LENGTH in passphrase.h and AlphaNumericSegmentLength in
 * internal/entropy/entropy.go. */
#define ALNUM_SEG_LEN 3

const AttackProfile ATTACK_PROFILES[NUM_ATTACK_PROFILES] = {
    {"legacy", "Weak legacy hashes (NTLM)", 308.2e9},
    {"weak", "Fast modern hashes (SHA256)", 27.6e9},
    {"standard", "Typical web app security (PBKDF2)", 11.0e6},
    {"strong", "Security-focused apps (bcrypt)", 300.5e3},
    {"paranoid", "Maximum security (scrypt)", 8.9e3},
    {"online", "Rate-limited online attacks", 100},
};

const AttackProfile *get_profile(const char *name)
{
    for (size_t i = 0; i < NUM_ATTACK_PROFILES; i++) {
        if (strcmp(ATTACK_PROFILES[i].name, name) == 0) {
            return &ATTACK_PROFILES[i];
        }
    }
    return NULL;
}

double bruteforce_entropy(const char *passphrase)
{
    bool lowercase = false;
    bool uppercase = false;
    bool digits = false;
    bool symbols = false;

    size_t len = strlen(passphrase);
    for (size_t i = 0; i < len; i++) {
        /* Byte-wise classification: any UTF-8 continuation/lead byte falls
         * outside a-z/A-Z/0-9 and only sets the symbols flag, which matches
         * Go's rune-wise classification of the same non-ASCII rune. */
        unsigned char c = (unsigned char)passphrase[i];
        if (c >= 'a' && c <= 'z') {
            lowercase = true;
        } else if (c >= 'A' && c <= 'Z') {
            uppercase = true;
        } else if (c >= '0' && c <= '9') {
            digits = true;
        } else {
            symbols = true;
        }
    }

    int characters = 0;
    if (lowercase) characters += LOWERCASE_CHARS;
    if (uppercase) characters += UPPERCASE_CHARS;
    if (digits) characters += DIGIT_CHARS;
    if (symbols) characters += SYMBOL_CHARS;

    return (double)len * log2((double)characters);
}

double wordlist_entropy(size_t wordlist_size, int word_count)
{
    double words_ent = (double)word_count * log2((double)wordlist_size);
    double alnum_ent = log2(pow(36.0, ALNUM_SEG_LEN) - pow(26.0, ALNUM_SEG_LEN) - pow(10.0, ALNUM_SEG_LEN));
    double positional_ent = log2((double)(word_count + 1));
    return words_ent + alnum_ent + positional_ent;
}

/* Encodes b as UTF-8, treating it as a Unicode code point in [0,255].
 * Mirrors Go's main.go computing delimiterRune := rune(Delimiter[0]) and
 * entropy.go splitting on string(delimiterRune): for b >= 0x80 this
 * produces the *2-byte UTF-8 encoding of that code point*, not b itself,
 * so it deliberately does not match a multi-byte delimiter's actual lead
 * byte. Replicated here (rather than splitting on the raw byte) for
 * parity with the Go reference's displayed pattern-aware entropy. out
 * must hold at least 2 bytes. Returns the number of bytes written. */
static size_t go_rune_utf8(unsigned char b, char out[2])
{
    if (b < 0x80) {
        out[0] = (char)b;
        return 1;
    }
    out[0] = (char)(0xC0 | (b >> 6));
    out[1] = (char)(0x80 | (b & 0x3F));
    return 2;
}

/* Scores one part (the substring passphrase[part_start:part_end]) of a
 * pattern-aware split, adding its letter-brute-force contribution to
 * *words_ent unless it is exactly the alphanumeric segment. */
static void score_pattern_part(const char *passphrase, size_t part_start, size_t part_end, double *words_ent)
{
    size_t part_len = part_end - part_start;
    bool has_letter = false;
    bool has_digit = false;
    for (size_t j = part_start; j < part_end; j++) {
        unsigned char c = (unsigned char)passphrase[j];
        if (c >= 'A' && c <= 'Z') {
            has_letter = true;
        } else if (c >= '0' && c <= '9') {
            has_digit = true;
        }
    }

    if (has_letter && has_digit && part_len == ALNUM_SEG_LEN) {
        /* This is the alphanumeric segment, skip it. */
    } else {
        *words_ent += (double)part_len * log2((double)WORD_CHARS);
    }
}

double pattern_aware_entropy(const char *passphrase, char separator, int word_count)
{
    double words_ent = 0.0;
    size_t n = strlen(passphrase);
    size_t part_start = 0;

    char sep_bytes[2];
    size_t sep_len = go_rune_utf8((unsigned char)separator, sep_bytes);

    /* Manual split on the (possibly 2-byte) separator sequence that
     * preserves empty parts, matching strings.Split(passphrase,
     * string(delimiterRune)) (e.g. "" -> one empty part, a trailing
     * separator -> a trailing empty part). */
    size_t i = 0;
    while (i < n) {
        if (i + sep_len <= n && memcmp(passphrase + i, sep_bytes, sep_len) == 0) {
            score_pattern_part(passphrase, part_start, i, &words_ent);
            i += sep_len;
            part_start = i;
        } else {
            i++;
        }
    }
    score_pattern_part(passphrase, part_start, n, &words_ent);

    double alnum_ent = log2(pow(36.0, ALNUM_SEG_LEN) - pow(26.0, ALNUM_SEG_LEN) - pow(10.0, ALNUM_SEG_LEN));
    double positional_ent = log2((double)(word_count + 1));

    return words_ent + alnum_ent + positional_ent;
}

const char *strength_rating(double bits)
{
    if (bits < 35) return "Weak";
    if (bits < 50) return "Fair";
    if (bits < 65) return "Good";
    if (bits < 85) return "Strong";
    return "Excellent";
}

void format_time_to_crack(double entropy_bits, double guesses_per_second, char *out, size_t out_size)
{
    double guesses = pow(2.0, entropy_bits) / 2.0; /* average case: halfway through the search space */
    double seconds = guesses / guesses_per_second;
    double years = seconds / (60.0 * 60.0 * 24.0 * 365.0);

    if (seconds < 1e-3) {
        snprintf(out, out_size, "instant");
    } else if (seconds < 1) {
        snprintf(out, out_size, "%.0fms", seconds * 1000);
    } else if (seconds < 60) {
        snprintf(out, out_size, "%.0fs", seconds);
    } else if (seconds < 3600) {
        snprintf(out, out_size, "%.0fm", seconds / 60);
    } else if (seconds < 86400) {
        snprintf(out, out_size, "%.0fh", seconds / 3600);
    } else if (years < 1) {
        snprintf(out, out_size, "%.0fd", seconds / 86400);
    } else if (years < 1e3) {
        snprintf(out, out_size, "%.1fy", years);
    } else if (years < 1e6) {
        snprintf(out, out_size, "%.0fky", years / 1e3);
    } else if (years < 1e9) {
        snprintf(out, out_size, "%.0fMy", years / 1e6);
    } else if (years < 1e12) {
        snprintf(out, out_size, "%.0fBy", years / 1e9);
    } else if (years < 1e15) {
        snprintf(out, out_size, "%.0fTy", years / 1e12);
    } else if (years < 1e18) {
        snprintf(out, out_size, "%.0fQy", years / 1e15);
    } else {
        double exp = log10(years);
        if (isinf(exp)) {
            /* C's printf renders infinity as "inf"; match Go's fmt, which
             * renders it "+Inf" (years overflows to +Inf for very large
             * entropy, e.g. from an extremely long delimiter). */
            snprintf(out, out_size, "1e+Infy");
        } else if (isnan(exp)) {
            /* C's printf renders NaN as "-nan"/"nan"; match Go's fmt, which
             * renders it "NaN" (years is NaN when guesses and
             * guesses_per_second are both infinite, e.g. custom-speed=inf
             * with an extremely long delimiter). */
            snprintf(out, out_size, "1eNaNy");
        } else {
            snprintf(out, out_size, "1e%.0fy", exp);
        }
    }
}

void list_all_profiles(void)
{
    printf("Available attack profiles:\n");
    for (size_t i = 0; i < NUM_ATTACK_PROFILES; i++) {
        printf("  %-10s - %s\n", ATTACK_PROFILES[i].name, ATTACK_PROFILES[i].description);
    }
}

/* Growing heap buffer used to assemble display_entropy_info()'s report;
 * cosmopolitan libc lacks open_memstream, so this is a manual appender. */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} StrBuf;

static int sb_init(StrBuf *sb)
{
    sb->cap = 256;
    sb->buf = malloc(sb->cap);
    if (!sb->buf) return -1;
    sb->buf[0] = '\0';
    sb->len = 0;
    return 0;
}

static int sb_append(StrBuf *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) {
        va_end(ap2);
        return -1;
    }

    size_t need_cap = sb->len + (size_t)needed + 1;
    if (need_cap > sb->cap) {
        size_t new_cap = sb->cap;
        while (new_cap < need_cap) new_cap *= 2;
        char *nb = realloc(sb->buf, new_cap);
        if (!nb) {
            va_end(ap2);
            return -1;
        }
        sb->buf = nb;
        sb->cap = new_cap;
    }

    vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap2);
    va_end(ap2);
    sb->len += (size_t)needed;
    return 0;
}

char *display_entropy_info(const char *passphrase, char delimiter, int word_count,
                            size_t max_length, size_t subset_size, bool all_profiles,
                            double custom_speed, const char *profile_name,
                            size_t wordlist_size)
{
    double brute_ent = bruteforce_entropy(passphrase);
    double pattern_ent = pattern_aware_entropy(passphrase, delimiter, word_count);
    double wordlist_ent = wordlist_entropy(wordlist_size, word_count);

    StrBuf sb;
    if (sb_init(&sb) != 0) return NULL;

    if (all_profiles) {
        if (sb_append(&sb, "Passphrase entropy analysis:\n") != 0) goto fail;
        if (sb_append(&sb, "  Brute-force:          %5.1f bits (%s)\n", brute_ent, strength_rating(brute_ent)) != 0) goto fail;
        if (sb_append(&sb, "  Pattern-aware attack: %5.1f bits (%s)\n", pattern_ent, strength_rating(pattern_ent)) != 0) goto fail;
        if (sb_append(&sb, "  Known wordlist:       %5.1f bits (%s)\n", wordlist_ent, strength_rating(wordlist_ent)) != 0) goto fail;
        if (max_length > 0) {
            double wordlist_ent_with_size = wordlist_entropy(subset_size, word_count);
            if (sb_append(&sb, "  Known wordlist+params:%5.1f bits\n", wordlist_ent_with_size) != 0) goto fail;
        }
        if (sb_append(&sb, "\n") != 0) goto fail;

        if (sb_append(&sb, "Time to crack estimates by attack scenario:\n") != 0) goto fail;
        if (sb_append(&sb, "%-10s %-18s %-18s %-18s", "Profile", "Brute-force", "Pattern-aware", "Wordlist") != 0) goto fail;
        if (max_length > 0) {
            if (sb_append(&sb, " %-18s", "Wordlist+params") != 0) goto fail;
        }
        if (sb_append(&sb, "\n") != 0) goto fail;

        if (sb_append(&sb, "%-10s %-18s %-18s %-18s", "-------", "------------------", "------------------", "------------------") != 0) goto fail;
        if (max_length > 0) {
            if (sb_append(&sb, " %-18s", "------------------") != 0) goto fail;
        }
        if (sb_append(&sb, "\n") != 0) goto fail;

        static const char *table_order[NUM_ATTACK_PROFILES] = {"online", "paranoid", "strong", "standard", "weak", "legacy"};
        for (size_t i = 0; i < NUM_ATTACK_PROFILES; i++) {
            const AttackProfile *p = get_profile(table_order[i]);
            char t_brute[16];
            char t_pattern[16];
            char t_wordlist[16];
            format_time_to_crack(brute_ent, p->speed, t_brute, sizeof t_brute);
            format_time_to_crack(pattern_ent, p->speed, t_pattern, sizeof t_pattern);
            format_time_to_crack(wordlist_ent, p->speed, t_wordlist, sizeof t_wordlist);
            if (sb_append(&sb, "%-10s %-18s %-18s %-18s", p->name, t_brute, t_pattern, t_wordlist) != 0) goto fail;
            if (max_length > 0) {
                double wordlist_ent_with_size = wordlist_entropy(subset_size, word_count);
                char t_wordlist_size[16];
                format_time_to_crack(wordlist_ent_with_size, p->speed, t_wordlist_size, sizeof t_wordlist_size);
                if (sb_append(&sb, " %-18s", t_wordlist_size) != 0) goto fail;
            }
            if (sb_append(&sb, "\n") != 0) goto fail;
        }
    } else {
        double speed;
        char custom_desc[64];
        const char *profile_desc;

        if (custom_speed > 0) {
            speed = custom_speed;
            if (isinf(speed)) {
                /* C's "%.0e" renders infinity as "inf"; match Go's fmt,
                 * which renders it "+Inf" (reachable via --custom-speed
                 * inf/Inf, which both strtod and Go's flag parser accept). */
                snprintf(custom_desc, sizeof custom_desc, "custom speed (+Inf guesses/sec)");
            } else {
                snprintf(custom_desc, sizeof custom_desc, "custom speed (%.0e guesses/sec)", speed);
            }
            profile_desc = custom_desc;
        } else {
            const AttackProfile *p = get_profile(profile_name);
            if (!p) {
                free(sb.buf);
                StrBuf err;
                if (sb_init(&err) != 0) return NULL;
                if (sb_append(&err, "Unknown profile: %s\nUse --list-profiles to see available profiles", profile_name) != 0) {
                    free(err.buf);
                    return NULL;
                }
                return err.buf;
            }
            speed = p->speed;
            profile_desc = p->description;
        }

        char t_brute[16];
        char t_pattern[16];
        char t_wordlist[16];
        format_time_to_crack(brute_ent, speed, t_brute, sizeof t_brute);
        format_time_to_crack(pattern_ent, speed, t_pattern, sizeof t_pattern);
        format_time_to_crack(wordlist_ent, speed, t_wordlist, sizeof t_wordlist);

        if (sb_append(&sb, "Entropy and estimated time to crack using %s:\n", profile_desc) != 0) goto fail;
        if (sb_append(&sb, "* Brute-force:           %5.1f bits (%s) - %s\n", brute_ent, strength_rating(brute_ent), t_brute) != 0) goto fail;
        if (sb_append(&sb, "* Pattern-aware attack:  %5.1f bits (%s) - %s\n", pattern_ent, strength_rating(pattern_ent), t_pattern) != 0) goto fail;
        if (sb_append(&sb, "* Known wordlist:        %5.1f bits (%s) - %s\n", wordlist_ent, strength_rating(wordlist_ent), t_wordlist) != 0) goto fail;
        if (max_length > 0) {
            double wordlist_ent_with_size = wordlist_entropy(subset_size, word_count);
            char t_wordlist_size[16];
            format_time_to_crack(wordlist_ent_with_size, speed, t_wordlist_size, sizeof t_wordlist_size);
            if (sb_append(&sb, "* Known wordlist and parameters (-m=%zu): %5.1f bits (%s)\n", max_length, wordlist_ent_with_size, t_wordlist_size) != 0) goto fail;
        }
    }

    return sb.buf;

fail:
    free(sb.buf);
    return NULL;
}
