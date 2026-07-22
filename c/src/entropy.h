#ifndef FINPASS_ENTROPY_H
#define FINPASS_ENTROPY_H

#include <stdbool.h>
#include <stddef.h>

/* A named attacker model: how fast it can try candidate passphrases. */
typedef struct {
    const char *name;
    const char *description;
    double speed; /* guesses per second */
} AttackProfile;

#define NUM_ATTACK_PROFILES 6

/* Fixed order: legacy, weak, standard, strong, paranoid, online. */
extern const AttackProfile ATTACK_PROFILES[NUM_ATTACK_PROFILES];

/* Looks up a profile by name in ATTACK_PROFILES. Returns NULL if unknown. */
const AttackProfile *get_profile(const char *name);

/* Entropy assuming the attacker only knows the character classes used
 * (lower/upper/digit/symbol), not the passphrase's word structure. */
double bruteforce_entropy(const char *passphrase);

/* Entropy assuming the attacker knows the word/separator/segment pattern
 * but must brute-force each word's characters (not a known wordlist).
 *
 * separator is the delimiter's first byte. For parity with the Go
 * reference (which computes rune(Delimiter[0]) and splits on its UTF-8
 * encoding), bytes >= 0x80 are internally re-encoded as a 2-byte UTF-8
 * sequence before splitting, so a multi-byte delimiter's actual lead byte
 * intentionally will not match. */
double pattern_aware_entropy(const char *passphrase, char separator, int word_count);

/* Entropy assuming the attacker knows the exact wordlist used. */
double wordlist_entropy(size_t wordlist_size, int word_count);

/* Maps entropy bits to one of "Weak", "Fair", "Good", "Strong", "Excellent". */
const char *strength_rating(double bits);

/* Formats the estimated time to crack (average case: half the search
 * space) into out, e.g. "42.3ky". out must hold at least 16 bytes. */
void format_time_to_crack(double entropy_bits, double guesses_per_second, char *out, size_t out_size);

/* Prints all attack profiles and their descriptions to stdout. */
void list_all_profiles(void);

/* Builds a human-readable entropy/crack-time report for passphrase.
 *
 * subset_size is the size of the length-restricted wordlist subset (i.e.
 * wordlist_subset() applied with max_length); it is only used, and only
 * meaningful, when max_length > 0. wordlist_size is the full wordlist size.
 *
 * If all_profiles is true, the report covers every attack profile and
 * custom_speed/profile_name are ignored. Otherwise, custom_speed > 0
 * selects a custom attacker speed; otherwise profile_name is looked up
 * via get_profile() and its speed used (an unknown name yields an error
 * message in the returned string instead of a failure).
 *
 * Returns a malloc'd NUL-terminated string, or NULL on allocation failure.
 * Caller must free() the result. */
char *display_entropy_info(const char *passphrase, char delimiter, int word_count,
                            size_t max_length, size_t subset_size, bool all_profiles,
                            double custom_speed, const char *profile_name,
                            size_t wordlist_size);

#endif
