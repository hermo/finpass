/* Standalone unit tests for c/src/entropy.c. Does not need the embedded
 * wordlist: entropy math only depends on wordlist *size*, never its
 * contents. Exits 0 on success, 1 if any check fails. */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/entropy.h"

#define TOLERANCE 1e-9

static int failures = 0;

static void check_double(const char *name, double got, double want)
{
    if (fabs(got - want) > TOLERANCE) {
        printf("FAIL %s: got %.17g, want %.17g\n", name, got, want);
        failures++;
    }
}

static void check_str(const char *name, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("FAIL %s: got \"%s\", want \"%s\"\n", name, got, want);
        failures++;
    }
}

static void check_true(const char *name, int cond)
{
    if (!cond) {
        printf("FAIL %s\n", name);
        failures++;
    }
}

static void test_bruteforce_entropy(void)
{
    check_double("bruteforce_entropy(\"abc\")", bruteforce_entropy("abc"), 14.101319154423276);
    check_double("bruteforce_entropy(\"ABC\")", bruteforce_entropy("ABC"), 14.101319154423276);
    check_double("bruteforce_entropy(\"123\")", bruteforce_entropy("123"), 9.965784284662087);
    check_double("bruteforce_entropy(\"!@#\")", bruteforce_entropy("!@#"), 15.0);
    check_double("bruteforce_entropy(\"aB1!\")", bruteforce_entropy("aB1!"), 26.21835540671055);
}

static void test_wordlist_entropy(void)
{
    check_double("wordlist_entropy(91000, 3)", wordlist_entropy(91000, 3), 66.19799208977426);
}

static void test_pattern_aware_entropy(void)
{
    /* "abc-def-A1B" split on '-': two 3-letter words plus a segment that
     * has both a letter and a digit and is exactly 3 bytes, so it's
     * skipped from the letter-brute-force sum. */
    double got = pattern_aware_entropy("abc-def-A1B", '-', 2);
    double want = 2.0 * 3.0 * log2(26.0) +
                  log2(pow(36.0, 3) - pow(26.0, 3) - pow(10.0, 3)) +
                  log2(3.0);
    check_double("pattern_aware_entropy(\"abc-def-A1B\", '-', 2)", got, want);

    /* Segment with a letter+digit but NOT length 3 must still be counted
     * as ordinary letter characters (only exact length-3 alnum segments
     * are treated as the special segment). */
    double got2 = pattern_aware_entropy("abc-def-A1B2", '-', 2);
    double want2 = 2.0 * 3.0 * log2(26.0) + 4.0 * log2(26.0) +
                   log2(pow(36.0, 3) - pow(26.0, 3) - pow(10.0, 3)) +
                   log2(3.0);
    check_double("pattern_aware_entropy(\"abc-def-A1B2\", '-', 2)", got2, want2);

    /* Multi-byte UTF-8 delimiter (e.g. -d ä, whose first byte is 0xC3):
     * for parity with the Go reference's rune(Delimiter[0]) + strings.Split
     * behavior, this must split on the 2-byte UTF-8 encoding of code point
     * 0xC3 (bytes C3 83), which never occurs in the passphrase below, so
     * the whole string is treated as a single part. */
    double got3 = pattern_aware_entropy("sana\xC3\xA4korjaus\xC3\xA4T3Q", (char)0xC3, 2);
    double want3 = 18.0 * log2(26.0) +
                   log2(pow(36.0, 3) - pow(26.0, 3) - pow(10.0, 3)) +
                   log2(3.0);
    check_double("pattern_aware_entropy multi-byte delimiter (Go parity)", got3, want3);
}

static void test_strength_rating(void)
{
    struct {
        double bits;
        const char *want;
    } cases[] = {
        {0, "Weak"}, {10, "Weak"}, {25, "Weak"}, {34.9, "Weak"},
        {35, "Fair"}, {42, "Fair"}, {49.9, "Fair"},
        {50, "Good"}, {57, "Good"}, {64.9, "Good"},
        {65, "Strong"}, {68, "Strong"}, {75, "Strong"}, {84.9, "Strong"},
        {85, "Excellent"}, {100, "Excellent"}, {128, "Excellent"}, {256, "Excellent"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_str("strength_rating", strength_rating(cases[i].bits), cases[i].want);
    }
}

static void test_format_time_to_crack(void)
{
    struct {
        double bits;
        double speed;
        const char *want;
    } cases[] = {
        {10, 100, "5s"},
        {1, 100, "10ms"},
        {20, 1e9, "instant"},
        {30, 1e9, "537ms"},
        {35, 1e9, "17s"},
        {40, 1e9, "9m"},
        {45, 1e9, "5h"},
        {50, 1e9, "7d"},
        {60, 1e9, "18.3y"},
        {70, 1e9, "19ky"},
        {80, 1e9, "19My"},
        {90, 1e9, "20By"},
        {100, 1e9, "20Ty"},
        {110, 1e9, "21Qy"},
        {140, 1e9, "1e25y"},
    };
    char out[16];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        format_time_to_crack(cases[i].bits, cases[i].speed, out, sizeof out);
        check_str("format_time_to_crack", out, cases[i].want);
    }

    /* Entropy large enough that pow(2, bits) overflows to +Inf must render
     * like Go's fmt ("+Inf"), not C printf's "inf". */
    format_time_to_crack(4000, 1e9, out, sizeof out);
    check_str("format_time_to_crack overflow to infinity", out, "1e+Infy");

    /* When both guesses and guesses_per_second are +Inf, seconds is NaN;
     * this must render like Go's fmt ("NaN"), not C printf's "-nan". */
    format_time_to_crack(4000, INFINITY, out, sizeof out);
    check_str("format_time_to_crack NaN renders as NaN", out, "1eNaNy");
}

static void test_get_profile(void)
{
    const AttackProfile *p = get_profile("standard");
    check_true("get_profile(\"standard\") non-NULL", p != NULL);
    if (p != NULL) {
        check_str("get_profile(\"standard\")->name", p->name, "standard");
        check_double("get_profile(\"standard\")->speed", p->speed, 11.0e6);
    }

    check_true("get_profile(\"nope\") is NULL", get_profile("nope") == NULL);

    /* Every documented profile must resolve and carry a positive speed
     * and non-empty description. */
    const char *names[NUM_ATTACK_PROFILES] = {"legacy", "weak", "standard", "strong", "paranoid", "online"};
    for (size_t i = 0; i < NUM_ATTACK_PROFILES; i++) {
        const AttackProfile *pp = get_profile(names[i]);
        check_true(names[i], pp != NULL && pp->speed > 0 && pp->description[0] != '\0');
    }
}

static void test_display_entropy_info_unknown_profile(void)
{
    char *out = display_entropy_info("abc-def-A1B", '-', 2, 0, 0, false, 0.0, "nope", 91000);
    check_true("display_entropy_info unknown profile non-NULL", out != NULL);
    if (out != NULL) {
        check_str("display_entropy_info unknown profile message", out,
                   "Unknown profile: nope\nUse --list-profiles to see available profiles");
        free(out);
    }
}

static void test_display_entropy_info_smoke(void)
{
    /* Not byte-comparing the whole report here (that needs a live
     * wordlist size matching a real run); just check it doesn't crash,
     * returns non-NULL, and contains an expected fragment. */
    char *out = display_entropy_info("abc-def-A1B", '-', 2, 0, 0, true, 0.0, NULL, 91000);
    check_true("display_entropy_info all_profiles non-NULL", out != NULL);
    if (out != NULL) {
        check_true("display_entropy_info all_profiles contains header",
                   strstr(out, "Passphrase entropy analysis:\n") != NULL);
        check_true("display_entropy_info all_profiles contains legacy row",
                   strstr(out, "legacy") != NULL);
        free(out);
    }

    char *out2 = display_entropy_info("abc-def-A1B", '-', 2, 0, 0, false, 1e7, NULL, 91000);
    check_true("display_entropy_info custom speed non-NULL", out2 != NULL);
    if (out2 != NULL) {
        check_true("display_entropy_info custom speed description",
                   strstr(out2, "custom speed (1e+07 guesses/sec)") != NULL);
        free(out2);
    }

    /* --custom-speed inf must render "+Inf" like Go's fmt, not C printf's
     * "inf". */
    char *out3 = display_entropy_info("abc-def-A1B", '-', 2, 0, 0, false, INFINITY, NULL, 91000);
    check_true("display_entropy_info infinite custom speed non-NULL", out3 != NULL);
    if (out3 != NULL) {
        check_true("display_entropy_info infinite custom speed description",
                   strstr(out3, "custom speed (+Inf guesses/sec)") != NULL);
        free(out3);
    }
}

int main(void)
{
    test_bruteforce_entropy();
    test_wordlist_entropy();
    test_pattern_aware_entropy();
    test_strength_rating();
    test_format_time_to_crack();
    test_get_profile();
    test_display_entropy_info_unknown_profile();
    test_display_entropy_info_smoke();

    if (failures > 0) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("All entropy checks passed\n");
    return 0;
}
