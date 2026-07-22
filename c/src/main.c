/* finpass: Finnish passphrase generator, CLI entry point.
 *
 * GNU-style option parsing via getopt_long. See README/main.go for the
 * original Go CLI this ports; behavior intentionally diverges where noted
 * below (notably: -n actually loops, and an empty delimiter is rejected
 * instead of crashing).
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entropy.h"
#include "passphrase.h"
#include "words.h"

#ifndef FINPASS_VERSION
#define FINPASS_VERSION "devel"
#endif

#define DEFAULT_WORD_COUNT 3
#define MIN_WORD_COUNT 1
#define MAX_WORD_COUNT 6
#define MIN_MAX_LENGTH 3
#define DEFAULT_COUNT 1
#define DEFAULT_DELIMITER "-"
#define DEFAULT_PROFILE "standard"

/* Value used for the --list-profiles long-only option (no short form). */
enum { OPT_LIST_PROFILES = 256 };

static void print_usage(FILE *out) {
    fprintf(out, "Usage: finpass [OPTIONS]\n");
    fprintf(out, "\nGenerate passphrases using Finnish language words.\n");
    fprintf(out, "\nOptions:\n");
    fprintf(out, "  -w, --words N          number of words (1-6, default: %d)\n", DEFAULT_WORD_COUNT);
    fprintf(out, "  -n, --count N          number of passphrases to generate (default: %d)\n", DEFAULT_COUNT);
    fprintf(out, "  -m, --max-length N     maximum length of each word component\n");
    fprintf(out, "                         (default: 0 = unlimited, min %d when set)\n", MIN_MAX_LENGTH);
    fprintf(out, "  -d, --delimiter S      delimiter between passphrase components (default: \"%s\")\n",
            DEFAULT_DELIMITER);
    fprintf(out, "  -i, --info             show entropy and estimated time to crack\n");
    fprintf(out, "  -p, --profile NAME     attack profile (legacy, weak, standard, strong,\n");
    fprintf(out, "                         paranoid, online; default: %s)\n", DEFAULT_PROFILE);
    fprintf(out, "  -s, --custom-speed N   custom attack speed (guesses per second)\n");
    fprintf(out, "  -a, --all-profiles     show entropy for all attack profiles\n");
    fprintf(out, "      --list-profiles    list available attack profiles\n");
    fprintf(out, "  -V, --version          show version information\n");
    fprintf(out, "  -h, --help             show this help message\n");
    fprintf(out, "\nExamples:\n");
    fprintf(out, "  finpass                # Generate one passphrase\n");
    fprintf(out, "  finpass -n 5           # Generate 5 passphrases\n");
    fprintf(out, "  finpass -i -p strong   # Show entropy analysis\n");
    fprintf(out, "  finpass -w 4 -d .      # 4 words with dot delimiter\n");
}

static void print_try_help(void) {
    fputs("Try 'finpass --help' for more information.\n", stderr);
}

/* Parses s as a base-10 long, requiring the whole string to be consumed.
 * Returns true on success. */
static bool parse_long_arg(const char *s, long *out) {
    if (s == NULL || *s == '\0') {
        return false;
    }
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || errno == ERANGE) {
        return false;
    }
    *out = v;
    return true;
}

/* Parses s as a double, requiring the whole string to be consumed. */
static bool parse_double_arg(const char *s, double *out) {
    if (s == NULL || *s == '\0') {
        return false;
    }
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (end == s || *end != '\0') {
        return false;
    }
    /* strtod sets ERANGE both on overflow (result is +/-HUGE_VAL) and on
     * gradual underflow to a subnormal (result is the correctly-rounded,
     * representable subnormal value). Go's strconv.ParseFloat accepts
     * subnormals, so only reject the overflow case to match. */
    if (errno == ERANGE && (v == HUGE_VAL || v == -HUGE_VAL)) {
        return false;
    }
    *out = v;
    return true;
}

static void invalid_value(const char *option, const char *value) {
    fprintf(stderr, "finpass: invalid value '%s' for %s\n", value, option);
    print_try_help();
    exit(1);
}

int main(int argc, char **argv) {
    int word_count = DEFAULT_WORD_COUNT;
    int count = DEFAULT_COUNT;
    long max_length_arg = 0;
    const char *delimiter = DEFAULT_DELIMITER;
    const char *profile_name = DEFAULT_PROFILE;
    double custom_speed = 0.0;
    bool show_info = false;
    bool all_profiles = false;
    bool list_profiles = false;
    bool show_version = false;
    bool show_help = false;

    static const struct option long_opts[] = {
        {"words", required_argument, NULL, 'w'},
        {"count", required_argument, NULL, 'n'},
        {"max-length", required_argument, NULL, 'm'},
        {"delimiter", required_argument, NULL, 'd'},
        {"info", no_argument, NULL, 'i'},
        {"profile", required_argument, NULL, 'p'},
        {"custom-speed", required_argument, NULL, 's'},
        {"all-profiles", no_argument, NULL, 'a'},
        {"list-profiles", no_argument, NULL, OPT_LIST_PROFILES},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "w:n:m:d:ip:s:aVh", long_opts, NULL)) != -1) {
        long lv;
        double dv;
        switch (opt) {
        case 'w':
            if (!parse_long_arg(optarg, &lv) || lv < INT_MIN || lv > INT_MAX) {
                invalid_value("-w/--words", optarg);
            }
            word_count = (int)lv;
            break;
        case 'n':
            if (!parse_long_arg(optarg, &lv) || lv < INT_MIN || lv > INT_MAX) {
                invalid_value("-n/--count", optarg);
            }
            count = (int)lv;
            break;
        case 'm':
            if (!parse_long_arg(optarg, &lv) || lv < 0) {
                invalid_value("-m/--max-length", optarg);
            }
            max_length_arg = lv;
            break;
        case 'd':
            delimiter = optarg;
            break;
        case 'i':
            show_info = true;
            break;
        case 'p':
            profile_name = optarg;
            break;
        case 's':
            if (!parse_double_arg(optarg, &dv)) {
                invalid_value("-s/--custom-speed", optarg);
            }
            custom_speed = dv;
            break;
        case 'a':
            all_profiles = true;
            break;
        case OPT_LIST_PROFILES:
            list_profiles = true;
            break;
        case 'V':
            show_version = true;
            break;
        case 'h':
            show_help = true;
            break;
        case '?':
        default:
            print_try_help();
            return 1;
        }
    }

    if (show_help) {
        print_usage(stdout);
        return 0;
    }

    if (show_version) {
        printf("finpass version %s\n", FINPASS_VERSION);
        printf("Generate passphrases using Finnish language words\n");
        return 0;
    }

    if (list_profiles) {
        list_all_profiles();
        return 0;
    }

    if (max_length_arg > 0 && max_length_arg < MIN_MAX_LENGTH) {
        fprintf(stderr, "maxlen must be at least %d\n", MIN_MAX_LENGTH);
        return 1;
    }

    if (word_count < MIN_WORD_COUNT || word_count > MAX_WORD_COUNT) {
        fprintf(stderr, "word count must be between %d and %d\n", MIN_WORD_COUNT, MAX_WORD_COUNT);
        return 1;
    }

    if (count < DEFAULT_COUNT) {
        fprintf(stderr, "count must be at least %d\n", DEFAULT_COUNT);
        return 1;
    }

    if (count > 1 && (show_info || all_profiles)) {
        fprintf(stderr,
                "entropy analysis (-i or -a) cannot be used with multiple passphrases (-n > 1)\n");
        return 1;
    }

    if (delimiter[0] == '\0') {
        fprintf(stderr, "delimiter must not be empty\n");
        return 1;
    }

    size_t max_length = (size_t)max_length_arg;

    Wordlist wl;
    if (wordlist_load(&wl) != 0) {
        fprintf(stderr, "failed to load wordlist\n");
        return 1;
    }

    char *passphrase = NULL;
    int status = 0;
    for (int i = 0; i < count; i++) {
        char *p = generate_passphrase(&wl, word_count, max_length, delimiter);
        if (p == NULL) {
            fprintf(stderr, "failed to generate passphrase\n");
            status = 1;
            break;
        }
        if (i > 0) {
            free(passphrase);
        }
        passphrase = p;
        puts(passphrase);
    }

    if (status == 0 && (show_info || all_profiles)) {
        Wordlist subset = {0};
        size_t subset_size = 0;
        if (max_length > 0) {
            if (wordlist_subset(&wl, max_length, &subset) != 0) {
                fprintf(stderr, "failed to compute wordlist subset\n");
                status = 1;
            } else {
                subset_size = subset.count;
            }
        }
        if (status == 0) {
            char *report = display_entropy_info(passphrase, delimiter[0], word_count, max_length,
                                                  subset_size, all_profiles, custom_speed,
                                                  profile_name, wl.count);
            if (report == NULL) {
                fprintf(stderr, "failed to build entropy report\n");
                status = 1;
            } else {
                fputs(report, stdout);
                free(report);
            }
        }
        if (max_length > 0) {
            wordlist_free(&subset);
        }
    }

    free(passphrase);
    wordlist_free(&wl);
    return status;
}
