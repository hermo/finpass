# Generate passphrases using Finnish language words

This tiny program generates somewhat memorable passphrases in Finnish.
Each generated password also includes a randomly placed 3-character alphanumeric section to add entropy.

## Flags

| Flag              | Description                                                    |
|-------------------|----------------------------------------------------------------|
| `-i`              | Show entropy and estimated time to crack                      |
| `-m MAXLEN`       | Maximum length of each word component                         |
| `-d DELIM`        | Specify delimiter (default is `-`)                           |
| `-w COUNT`        | Number of words (1-6, default is 3)                          |
| `-n COUNT`        | Number of passphrases to generate (default is 1)               |
| `-profile NAME`   | Attack profile for entropy calculation (default is `standard`) |
| `-list-profiles`  | Show available attack profiles                                |
| `-all-profiles`   | Show entropy for all attack profiles                         |
| `-custom-speed N` | Custom attack speed (guesses per second)                     |

### Attack Profiles

Available profiles for entropy calculation:
- `legacy` - Weak legacy hashes (NTLM)
- `weak` - Fast modern hashes (SHA256)
- `standard` - Typical web app security (PBKDF2)
- `strong` - Security-focused apps (bcrypt)
- `paranoid` - Maximum security (scrypt)
- `online` - Rate-limited online attacks

Example:

```
$ finpass -i -m 7 -d . -w 4 -profile strong
36C.kytkea.terkut.koukuta
Entropy and estimated time to crack using Security-focused apps (bcrypt):
* Brute-force:           154.2 bits (1e46y)
* Pattern-aware attack:   66.5 bits (170ky)
* Known wordlist:         58.6 bits (7y)
* Known wordlist and parameters (-m=7): 50.1 bits (3d)
```

The wordlist contains about 91k words and is a subset of the wordlist found at https://github.com/hugovk/everyfinnishword

## Installation

Pre-built releases exist for Linux, macOS and Windows on amd64/arm64 platforms. See the releases for details.

## Randomness Testing

The passphrase generator has been thoroughly tested for randomness quality using statistical analysis:

### Test Results (100,000 passphrase sample)

- **Word Selection Randomness**: ✅ EXCELLENT
  - Coefficient of Variation: 0.5071 vs expected 0.5415 (6.4% deviation)
  - Follows proper Poisson distribution for random selection

- **Position Distribution**: ✅ NEAR-PERFECT
  - Position 1: 25.23%, Position 2: 25.27%, Position 3: 24.84%, Position 4: 24.69%
  - Maximum deviation from expected 25%: only 0.31%

- **Alphanumeric Segments**: ✅ GOOD
  - 27,245 unique segments from 100,019 total
  - Proper distribution across 46,656 possible combinations

- **Duplicate Prevention**: ✅ PERFECT
  - 0 duplicates in 100,000 generated passphrases

- **Wordlist Coverage**: ✅ EXCELLENT
  - 96.19% coverage vs expected 96.24% (0.04% difference)
  - Uniform sampling across the entire wordlist

Run [`test-randomness.sh`](test-randomness.sh) to perform your own randomness analysis.

## Building from Source

### Prerequisites
- Go 1.21 or later
- The compressed wordlist file (`words.txt.gz`) must be present

### Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/hermo/finpass.git
   cd finpass
   ```

2. Build the optimized binary:
   ```bash
   go build -ldflags="-s -w" -o finpass
   ```

**Note**: The compressed wordlist file `words.txt.gz` is committed to the repository and embedded during build. No additional steps are needed.

### Build Details

The binary uses an embedded compressed wordlist for optimal size:
- **Wordlist**: 91,443 Finnish words compressed from 1.1MB to 321KB (69.6% reduction)
- **Binary size**: ~2.2MB (down from 5.0MB unoptimized)
- **Startup time**: ~17ms (includes wordlist decompression)
- **Dependencies**: None (uses only Go standard library)

The wordlist is automatically decompressed at startup using `//go:embed` and gzip compression.

### Development

For development builds without optimization:
```bash
go build
```

For release builds with full optimization:
```bash
go build -ldflags="-s -w -X main.version=$(git describe --tags)"
```

### Updating the Wordlist

If you need to update the Finnish wordlist:

1. **Replace the source wordlist**:
   ```bash
   # Replace words.txt with your new wordlist (one word per line)
   # Example: download from https://github.com/hugovk/everyfinnishword
   ```

2. **Regenerate the compressed wordlist**:
   ```bash
   gzip -9 -c words.txt > words.txt.gz
   ```

3. **Rebuild the binary**:
   ```bash
   go build -ldflags="-s -w" -o finpass
   ```

**Important**: Both `words.txt.gz` (compressed wordlist) and `words.txt` (source) should be committed to the repository. The `words.txt.gz` file is embedded in the binary during build via `//go:embed`, while `words.txt` serves as the source for regenerating the compressed version when needed.

**File sizes**:
- `words.txt`: ~1.1MB (91,443 words, human-readable source)
- `words.txt.gz`: ~321KB (compressed, embedded in binary)
