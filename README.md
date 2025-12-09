# finpass: Finnish Passphrase Generator

This project provides a tool to generate memorable passphrases using Finnish language words. It is available as:
- **Command-line interface (CLI)** for terminal use
- **WebAssembly (WASM)** module for browser use
- **Vanilla JavaScript** web interface with modern ES modules

Each generated password also includes a randomly placed 3-character alphanumeric section to add entropy.

## Usage

### Vanilla JavaScript Web Interface

The vanilla JavaScript implementation provides a modern, lightweight web interface without requiring any build steps or WASM compilation.

**To run the JavaScript version:**

```bash
make serve-js
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

Alternatively, you can serve the [`js/`](js/) directory with any static HTTP server:

```bash
# Using Python's built-in HTTP server
python3 -m http.server 8080 -d js

# Using Node.js http-server
npx http-server js -p 8080
```

**Features:**
- Pure ES modules - no build step required
- Modern Web Components architecture
- Bilingual support (English/Finnish)
- Real-time entropy calculations
- Responsive design for mobile and desktop
- Works in all modern browsers with ES module support

**Browser Requirements:**
- Modern browsers with ES modules support (Chrome 61+, Firefox 60+, Safari 11+, Edge 16+)
- JavaScript enabled
- Web Crypto API support for secure random number generation

### WebAssembly Interface

To use the WASM web interface, build the WASM module and start the local server:

```bash
make serve
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

### Command-Line Interface (CLI)

#### Flags

The command-line tool supports the following flags:

| Flag | Description | Default |
|---|---|---|
| `-w COUNT` | Number of words to generate | `3` |
| `-n COUNT` | Number of passphrases to generate | `1` |
| `-m MAXLEN` | Maximum length of each word component | `0` (unlimited) |
| `-d DELIM` | Delimiter between components | `-` |
| `-i` | Show entropy and time-to-crack analysis | |
| `-profile NAME` | Attack profile for entropy calculation | `standard` |
| `-list-profiles` | List all available attack profiles | |
| `-all-profiles` | Show entropy for all attack profiles | |
| `-custom-speed N` | Custom attack speed (guesses per second) | |
| `-version`, `-V` | Print version and exit | |

#### Examples

Generate a single passphrase:
```
$ finpass
palvelivat-8KR-mailit
```

Generate with entropy analysis:
```
$ finpass -i -profile strong
36C-kytkea-terkut-koukuta
Entropy and estimated time to crack using Security-focused apps (bcrypt):
* Brute-force:           154.2 bits (1e46y)
* Pattern-aware attack:   66.5 bits (170ky)
* Known wordlist:         58.6 bits (7y)
```

Generate 4-word passphrase with custom delimiter:
```
$ finpass -w 4 -d .
36C.kytkea.terkut.koukuta
```

## Attack Profiles

Available profiles for entropy calculation:
- `legacy` - Weak legacy hashes (NTLM)
- `weak` - Fast modern hashes (SHA256)
- `standard` - Typical web app security (PBKDF2)
- `strong` - Security-focused apps (bcrypt)
- `paranoid` - Maximum security (scrypt)
- `online` - Rate-limited online attacks

The wordlist contains about 91k words and is a subset of the wordlist found at https://github.com/hugovk/everyfinnishword

## Security Features

### Password Strength Rating System

This tool includes a comprehensive strength rating system that evaluates generated passphrases on a 5-level scale. The ratings are specifically **calibrated for randomly-generated passphrases** (not user-chosen passwords), which have fundamentally different security characteristics.

**Strength Rating Thresholds:**

| Rating | Entropy Range | Security Level |
|--------|--------------|----------------|
| Weak (1/5) | < 35 bits | Vulnerable to dedicated attacks |
| Fair (2/5) | 35-49 bits | Acceptable for low-value accounts |
| Good (3/5) | 50-64 bits | Strong for most purposes |
| Strong (4/5) | 65-84 bits | Very strong, exceeds requirements |
| Excellent (5/5) | 85+ bits | Extremely strong, nation-state resistant |

**Example:** A passphrase like `istuvillaan.R8U.pergola.lastain` (35 characters, ~68 bits entropy) rates as **"strong" (4/5)**.

### Why These Thresholds Work for Random Passphrases

Unlike user-chosen passwords, randomly-generated passphrases provide:
- **True randomness** - entropy calculations are mathematically accurate
- **Positional unpredictability** - the alphanumeric segment position adds genuine entropy
- **No blocklist concerns** - random words don't appear in common password lists
- **Higher security per character** - no human bias or predictable patterns

These thresholds align with practical security requirements while accounting for real-world attack scenarios and proper password hashing (bcrypt/scrypt/Argon2).

### NIST SP 800-63B Compliance

Generated passphrases comply with [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html):

- **Single-factor authentication:** 15+ characters minimum ✓
- **Multi-factor authentication:** 8+ characters minimum ✓
- **No forced composition rules:** No artificial uppercase/symbol requirements
- **Focus on length over complexity:** Longer passphrases are inherently stronger

The default 3-word configuration generates passphrases averaging 25-30 characters, well exceeding NIST minimums.

### Entropy Calculation Methods

The tool uses three complementary entropy calculation methods:

1. **Brute-force Entropy**: Assumes attacker has no knowledge of generation method
2. **Pattern-Aware Entropy**: Assumes attacker knows the pattern but not the wordlist
3. **Wordlist Entropy** (worst-case): Assumes attacker has the exact wordlist and full algorithm knowledge

Even in the worst-case scenario with complete algorithm knowledge, the positional entropy of the randomly-placed alphanumeric segment provides additional protection that cannot be bypassed.

**For Developers:** See [`TESTING.md`](TESTING.md) for detailed information about the strength rating implementation and cross-platform validation.

## Installation

Pre-built releases for the CLI exist for Linux, macOS and Windows on amd64/arm64 platforms. See the releases for details.

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
- Go 1.22 or later
- Make

### Build Instructions

The provided `Makefile` simplifies the build process.

*   **Build CLI:**
    ```bash
    make cli
    ```
    This will create the `finpass` binary in the root directory.

*   **Build WASM:**
    ```bash
    make wasm
    ```
    This will create `finpass.wasm` and `wasm_exec.js` in the `wasm/` directory.

*   **Test:**
    ```bash
    make test
    ```

*   **Clean build artifacts:**
    ```bash
    make clean
    ```

### Build Details

The binary uses an embedded compressed wordlist for optimal size:
- **Wordlist**: 91,443 Finnish words compressed from 1.1MB to 321KB (69.6% reduction)
- **Binary size**: ~2.2MB (down from 5.0MB unoptimized)
- **Startup time**: ~17ms (includes wordlist decompression)
- **Dependencies**: None (uses only Go standard library)

The wordlist is automatically decompressed at startup using `//go:embed` and gzip compression.

### Updating the Wordlist

If you need to update the Finnish wordlist:

1.  **Replace the source wordlist**:
    The wordlist files are located in the `internal/` directory.
    ```bash
    # Replace internal/words.txt with your new wordlist (one word per line)
    # Example: download from https://github.com/hugovk/everyfinnishword
    ```

2.  **Regenerate the compressed wordlist**:
    ```bash
    gzip -9 -c internal/words.txt > internal/words.txt.gz
    ```

3.  **Rebuild the binary**:
    ```bash
    make cli
    ```

**Important**: Both `internal/words.txt.gz` (compressed wordlist) and `internal/words.txt` (source) should be committed to the repository. The `words.txt.gz` file is embedded in the binary during build via `//go:embed`, while `words.txt` serves as the source for regenerating the compressed version when needed.

## Frequently Asked Questions

### How is the strength rating calculated?

The strength rating is based on the entropy (randomness) of the generated passphrase, measured in bits. The tool calculates entropy using three different methods:

1. **Brute-force entropy** - assumes the attacker tries all possible character combinations
2. **Pattern-aware entropy** - assumes the attacker knows the generation pattern but not the wordlist
3. **Wordlist entropy** - worst-case scenario where the attacker has the exact wordlist

The rating uses the wordlist entropy as the baseline, since it represents the minimum guaranteed security even if an attacker has complete knowledge of the system.

### What do the different strength levels mean?

The 5-level rating system is calibrated specifically for randomly-generated passphrases:

- **Weak (1/5)**: Less than 35 bits - vulnerable to dedicated attacks
- **Fair (2/5)**: 35-49 bits - acceptable for low-value accounts
- **Good (3/5)**: 50-64 bits - strong for most purposes
- **Strong (4/5)**: 65-84 bits - very strong, exceeds most requirements
- **Excellent (5/5)**: 85+ bits - extremely strong, resistant to nation-state attacks

With proper password hashing (bcrypt, scrypt, or Argon2), passphrases rated "good" or higher are secure against practical offline attacks.

### What is NIST SP 800-63B compliance?

[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) is a U.S. government guideline for digital identity authentication. It specifies minimum password lengths based on authentication factors:

- **15+ characters** for single-factor authentication (password only)
- **8+ characters** for multi-factor authentication (password + another factor)

The default configuration of this tool (3 words) generates passphrases averaging 25-30 characters, comfortably exceeding both requirements.

### Why are these thresholds appropriate for random passphrases?

These strength thresholds are specifically designed for **randomly-generated** passphrases, which differ fundamentally from user-chosen passwords:

**Random passphrases provide:**
- True mathematical randomness (no human bias)
- Accurate entropy calculations (no predictable patterns)
- Positional unpredictability (segment placement adds genuine entropy)
- No common password concerns (won't appear on blocklists)

**In contrast, user-chosen passwords:**
- Often follow predictable patterns ("Password1!")
- Have lower entropy relative to length
- Frequently appear on blocklists
- Require more conservative ratings

This is why user-chosen passwords need stricter guidelines (like NIST's emphasis on length), while our randomly-generated passphrases can be accurately rated based on their true entropy.

### How can I see the entropy and strength rating?

**Command-line interface:** Use the `-i` flag to show entropy analysis, or `-all-profiles` to see all attack profiles:
```bash
finpass -i
```

To see analysis for all attack profiles:
```bash
finpass -all-profiles
```

**Web interface:** The strength rating is always visible. Click "Show Details" to see comprehensive entropy calculations and time-to-crack estimates.

**For developers:** See [`TESTING.md`](TESTING.md) for information about running tests and validating the strength rating system.
