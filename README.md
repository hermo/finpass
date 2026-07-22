# finpass: Finnish Passphrase Generator

This project provides a tool to generate memorable passphrases using Finnish
language words. It is available as:

- **Command-line interface (CLI)** for terminal use
- **WebAssembly (WASM)** module for browser use
- **TypeScript** web interface with modern ES modules
- **Browser extension** for Firefox and Chrome
- **Single-file multi-platform C binary (Cosmopolitan APE)**

Each generated password also includes a randomly placed 3-character
alphanumeric section to add entropy.

## Usage

### TypeScript Web Interface

The TypeScript implementation provides a modern, type-safe web interface built
with Bun and bundled for optimal performance.

**To build and run the TypeScript version:**

```bash
make serve-js
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

Alternatively, you can serve the [`js/dist/`](js/dist/) directory with any static HTTP
server:

```bash
# Using Python's built-in HTTP server
python3 -m http.server 8080 -d js/dist

# Using Node.js http-server
npx http-server js/dist -p 8080
```

**Development:**

```bash
cd js
bun run dev  # Watch mode - rebuilds on file changes
```

**Features:**

- TypeScript with strict type checking
- Modern Web Components architecture
- Bundled and minified for optimal performance
- Content-hashed filenames for cache-busting
- Bilingual support (English/Finnish)
- Real-time entropy calculations
- Responsive design for mobile and desktop
- Works in all modern browsers

**Browser Requirements:**

- Modern browsers (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- JavaScript enabled
- Web Crypto API support for secure random number generation

### Browser Extension

The browser extension brings Finpass directly into your browser toolbar. It supports both Firefox (Manifest V2) and Chrome (Manifest V3).

**Features:**

- Generate passphrases from the toolbar popup
- Copy to clipboard or fill into password fields
- Configurable word count (1-3) and shorter words option
- Strength rating display
- Auto-detected language (English/Finnish)
- Zero runtime dependencies

**Build and package:**

```bash
make ext-package-firefox  # Build finpass-firefox.xpi
make ext-package-chrome   # Build finpass-chrome.zip
```

**Load for development:**

- **Firefox:** Open `about:debugging` → "This Firefox" → "Load Temporary Add-on" → select `extension/manifest.json` (after running `make ext-firefox`)
- **Chrome:** Open `chrome://extensions` → enable Developer mode → "Load unpacked" → select the `extension/` directory (after running `make ext-chrome`)

**Run tests:**

```bash
make ext-test
```

### WebAssembly Interface

To use the WASM web interface, build the WASM module and start the local server:

```bash
make serve
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

### Command-Line Interface (CLI)

#### Flags

The command-line tool supports the following flags:

| Flag              | Description                              | Default         |
| ----------------- | ---------------------------------------- | --------------- |
| `-w COUNT`        | Number of words to generate              | `3`             |
| `-n COUNT`        | Number of passphrases to generate        | `1`             |
| `-m MAXLEN`       | Maximum length of each word component    | `0` (unlimited) |
| `-d DELIM`        | Delimiter between components             | `-`             |
| `-i`              | Show entropy and time-to-crack analysis  |                 |
| `-profile NAME`   | Attack profile for entropy calculation   | `standard`      |
| `-list-profiles`  | List all available attack profiles       |                 |
| `-all-profiles`   | Show entropy for all attack profiles     |                 |
| `-custom-speed N` | Custom attack speed (guesses per second) |                 |
| `-version`, `-V`  | Print version and exit                   |                 |

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

### C (Cosmopolitan APE)

The C implementation is a single-file binary built with
[Cosmopolitan libc](https://github.com/jart/cosmopolitan) into an Actually
Portable Executable (APE). The same `finpass.ape` file runs unmodified on
Linux, macOS and Windows, on both x86-64 and arm64 — no separate builds or
installers needed. The Finnish wordlist is embedded directly in the binary.

**Build:**

```bash
make ape COSMOCC=/path/to/cosmocc
```

Get `cosmocc` from [cosmo.zip](https://cosmo.zip) or the
[Cosmopolitan releases](https://github.com/jart/cosmopolitan). This produces
`./finpass.ape` in the repository root.

**Run:**

```bash
./finpass.ape -i -p strong
```

**Test:**

```bash
make ape-test
```

#### Flags

The C CLI follows standard GNU `getopt_long` conventions (`--long-flag`
double-dash, short flags combinable), which differs from the Go CLI's
single-dash long flags shown above:

| Flag                    | Description                               | Default         |
| ----------------------- | ------------------------------------------ | --------------- |
| `-w`, `--words N`        | Number of words to generate (1-6)          | `3`             |
| `-n`, `--count N`        | Number of passphrases to generate          | `1`             |
| `-m`, `--max-length N`   | Maximum length of each word component      | `0` (unlimited) |
| `-d`, `--delimiter S`    | Delimiter between components               | `-`             |
| `-i`, `--info`           | Show entropy and time-to-crack analysis    |                 |
| `-p`, `--profile NAME`   | Attack profile for entropy calculation     | `standard`      |
| `-s`, `--custom-speed N` | Custom attack speed (guesses per second)   |                 |
| `-a`, `--all-profiles`   | Show entropy for all attack profiles       |                 |
| `--list-profiles`        | List all available attack profiles         |                 |
| `-V`, `--version`        | Print version and exit                     |                 |
| `-h`, `--help`           | Show help message                          |                 |

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

This tool includes a comprehensive strength rating system that evaluates
generated passphrases on a 5-level scale. The ratings are specifically
**calibrated for randomly-generated passphrases** (not user-chosen passwords),
which have fundamentally different security characteristics.

**Strength Rating Thresholds:**

| Rating          | Entropy Range | Security Level                           |
| --------------- | ------------- | ---------------------------------------- |
| Weak (1/5)      | < 35 bits     | Vulnerable to dedicated attacks          |
| Fair (2/5)      | 35-49 bits    | Acceptable for low-value accounts        |
| Good (3/5)      | 50-64 bits    | Strong for most purposes                 |
| Strong (4/5)    | 65-84 bits    | Very strong, exceeds requirements        |
| Excellent (5/5) | 85+ bits      | Extremely strong, nation-state resistant |

**Example:** A passphrase like `istuvillaan.R8U.pergola.lastain` (35 characters, ~68 bits entropy) rates as **"strong" (4/5)**.

### NIST SP 800-63B Compliance

Finpass aims to generate passphrases that work with both legacy password
requirements and [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html):

- **Single-factor authentication:** 15+ characters minimum
- **Multi-factor authentication:** 8+ characters minimum
- **No forced composition rules:** No artificial uppercase/symbol requirements
- **Focus on length over complexity:** Longer passphrases are inherently stronger

The default 3-word configuration generates passphrases averaging 35-45
characters, well exceeding NIST minimums.

### Entropy Calculation Methods

The tool uses three complementary entropy calculation methods:

1. **Brute-force Entropy**: Assumes attacker has no knowledge of generation method
2. **Pattern-Aware Entropy**: Assumes attacker knows the pattern but not the wordlist
3. **Wordlist Entropy** (worst-case): Assumes attacker has the exact wordlist and full algorithm knowledge

Even in the worst-case scenario with complete algorithm knowledge, the
positional entropy of the randomly-placed alphanumeric segment provides
additional protection that cannot be bypassed.

## Installation

Pre-built releases for the CLI exist for Linux, macOS and Windows on
amd64/arm64 platforms. See the releases for details.

## Building from Source

### Prerequisites

- Go 1.22 or later
- Make
- [Bun](https://bun.sh) (for TypeScript web interface)

### Build Instructions

The provided `Makefile` simplifies the build process.

- **Build CLI:**

  ```bash
  make cli
  ```

  This will create the `finpass` binary in the root directory.

- **Build WASM:**

  ```bash
  make wasm
  ```

  This will create `finpass.wasm` and `wasm_exec.js` in the `wasm/` directory.

- **Build TypeScript web interface:**

  ```bash
  make js
  ```

  This will build and bundle the TypeScript source files to the `js/dist/` directory.

- **Build C (Cosmopolitan APE):**

  ```bash
  make ape COSMOCC=/path/to/cosmocc
  ```

  This will create the `finpass.ape` binary in the root directory. See
  [C (Cosmopolitan APE)](#c-cosmopolitan-ape) above for details and where to
  get `cosmocc`.

- **Test:**

  ```bash
  make test
  ```

- **Clean build artifacts:**
  ```bash
  make clean
  ```

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

**Important**: Both `internal/words.txt.gz` (compressed wordlist) and
`internal/words.txt` (source) should be committed to the repository.

The `words.txt.gz` file is embedded in the binary during build via
`//go:embed`, while `words.txt` serves as the source for regenerating the
compressed version when needed.

## Frequently Asked Questions

### How is the strength rating calculated?

The strength rating is based on the entropy (randomness) of the generated
passphrase, measured in bits. The tool calculates entropy using three different
methods:

1. **Brute-force entropy** - assumes the attacker tries all possible character
   combinations
2. **Pattern-aware entropy** - assumes the attacker knows the generation
   pattern but not the wordlist
3. **Wordlist entropy** - worst-case scenario where the attacker has the exact
   wordlist

The rating uses the wordlist entropy as the baseline, since it represents the
minimum guaranteed security even if an attacker has complete knowledge of the
system.

### What do the different strength levels mean?

The 5-level rating system is calibrated specifically for randomly-generated
passphrases:

- **Weak (1/5)**: Less than 35 bits - vulnerable to dedicated attacks
- **Fair (2/5)**: 35-49 bits - acceptable for low-value accounts
- **Good (3/5)**: 50-64 bits - strong for most purposes
- **Strong (4/5)**: 65-84 bits - very strong, exceeds most requirements
- **Excellent (5/5)**: 85+ bits - extremely strong, resistant to nation-state
  attacks

With proper password hashing (bcrypt, scrypt, or Argon2), passphrases rated
"good" or higher are secure against practical offline attacks.

### How can I see the entropy and strength rating?

**Command-line interface:** Use the `-i` flag to show entropy analysis, or
`-all-profiles` to see all attack profiles:

```bash
finpass -i
```

To see analysis for all attack profiles:

```bash
finpass -all-profiles
```

**Web interface:** The strength rating is always visible. Click "Show Details"
to see comprehensive entropy calculations and time-to-crack estimates.
