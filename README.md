# finpass: Finnish Passphrase Generator (CLI and WASM)

This project provides a tool to generate memorable passphrases using Finnish language words. It is available as both a command-line interface (CLI) and a WebAssembly (WASM) module for direct use in a browser.

Each generated password also includes a randomly placed 3-character alphanumeric section to add entropy.

## Usage

### Web Interface

To use the web interface, build the WASM module and start the local server:

```bash
make serve
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

### Command-Line Interface (CLI)

#### Flags

The command-line tool supports the following flags:

| Flag | Description | Default |
|---|---|---|
| `-n COUNT` | Number of words to generate | `3` |
| `-m MAXLEN` | Maximum length of each word component | `0` (unlimited) |
| `-d DELIM` | Specify delimiter | `.` |
| `-e` | Show entropy information (default on) | |
| `-E` | Do not show entropy information | |
| `-p NAME` | Attack profile for entropy calculation | `strong` |
| `-l` | List all available attack profiles | |
| `-a` | Show entropy for all attack profiles | |
| `-s N` | Custom attack speed (guesses per second) | |
| `-v` | Print version and exit | |

#### Example

```
$ finpass -n 4 -m 7 -d . -p strong
36C.kytkea.terkut.koukuta
Entropy and estimated time to crack using Security-focused apps (bcrypt):
* Brute-force:           154.2 bits (1e46y)
* Pattern-aware attack:   66.5 bits (170ky)
* Known wordlist:         58.6 bits (7y)
* Known wordlist and parameters (-m=7): 50.1 bits (3d)
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
