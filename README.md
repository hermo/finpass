# finpass

Generate memorable passphrases from Finnish words.

```
$ finpass
palvelivat-8KR-mailit
```

Each passphrase is built from randomly chosen Finnish words plus a randomly
placed 3-character alphanumeric segment for extra entropy. The wordlist
(~91k words) is a subset of
[everyfinnishword](https://github.com/hugovk/everyfinnishword).

finpass is available as:

- a **CLI binary** — a single-file [Cosmopolitan](https://github.com/jart/cosmopolitan)
  APE executable that runs unmodified on Linux, macOS and Windows (amd64 and arm64)
- a **web interface** (TypeScript)
- a **browser extension** for Firefox and Chrome (work in progress)
- a **Go implementation**, buildable from source

## Installation

**Homebrew:**

```bash
brew install hermo/tap/finpass
```

**deb/rpm:** arch-independent packages are attached to each
[release](https://github.com/hermo/finpass/releases) and install the binary as
`/usr/bin/finpass`.

**Standalone binary:** download `finpass.ape` from a
[release](https://github.com/hermo/finpass/releases), then:

```bash
chmod +x finpass.ape   # Linux / macOS
./finpass.ape
```

On Windows, rename `finpass.ape` to `finpass.exe` and run it.

See [Verifying a release](#verifying-a-release) to check the authenticity of
downloaded artifacts.

## Usage

```
$ finpass -w 4 -d .
36C.kytkea.terkut.koukuta

$ finpass -i -p strong
36C-kytkea-terkut-koukuta
Entropy and estimated time to crack using Security-focused apps (bcrypt):
* Brute-force:           154.2 bits (1e46y)
* Pattern-aware attack:   66.5 bits (170ky)
* Known wordlist:         58.6 bits (7y)
```

| Flag                     | Description                              | Default         |
| ------------------------ | ---------------------------------------- | --------------- |
| `-w`, `--words N`        | Number of words (1–6)                    | `3`             |
| `-n`, `--count N`        | Number of passphrases to generate        | `1`             |
| `-m`, `--max-length N`   | Maximum length of each word component    | `0` (unlimited) |
| `-d`, `--delimiter S`    | Delimiter between components             | `-`             |
| `-i`, `--info`           | Show entropy and time-to-crack analysis  |                 |
| `-p`, `--profile NAME`   | Attack profile for entropy calculation   | `standard`      |
| `-s`, `--custom-speed N` | Custom attack speed (guesses per second) |                 |
| `-a`, `--all-profiles`   | Show entropy for all attack profiles     |                 |
| `--list-profiles`        | List all available attack profiles       |                 |
| `-V`, `--version`        | Print version and exit                   |                 |
| `-h`, `--help`           | Show help message                        |                 |

The Go implementation accepts the same options in Go's single-dash flag style
(`-profile`, `-all-profiles`, `-list-profiles`, `-custom-speed`); the released
binary follows GNU `getopt_long` conventions as shown above.

### Attack profiles

Entropy analysis estimates time-to-crack against a chosen attacker model:

- `legacy` — weak legacy hashes (NTLM)
- `weak` — fast modern hashes (SHA256)
- `standard` — typical web app security (PBKDF2)
- `strong` — security-focused apps (bcrypt)
- `paranoid` — maximum security (scrypt)
- `online` — rate-limited online attacks

## Verifying a release

Every release includes a `SHA256SUMS` file and a detached SSH signature over
it (`SHA256SUMS.sig`), made with a key held on a hardware security token —
the private keys never exist on any computer. The set of valid release keys
is published as [`finpass-allowed-signers`](finpass-allowed-signers) in this
repository; that file, not any single key, is the trust root, so keys can be
rotated without breaking verification.

Verification needs no extra tools — just OpenSSH 8.2 or later (`ssh-keygen`),
which is preinstalled on Linux, macOS and Windows 10+.

**1. Download the artifact, the checksums, and the signature** (example for
the standalone binary; same procedure for the deb/rpm packages):

```bash
V=v1.6.0  # the release you are verifying
curl -fsSLO "https://github.com/hermo/finpass/releases/download/$V/finpass.ape"
curl -fsSLO "https://github.com/hermo/finpass/releases/download/$V/SHA256SUMS"
curl -fsSLO "https://github.com/hermo/finpass/releases/download/$V/SHA256SUMS.sig"
curl -fsSLO "https://raw.githubusercontent.com/hermo/finpass/main/finpass-allowed-signers"
```

**2. Check that `SHA256SUMS` was signed by a current release key:**

```bash
ssh-keygen -Y verify -f finpass-allowed-signers -I release@mirko.fi \
    -n file -s SHA256SUMS.sig < SHA256SUMS
```

Expected output (the key type and fingerprint vary by which hardware token
signed the release):

```
Good "file" signature for release@mirko.fi with SK-ED25519 key SHA256:...
```

Anything else — `Could not verify signature`, a different principal, a
non-zero exit code — means the file is not authentic; don't run the binary.

**3. Check that the downloaded artifacts match the signed checksums:**

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

On macOS use `shasum -a 256 --check --ignore-missing SHA256SUMS`. On Windows
(PowerShell), compare manually:

```powershell
(Get-FileHash finpass.ape -Algorithm SHA256).Hash
Select-String finpass.ape SHA256SUMS
```

Step 2 proves the checksum list is authentic; step 3 proves your downloads
match it. Both must pass.

**Fetching the trust root securely:** `finpass-allowed-signers` is served
from this repository over HTTPS. For extra assurance, cross-check it against
the copy in a git clone, or — if you verified releases before v1.6.0 with
minisign — verify the transition signature `finpass-allowed-signers.minisig`
attached to the v1.6.0 release with the long-standing minisign public key.

## Security design

### Entropy calculation

Three complementary methods, from most to least optimistic:

1. **Brute-force entropy** — the attacker has no knowledge of the generation
   method and must try all character combinations
2. **Pattern-aware entropy** — the attacker knows the pattern but not the
   wordlist
3. **Wordlist entropy** (worst case) — the attacker has the exact wordlist
   and full algorithm knowledge

Strength ratings use the worst-case wordlist entropy as the baseline, so they
hold even against an attacker with complete knowledge of the system. Even
then, the random placement of the alphanumeric segment contributes positional
entropy that cannot be bypassed.

### Strength rating

Generated passphrases are rated on a 5-level scale. The thresholds are
calibrated for randomly-generated passphrases, not user-chosen passwords:

| Rating          | Entropy   | Security level                    |
| --------------- | --------- | --------------------------------- |
| Weak (1/5)      | < 35 bits | Vulnerable to dedicated attacks   |
| Fair (2/5)      | 35–49 bits | Acceptable for low-value accounts |
| Good (3/5)      | 50–64 bits | Strong for most purposes          |
| Strong (4/5)    | 65–84 bits | Very strong, exceeds requirements |
| Excellent (5/5) | 85+ bits  | Extremely strong                  |

With proper password hashing (bcrypt, scrypt, or Argon2), passphrases rated
"good" or higher are secure against practical offline attacks. Use `-i` to
see the rating and entropy analysis on the CLI; the web interface shows the
rating for every generated passphrase.

### NIST SP 800-63B

The default 3-word configuration generates passphrases of 35–45 characters,
well beyond the minimums in
[NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
(15+ characters for single-factor, 8+ for multi-factor authentication),
with no reliance on artificial composition rules — length over complexity.

## Web interface

```bash
make serve-js
```

Then open [http://localhost:8080](http://localhost:8080). Alternatively,
serve the built `js/dist/` directory with any static HTTP server. The
interface is bilingual (English/Finnish), shows real-time entropy
calculations, and uses the Web Crypto API for random number generation.

For development with rebuild-on-change:

```bash
cd js
bun run dev
```

## Browser extension

A work-in-progress extension for Firefox (Manifest V2) and Chrome
(Manifest V3). It generates passphrases from a toolbar popup, copies them to
the clipboard or fills them into password fields, and has no runtime
dependencies.

**Build and package:**

```bash
make ext-package-firefox  # finpass-firefox.xpi
make ext-package-chrome   # finpass-chrome.zip
```

**Load for development:**

- **Firefox:** run `make ext-firefox`, then open `about:debugging` → "This
  Firefox" → "Load Temporary Add-on" → select `extension/manifest.json`
- **Chrome:** run `make ext-chrome`, then open `chrome://extensions` →
  enable Developer mode → "Load unpacked" → select the `extension/` directory

**Test:** `make ext-test`

## Building from source

Prerequisites: Make, plus per target:

- **C/APE binary:** [Podman](https://podman.io) or Docker (or a local
  `cosmocc` toolchain)
- **Go CLI:** Go 1.22 or later
- **Web interface / extension:** [Bun](https://bun.sh)

| Target               | Command                              | Output                 |
| -------------------- | ------------------------------------ | ---------------------- |
| C/APE binary         | `make ape-container`                 | `finpass.ape`          |
| Go CLI               | `make cli`                           | `finpass`              |
| Web interface        | `make js`                            | `js/dist/`             |
| Tests (Go)           | `make test`                          |                        |
| Tests (C/APE)        | `make ape-test`                      |                        |
| Clean                | `make clean`                         |                        |

`make ape-container` builds the toolchain image from the `Dockerfile` and
needs no local toolchain; set `CONTAINER_ENGINE=docker` to use Docker instead
of Podman. With `cosmocc` (from [cosmo.zip](https://cosmo.zip) or the
[Cosmopolitan releases](https://github.com/jart/cosmopolitan)) installed
locally, you can build directly:

```bash
make ape COSMOCC=/path/to/cosmocc
```

Release engineering is documented in [RELEASING.md](RELEASING.md).

### Updating the wordlist

1. Replace `internal/words.txt` with the new wordlist (one word per line)
2. Regenerate the compressed copy embedded into the binaries:

   ```bash
   gzip -9 -c internal/words.txt > internal/words.txt.gz
   ```

3. Rebuild (`make cli`, `make ape-container`)

Commit both `internal/words.txt` (source) and `internal/words.txt.gz`
(embedded via `//go:embed`).
