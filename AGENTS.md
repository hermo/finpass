# Finpass Agent Guidelines

This document provides build instructions and code style guidelines for AI coding agents working in the Finpass repository.

## Repository Structure

This is a **monorepo** containing four independent implementations of the same passphrase generation algorithm:

1. **Go CLI App** - Command-line tool (`main.go`, `internal/`)
2. **JavaScript Web App** - Browser-based interface (`js/src/components/`, `js/src/lib/`)
3. **Browser Extension** - Firefox/Chrome extension (`extension/`)
4. **C CLI App** - Single-file Cosmopolitan APE binary (`c/src/`, `c/tests/`)

All implementations share the same algorithm but are wholly separate codebases with no shared code between them.

## Build, Lint & Test Commands

### Go CLI

**Build:**

```bash
make cli              # Build the finpass CLI binary
make clean            # Remove all build artifacts
```

**Test:**

```bash
go test ./...                                    # Run all tests
go test -v ./...                                 # Run all tests (verbose)
go test -run TestFunctionName                    # Run single test in current package
go test -run TestFunctionName ./internal/entropy # Run single test in specific package
go test -v -run TestBruteforceEntropy            # Run specific test (verbose)
```

**Lint:**

```bash
staticcheck ./...     # Run staticcheck linter (same as CI)
```

### JavaScript Web App

**Serve:**

```bash
make serve-js         # Serve on http://localhost:8080
```

**Test:**

- Open `js/test.html` in a web browser to run all JavaScript unit tests
- No CLI test runner available; MUST use browser
- Tests use custom describe/test framework

**Note:** The JavaScript implementation requires NO build step. It uses native ES modules.

### Other Commands

```bash
./test-randomness.sh  # Run statistical randomness analysis (requires finpass binary)
```

### CI/CD

The repository uses GitHub Actions for continuous integration:

- **Staticcheck:** Runs on all pushes and pull requests (`.github/workflows/staticcheck.yml`)
- **CodeQL:** Security analysis on pushes to main

All code MUST pass staticcheck before merging. Run `staticcheck ./...` locally before committing.

### Browser Extension

**Build & Package:**

```bash
make ext-sync             # Sync shared assets (wordlist, icons) into extension/
make ext-firefox          # Prepare for Firefox (copies Manifest V2)
make ext-chrome           # Prepare for Chrome (copies Manifest V3)
make ext-package-firefox  # Build finpass-firefox.xpi
make ext-package-chrome   # Build finpass-chrome.zip
make ext-icons            # Regenerate icons from js/favicon.svg using GraphicsMagick
```

**Test:**

```bash
make ext-test             # Run extension tests via vitest
```

**Notes:**

- The extension has its own `lib/` directory with standalone JS files (not copies of the TS web app)
- `ext-sync` copies `internal/words.txt` and regenerates icons; it does NOT sync lib files
- Test dependencies (vitest, fast-check) are dev-only; the shipped extension has zero npm dependencies
- Firefox manifest (`manifest.v2.json`) includes `browser_specific_settings` with gecko ID and `data_collection_permissions`
- Chrome manifest (`manifest.v3.json`) uses Manifest V3 with service worker background

### C (Cosmopolitan APE)

**Build:**

```bash
make ape COSMOCC=/path/to/cosmocc  # Build finpass.ape (single-file APE binary)
make ape-clean                     # Remove ape build artifacts
```

**Test:**

```bash
make ape-test          # Build and run all c/tests/*.c test binaries
```

**Notes:**

- Sources live in `c/src/*.c|h`; tests live in `c/tests/`
- Built with `-Wall -Wextra -Wpedantic -Werror -O2 -std=c11`; all code MUST compile cleanly under this discipline
- All randomness MUST go through the CSPRNG wrapper in `c/src/rand.c`; `rand()` and `srand()` are FORBIDDEN
- The Finnish wordlist is front-coded at build time by `c/tools/wordenc.c` (shared-prefix-length control byte < 32 per word + differing suffix; word bytes are >= 33 so the control byte doubles as delimiter), zip-embedded, and decoded at startup from `/zip/words.fc` by `c/src/words.c`
- Uses GNU-style `getopt_long` flags, deliberately NOT matching the Go CLI's single-dash long flags

## Go Code Style Guidelines

### Package Structure

- `internal/` - Core implementation code (passphrase generation, entropy, wordlist)
- `internal/entropy/` - Entropy and strength calculations
- Each package MUST have a single, clear responsibility

### Imports

Imports MUST be organized in two groups separated by a blank line:

1. Standard library imports (alphabetically sorted)
2. Local imports (alphabetically sorted)

Example:

```go
import (
    "crypto/rand"
    "fmt"
    "strings"

    "github.com/hermo/finpass/internal"
    "github.com/hermo/finpass/internal/entropy"
)
```

### Naming Conventions

- **Exported identifiers:** MUST use PascalCase (e.g., `GeneratePassword`, `BruteforceEntropy`, `AttackProfile`)
- **Unexported identifiers:** MUST use camelCase (e.g., `randomInt`, `wordlistSubset`)
- **Constants:** MUST use PascalCase or SCREAMING_SNAKE_CASE depending on context
- **Types:** MUST use PascalCase (e.g., `StrengthRating`, `Settings`)

### Error Handling

- Functions MUST return errors rather than panic (except in `init()` functions)
- Errors MUST be wrapped with context using `fmt.Errorf()` with `%w` verb
- Errors MUST be checked immediately after function calls
- Error messages MUST be lowercase and not end with punctuation

Example:

```go
if err != nil {
    return "", fmt.Errorf("failed to generate random word: %w", err)
}
```

### Constants and Variables

- Constants MUST be defined at package level
- Related constants SHOULD be grouped in `const` blocks
- Constants MUST have doc comments explaining their purpose

### Testing

- Tests MUST use table-driven patterns where appropriate
- Test files MUST be named `*_test.go`
- Subtests MUST use `t.Run()` with descriptive names
- Test table structs SHOULD include a `name` field for test identification

### Documentation

- All exported functions, types, and constants MUST have doc comments
- Doc comments MUST start with the name of the item being documented
- Doc comments MUST use complete sentences
- Package-level documentation SHOULD be in a dedicated doc.go file or at the top of the main package file

## JavaScript Code Style Guidelines

### Module Structure

- ES modules with explicit `.js` extensions in all imports (REQUIRED)
- `components/` - Web Components
- `lib/` - Utility functions and core logic
- Each module MUST export specific, focused functionality

### Imports

Imports MUST include the `.js` file extension:

```javascript
import { generatePassphrase } from "../lib/passphrase.js";
import { calculateEntropy } from "../lib/entropy-calc.js";
```

### Naming Conventions

- **Functions and variables:** MUST use camelCase (e.g., `generatePassphrase`, `wordCount`)
- **Constants:** MUST use SCREAMING_SNAKE_CASE (e.g., `ALPHANUMERIC_CHARS`, `SEGMENT_LENGTH`)
- **Classes:** MUST use PascalCase (e.g., `FinpassApp`, `EntropyDisplay`)
- **Private class fields:** MUST be prefixed with underscore (e.g., `_wordlist`, `_settings`)

### JSDoc Documentation

All exported functions MUST have JSDoc comments including:

- Description of what the function does
- `@param` for each parameter with type and description
- `@returns` with type and description
- `@throws` if the function can throw errors
- `@module` tag at the top of each file

Example:

```javascript
/**
 * Generate a passphrase with random words and alphanumeric segment.
 * @param {Object} options - Generation options
 * @param {number} options.wordCount - Number of words to include
 * @param {string[]} options.wordlist - Array of words to choose from
 * @returns {string} The generated passphrase
 * @throws {Error} If wordlist is empty or parameters are invalid
 */
```

### Error Handling

- Functions MUST throw descriptive Error objects for invalid conditions
- Error messages MUST clearly explain what went wrong
- Parameter validation MUST happen early in functions
- Async operations SHOULD use try/catch blocks

### Web Components

- MUST use Shadow DOM for encapsulation
- Event handlers MUST be bound in the constructor
- MUST clean up event listeners in `disconnectedCallback()`
- MUST call `super()` first in constructor
- Component names MUST use kebab-case with a prefix (e.g., `finpass-app`)

### Testing

- Test files MUST be named `*.test.js`
- Tests MUST use the custom describe/test framework
- Test descriptions MUST be clear and specific
- Tests MUST be runnable via `js/test.html` in a browser

## Project-Specific Conventions

### ⚠️ CRITICAL: Entropy Calculations

**SPECIAL ATTENTION REQUIRED** for any changes to entropy calculation logic:

- Three entropy methods MUST remain consistent: Brute-force, Pattern-aware, and Wordlist
- Changes to entropy logic MUST be validated in BOTH implementations:
  - Go: `internal/entropy/entropy.go` and `internal/entropy/strength_test.go`
  - JavaScript: `js/lib/entropy-calc.js` and `js/lib/entropy-calc.test.js`
- Tests MUST pass in both Go and JavaScript before committing
- Strength rating thresholds (Weak/Fair/Good/Strong/Excellent) MUST match exactly
- Time-to-crack estimates MUST use identical attack profiles and calculations

### Cryptographic Randomness

- Go: MUST use `crypto/rand` exclusively for all random number generation
- JavaScript: MUST use Web Crypto API (`window.crypto.getRandomValues()`) exclusively
- NEVER use `math/rand` (Go) or `Math.random()` (JavaScript) for any security-related randomness
- All random number generation MUST be cryptographically secure

### Wordlist Handling

- Go: Wordlist is embedded as compressed data (`//go:embed words.txt.gz`) and decompressed at startup
- JavaScript: Wordlist is fetched from `words.txt` at runtime
- Both implementations MUST use the identical source wordlist (`internal/words.txt`)
- The wordlist contains ~91,000 Finnish words

### Dependencies

- **Go: MUST use standard library only** - Zero external dependencies are allowed
- **JavaScript: MUST use vanilla ES modules only** - Zero npm dependencies are allowed
- This policy ensures minimal binary size and maximum portability

### Algorithm Consistency

Both implementations MUST follow identical passphrase generation logic:

- Alphanumeric segment MUST be exactly 3 characters
- Alphanumeric segment MUST contain at least one letter AND one digit
- Alphanumeric segment MUST be inserted at a random position (including start/end)
- Word selection MUST use cryptographically secure randomness
- Delimiter MUST be configurable (default: `-` for CLI, `.` for web)

### Cross-Implementation Validation

When making algorithmic changes:

1. Update both Go and JavaScript implementations
2. Run all tests in both languages
3. Verify entropy calculations match using the same test passphrases
4. Test manual passphrase generation to ensure output is comparable
5. Run `./test-randomness.sh` for statistical validation (if changing generation logic)

<!-- rtk-instructions v2 -->

# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:

```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)

```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (90-99% savings)

```bash
rtk cargo test          # Cargo test failures only (90%)
rtk vitest run          # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)

```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)

```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)

```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)

```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%)
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)

```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)

```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)

```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands

```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category         | Commands                       | Typical Savings |
| ---------------- | ------------------------------ | --------------- |
| Tests            | vitest, playwright, cargo test | 90-99%          |
| Build            | next, tsc, lint, prettier      | 70-87%          |
| Git              | status, log, diff, add, commit | 59-80%          |
| GitHub           | gh pr, gh run, gh issue        | 26-87%          |
| Package Managers | pnpm, npm, npx                 | 70-90%          |
| Files            | ls, read, grep, find           | 60-75%          |
| Infrastructure   | docker, kubectl                | 85%             |
| Network          | curl, wget                     | 65-70%          |

Overall average: **60-90% token reduction** on common development operations.

<!-- /rtk-instructions -->
