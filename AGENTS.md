# Finpass Agent Guidelines

This document provides build instructions and code style guidelines for AI coding agents working in the Finpass repository.

## Repository Structure

This is a **monorepo** containing two independent implementations of the same passphrase generation algorithm:

1. **Go CLI App** - Command-line tool (`main.go`, `internal/`, `wasm/`)
2. **JavaScript Web App** - Browser-based interface (`js/components/`, `js/lib/`)

Both implementations share the same algorithm but are wholly separate codebases with no shared code between them.

## Build, Lint & Test Commands

### Go CLI

**Build:**
```bash
make cli              # Build the finpass CLI binary
make wasm             # Build WebAssembly version
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
make serve            # Serve WASM version on http://localhost:8000
```

### CI/CD

The repository uses GitHub Actions for continuous integration:

- **Staticcheck:** Runs on all pushes and pull requests (`.github/workflows/staticcheck.yml`)
- **CodeQL:** Security analysis on pushes to main

All code MUST pass staticcheck before merging. Run `staticcheck ./...` locally before committing.

## Go Code Style Guidelines

### Package Structure

- `internal/` - Core implementation code (passphrase generation, entropy, wordlist)
- `internal/entropy/` - Entropy and strength calculations
- `wasm/` - WebAssembly bridge
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
import { generatePassphrase } from '../lib/passphrase.js';
import { calculateEntropy } from '../lib/entropy-calc.js';
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
