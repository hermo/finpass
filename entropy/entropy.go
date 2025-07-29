package entropy

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
)

const (
	// Character set sizes for entropy calculation
	LowercaseChars = 26
	UppercaseChars = 26
	Digits         = 10
	Symbols        = 32 // Assuming 32 common symbols for simplicity
	WordChars      = 26 // Assuming 26 possible characters for words
)

const (
	AlphaNumericSegmentLength = 3 // This constant was moved from main.go
)

type AttackProfile struct {
	Name        string
	Description string
	Speed       float64 // guesses per second
}

var attackProfiles = map[string]AttackProfile{
	"legacy": {
		Name:        "legacy",
		Description: "Weak legacy hashes (NTLM)",
		Speed:       308.2e9, // 308.2 GH/s
	},
	"weak": {
		Name:        "weak",
		Description: "Fast modern hashes (SHA256)",
		Speed:       27.6e9, // 27.6 GH/s
	},
	"standard": {
		Name:        "standard",
		Description: "Typical web app security (PBKDF2)",
		Speed:       11.0e6, // 11.0 MH/s
	},
	"strong": {
		Name:        "strong",
		Description: "Security-focused apps (bcrypt)",
		Speed:       300.5e3, // 300.5 kH/s
	},
	"paranoid": {
		Name:        "paranoid",
		Description: "Maximum security (scrypt)",
		Speed:       8.9e3, // 8.9 kH/s
	},
	"online": {
		Name:        "online",
		Description: "Rate-limited online attacks",
		Speed:       100, // 100 attempts/sec
	},
}

// bruteForceEntropy calculates the entropy of a passphrase based on the number of
// characters and character classes used
func BruteforceEntropy(passphrase string) float64 {
	lowercase := false
	uppercase := false
	digits := false
	symbols := false
	for _, c := range passphrase {
		switch {
		case c >= 'a' && c <= 'z':
			lowercase = true
		case c >= 'A' && c <= 'Z':
			uppercase = true
		case c >= '0' && c <= '9':
			digits = true
		default:
			symbols = true
		}
	}

	characters := 0
	if lowercase {
		characters += LowercaseChars
	}
	if uppercase {
		characters += UppercaseChars
	}
	if digits {
		characters += Digits
	}
	if symbols {
		characters += Symbols
	}

	return float64(len(passphrase)) * math.Log2(float64(characters))
}

// wordlistEntropy calculates the entropy of a passphrase based on wordlist size
func WordlistEntropy(passphrase string, separator rune, wordlistSize int, wordCount int) float64 {
	wordsEnt := float64(wordCount) * math.Log2(float64(wordlistSize))

	// Entropy of 3-character alphanumeric segment that must contain both letters and numbers
	// Calculated as log2(36^3 - 26^3 - 10^3) = log2(46656 - 17576 - 1000) = log2(28080) ≈ 14.45
	alphanumericEnt := math.Log2(math.Pow(36, AlphaNumericSegmentLength) - math.Pow(26, AlphaNumericSegmentLength) - math.Pow(10, AlphaNumericSegmentLength))

	totalPositions := wordCount + 1
	positionalEnt := math.Log2(float64(totalPositions))

	return wordsEnt + alphanumericEnt + positionalEnt
}

// patternAwareEntropy calculates entropy assuming attacker knows the pattern
// but not the exact wordlist - they must brute-force the word characters
func PatternAwareEntropy(passphrase string, separator rune, wordCount int) float64 {
	parts := strings.Split(passphrase, string(separator))

	wordsEnt := 0.0

	for _, part := range parts {
		hasLetter := false
		hasDigit := false
		for _, c := range part {
			if c >= 'A' && c <= 'Z' {
				hasLetter = true
			} else if c >= '0' && c <= '9' {
				hasDigit = true
			}
		}

		if hasLetter && hasDigit && len(part) == AlphaNumericSegmentLength {
			// This is the alphanumeric segment, skip it
		} else {
			wordsEnt += float64(len(part)) * math.Log2(WordChars)
		}
	}

	alphanumericEnt := math.Log2(math.Pow(36, AlphaNumericSegmentLength) - math.Pow(26, AlphaNumericSegmentLength) - math.Pow(10, AlphaNumericSegmentLength))

	totalPositions := wordCount + 1
	positionalEnt := math.Log2(float64(totalPositions))

	return wordsEnt + alphanumericEnt + positionalEnt
}

// estimateTimeToCrack estimates the time it would take to crack a passphrase
// based on the entropy and attack speed (assumes finding passphrase at 50% of search space)
func EstimateTimeToCrack(entropy float64, guessesPerSecond float64) string {
	guesses := math.Pow(2, entropy) / 2 // Average case: find passphrase halfway through search space
	seconds := guesses / guessesPerSecond

	// Convert to years for easier comparison
	years := seconds / (60 * 60 * 24 * 365)

	switch {
	case seconds < 1e-3:
		return "instant"
	case seconds < 1:
		return fmt.Sprintf("%.0fms", seconds*1000)
	case seconds < 60:
		return fmt.Sprintf("%.0fs", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%.0fm", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.0fh", seconds/3600)
	case years < 1:
		return fmt.Sprintf("%.0fd", seconds/86400)
	case years < 1e3:
		return fmt.Sprintf("%.1fy", years)
	case years < 1e6:
		return fmt.Sprintf("%.0fky", years/1e3)
	case years < 1e9:
		return fmt.Sprintf("%.0fMy", years/1e6)
	case years < 1e12:
		return fmt.Sprintf("%.0fBy", years/1e9)
	case years < 1e15:
		return fmt.Sprintf("%.0fTy", years/1e12)
	case years < 1e18:
		return fmt.Sprintf("%.0fQy", years/1e15)
	default:
		// Use scientific notation for extremely large numbers
		exp := math.Log10(years)
		return fmt.Sprintf("1e%.0fy", exp)
	}
}

func GetProfile(name string) (AttackProfile, bool) {
	profile, exists := attackProfiles[name]
	return profile, exists
}

func ListAllProfiles() {
	fmt.Println("Available attack profiles:")
	for _, profile := range []string{"legacy", "weak", "standard", "strong", "paranoid", "online"} {
		p := attackProfiles[profile]
		fmt.Printf("  %-10s - %s\n", p.Name, p.Description)
	}
}

func CalculateEntropyForProfile(passphrase string, delimiter rune, wordCount int, profile AttackProfile, words []string) (float64, float64, float64) {
	bruteEnt := BruteforceEntropy(passphrase)
	patternEnt := PatternAwareEntropy(passphrase, delimiter, wordCount)
	wordlistEnt := WordlistEntropy(passphrase, delimiter, len(words), wordCount)
	return bruteEnt, patternEnt, wordlistEnt
}

func RandomInt(max int) (int64, error) {
	if max == 0 {
		return 0, nil
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random integer: %w", err)
	}
	return nBig.Int64(), nil
}

func WordlistSubset(maxLength uint, words []string) []string {
	var wordlist []string
	for _, word := range words {
		if uint(len(word)) <= maxLength {
			wordlist = append(wordlist, word)
		}
	}
	return wordlist
}

func RandomWord(maxLength uint, words []string) string {
	numWords := len(words)
	idx, err := RandomInt(numWords)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random word index: %v\n", err)
		os.Exit(1)
	}
	word := words[idx]
	if maxLength > 0 {
		for uint(len(word)) > maxLength {
			idx, err := RandomInt(numWords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating random word index: %v\n", err)
				os.Exit(1)
			}
			word = words[idx]
		}
	}
	return word
}

func RandomAlphaNumericSegment(length int) string {
	const (
		alphanumericChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)

	var sb strings.Builder
	sb.Grow(length) // Pre-allocate capacity for length characters

	var hasChar, hasNum bool

	for {
		sb.Reset() // Clear the builder for a new attempt
		hasChar = false
		hasNum = false

		for i := 0; i < length; i++ {
			// Generate a random index for the alphanumeric character set
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumericChars))))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating random index for alphanumeric character: %v\n", err)
				os.Exit(1)
			}
			char := alphanumericChars[idx.Int64()]
			sb.WriteByte(char)

			if char >= '0' && char <= '9' {
				hasNum = true
			} else {
				hasChar = true
			}
		}

		if hasChar && hasNum {
			return sb.String()
		}
	}
}

func DisplayEntropyInfo(passphrase string, delimiterRune rune, wordCount int, maxLength uint, smallWords []string, allProfiles bool, customSpeed float64, profileName string, words []string) {
	if allProfiles {
		bruteEnt, patternEnt, wordlistEnt := CalculateEntropyForProfile(passphrase, delimiterRune, wordCount, AttackProfile{}, words)

		fmt.Fprintf(os.Stderr, "Passphrase entropy analysis:\n")
		fmt.Fprintf(os.Stderr, "  Brute-force:          %5.1f bits\n", bruteEnt)
		fmt.Fprintf(os.Stderr, "  Pattern-aware attack: %5.1f bits\n", patternEnt)
		fmt.Fprintf(os.Stderr, "  Known wordlist:       %5.1f bits\n", wordlistEnt)
		if maxLength > 0 {
			wordlistEntWithSize := WordlistEntropy(passphrase, delimiterRune, len(smallWords), wordCount)
			fmt.Fprintf(os.Stderr, "  Known wordlist+params:%5.1f bits\n", wordlistEntWithSize)
		}
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintf(os.Stderr, "Time to crack estimates by attack scenario:\n")
		fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s", "Profile", "Brute-force", "Pattern-aware", "Wordlist")
		if maxLength > 0 {
			fmt.Fprintf(os.Stderr, " %-18s", "Wordlist+params")
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s", "-------", "------------------", "------------------", "------------------")
		if maxLength > 0 {
			fmt.Fprintf(os.Stderr, " %-18s", "------------------")
		}
		fmt.Fprintln(os.Stderr, "")

		for _, pName := range []string{"online", "paranoid", "strong", "standard", "weak", "legacy"} {
			profile := attackProfiles[pName]
			fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s",
				profile.Name,
				EstimateTimeToCrack(bruteEnt, profile.Speed),
				EstimateTimeToCrack(patternEnt, profile.Speed),
				EstimateTimeToCrack(wordlistEnt, profile.Speed))
			if maxLength > 0 {
				wordlistEntWithSize := WordlistEntropy(passphrase, delimiterRune, len(smallWords), wordCount)
				fmt.Fprintf(os.Stderr, " %-18s", EstimateTimeToCrack(wordlistEntWithSize, profile.Speed))
			}
			fmt.Fprintln(os.Stderr, "")
		}
	} else {
		var speed float64
		var profileDesc string

		if customSpeed > 0 {
			speed = customSpeed
			profileDesc = fmt.Sprintf("custom speed (%.0e guesses/sec)", speed)
		} else {
			profile, exists := GetProfile(profileName)
			if !exists {
				fmt.Fprintf(os.Stderr, "Unknown profile: %s\n", profileName)
				fmt.Fprintln(os.Stderr, "Use --list-profiles to see available profiles")
				os.Exit(1)
			}
			speed = profile.Speed
			profileDesc = profile.Description
		}
		bruteEnt, patternEnt, wordlistEnt := CalculateEntropyForProfile(passphrase, delimiterRune, wordCount, AttackProfile{Speed: speed}, words)

		fmt.Fprintf(os.Stderr, "Entropy and estimated time to crack using %s:\n", profileDesc)
		fmt.Fprintf(os.Stderr, "* Brute-force:           %5.1f bits (%s)\n", bruteEnt, EstimateTimeToCrack(bruteEnt, speed))
		fmt.Fprintf(os.Stderr, "* Pattern-aware attack:  %5.1f bits (%s)\n", patternEnt, EstimateTimeToCrack(patternEnt, speed))
		fmt.Fprintf(os.Stderr, "* Known wordlist:        %5.1f bits (%s)\n", wordlistEnt, EstimateTimeToCrack(wordlistEnt, speed))
		if maxLength > 0 {
			wordlistEntWithSize := WordlistEntropy(passphrase, delimiterRune, len(smallWords), wordCount)
			fmt.Fprintf(os.Stderr, "* Known wordlist and parameters (-m=%d): %5.1f bits (%s)\n", maxLength, wordlistEntWithSize, EstimateTimeToCrack(wordlistEntWithSize, speed))
		}
	}
}
