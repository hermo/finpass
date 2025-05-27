package main

import (
	"fmt"
	"math"
	"strings"
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

// bruteForceEntropy calculates the entropy of a password based on the number of
// characters and character classes used
func bruteforceEntropy(password string) float64 {
	lowercase := false
	uppercase := false
	digits := false
	symbols := false
	for _, c := range password {
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
		characters += 26
	}
	if uppercase {
		characters += 26
	}
	if digits {
		characters += 10
	}
	if symbols {
		characters += 32 // Assuming 32 common symbols for simplicity
	}

	return float64(len(password)) * math.Log2(float64(characters))
}

// wordlistEntropy calculates the entropy of a password based on wordlist size
func wordlistEntropy(password string, separator rune, wordlistSize int, wordCount int) float64 {
	wordsEnt := float64(wordCount) * math.Log2(float64(wordlistSize))

	// Entropy of 3-character alphanumeric segment that must contain both letters and numbers
	// Calculated as log2(36^3 - 26^3 - 10^3) = log2(46656 - 17576 - 1000) = log2(28080) ≈ 15.5
	alphanumericEnt := 15.5

	totalPositions := wordCount + 1
	positionalEnt := math.Log2(float64(totalPositions))

	return wordsEnt + alphanumericEnt + positionalEnt
}

// patternAwareEntropy calculates entropy assuming attacker knows the pattern
// but not the exact wordlist - they must brute-force the word characters
func patternAwareEntropy(password string, separator rune, wordCount int) float64 {
	parts := strings.Split(password, string(separator))

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

		if hasLetter && hasDigit && len(part) == 3 {
			// This is the alphanumeric segment, skip it
		} else {
			wordsEnt += float64(len(part)) * math.Log2(26)
		}
	}

	alphanumericEnt := 15.5

	totalPositions := wordCount + 1
	positionalEnt := math.Log2(float64(totalPositions))

	return wordsEnt + alphanumericEnt + positionalEnt
}

// estimateTimeToCrack estimates the time it would take to crack a password
// based on the entropy and attack speed (assumes finding password at 50% of search space)
func estimateTimeToCrack(entropy float64, guessesPerSecond float64) string {
	guesses := math.Pow(2, entropy) / 2 // Average case: find password halfway through search space
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

func getProfile(name string) (AttackProfile, bool) {
	profile, exists := attackProfiles[name]
	return profile, exists
}

func listAllProfiles() {
	fmt.Println("Available attack profiles:")
	for _, profile := range []string{"legacy", "weak", "standard", "strong", "paranoid", "online"} {
		p := attackProfiles[profile]
		fmt.Printf("  %-10s - %s\n", p.Name, p.Description)
	}
}

func calculateEntropyForProfile(password string, delimiter rune, wordCount int, profile AttackProfile) (float64, float64, float64) {
	bruteEnt := bruteforceEntropy(password)
	patternEnt := patternAwareEntropy(password, delimiter, wordCount)
	wordlistEnt := wordlistEntropy(password, delimiter, len(words), wordCount)
	return bruteEnt, patternEnt, wordlistEnt
}
