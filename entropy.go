package main

import (
	"fmt"
	"math"
	"unicode"
)

// bruteForceEntropy calculates the entropy of a password based on the number of
// characters and character classes used
func bruteForceEntropy(password string) float64 {
	// deduce character classes used from password. Classes include lowercase,
	// uppercase, digits, and symbols
	const (
		lowercaseSize = 26
		uppercaseSize = 26
		digitSize     = 10
		symbolSize    = 32 // !"#¤%&/()=?@£$€{[]}\`|<>'*-_^~§½
	)

	lowercase := false
	uppercase := false
	digits := false
	symbols := false

	for _, c := range password {
		switch {
		case unicode.IsLower(c):
			lowercase = true
		case unicode.IsUpper(c):
			uppercase = true
		case unicode.IsDigit(c):
			digits = true
		default:
			symbols = true
		}
	}

	// Add the number of characters in each class used
	characters := 0
	if lowercase {
		characters += lowercaseSize
	}
	if uppercase {
		characters += uppercaseSize
	}
	if digits {
		characters += digitSize
	}
	if symbols {
		characters += symbolSize
	}

	if characters == 0 {
		return 0 // Handling edge case where the password is empty
	}

	return float64(len(password)) * math.Log2(float64(characters))
}

// wordlistEntropy calculates the entropy of a password based on wordlist size
func wordlistEntropy(password string, separator rune, wordlistSize int) float64 {
	// count the number of wordCount in the password. exclude one word.
	wordCount := 0
	for _, c := range password {
		if c == separator {
			wordCount++
		}
	}
	wordsEnt := float64(wordCount) * math.Log2(float64(wordlistSize))

	// calculate entropy increase from the separator. there are 3 separators and they are always -
	separatorEnt := math.Log2(3)

	// one word is always 3 characters long and contains uppercase letters and one or more digits
	randomEnt := 3 * math.Log2(36)

	return wordsEnt + separatorEnt + randomEnt
}

// estimateTimeToCrack estimates the time it would take to crack a password
// based on the entropy of the password
func estimateTimeToCrack(entropy float64) string {
	// Assume the cracking speed is 20MH/s
	// Estimate based on RTX 4090 Hashcat benchmarks
	// https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
	guessesPerSecond := 20e6
	// calculate the number of guesses needed to crack the password
	guesses := math.Pow(2, entropy)
	// calculate the number of seconds needed to crack the password
	seconds := guesses / guessesPerSecond
	// calculate minutes needed to crack the password
	minutes := seconds / 60
	// calculate hours needed to crack the password
	hours := seconds / 60 / 60
	// calculate days needed to crack the password
	days := seconds / 60 / 60 / 24
	// calculate the number of years needed to crack the password
	years := seconds / 60 / 60 / 24 / 365
	// calculate the number of centuries needed to crack the password
	centuries := years / 100
	// calculate thousands of years needed to crack the password
	thousandsOfYears := years / 1000
	// calculate millions of years needed to crack the password
	millionsOfYears := years / 1000000
	// calculate billions of years needed to crack the password
	billionsOfYears := years / 1000000000
	// calculate trillions of years needed to crack the password
	trillionsOfYears := years / 1000000000000
	// calculate quadrillions of years needed to crack the password
	quadrillionsOfYears := years / 1000000000000000
	// calculate quintillions of years needed to crack the password
	quintillionsOfYears := years / 1000000000000000000
	// calculate sextillions of years needed to crack the password
	sextillionsOfYears := years / 1000000000000000000000
	// calculate septillions of years needed to crack the password
	septillionsOfYears := years / 1000000000000000000000000
	// calculate octillions of years needed to crack the password
	octillionsOfYears := years / 1000000000000000000000000000
	// calculate nonillions of years needed to crack the password
	nonillionsOfYears := years / 1000000000000000000000000000000

	// return the appropriate number of years, centuries, millennia, or aeons as a formatted string with 1 decimal place
	switch {
	case nonillionsOfYears > 1:
		return fmt.Sprintf("~%.0f nonillion years", nonillionsOfYears)
	case octillionsOfYears > 1:
		return fmt.Sprintf("~%.0f octillion years", octillionsOfYears)
	case septillionsOfYears > 1:
		return fmt.Sprintf("~%.0f septillion years", septillionsOfYears)
	case sextillionsOfYears > 1:
		return fmt.Sprintf("~%.0f sextillion years", sextillionsOfYears)
	case quintillionsOfYears >= 1:
		return fmt.Sprintf("~%.0f quintillion years", quintillionsOfYears)
	case quadrillionsOfYears >= 1:
		return fmt.Sprintf("~%.0f quadrillion years", quadrillionsOfYears)
	case trillionsOfYears >= 1:
		return fmt.Sprintf("~%.0f trillion years", trillionsOfYears)
	case billionsOfYears >= 1:
		return fmt.Sprintf("~%.0f billion years", billionsOfYears)
	case millionsOfYears >= 1:
		return fmt.Sprintf("~%.0f million years", millionsOfYears)
	case thousandsOfYears >= 1:
		return fmt.Sprintf("~%.0f thousand years", thousandsOfYears)
	case centuries >= 1:
		return fmt.Sprintf("~%.0f centuries", centuries)
	case years >= 1:
		return fmt.Sprintf("~%.1f years", years)
	case days >= 1:
		return fmt.Sprintf("~%.1f days", days)
	case hours >= 1:
		return fmt.Sprintf("~%.1f hours", hours)
	case minutes >= 1:
		return fmt.Sprintf("~%.1f minutes", minutes)
	case seconds >= 1:
		return fmt.Sprintf("~%.0f seconds", seconds)
	default:
		return "instantly"
	}
}
