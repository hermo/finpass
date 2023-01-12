package main

import (
	"fmt"
	"math"
)

func bruteforceEntropy(password string) float64 {
	// deduce character classes used from password. Classes include lowercase, uppercase, digits, and symbols
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
	// add the number of characters in each class used
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
		characters += 10
	}

	return float64(len(password)) * math.Log2(float64(characters))
}

func wordlistEntropy(password string, separator rune) float64 {
	// count the number of wordCount in the password. exclude one word.
	wordCount := 0
	for _, c := range password {
		if c == separator {
			wordCount++
		}
	}
	wordlistSize := len(words)
	wordsEnt := float64(wordCount) * math.Log2(float64(wordlistSize))

	// calculate entropy increase from the separator. there are 3 separators and they are always -
	separatorEnt := math.Log2(3)

	// one word is always 3 characters long and contains uppercase letters and one or more digits
	randomEnt := 3 * math.Log2(36)

	return wordsEnt + separatorEnt + randomEnt
}

func estimateCrackTime(entropy float64) string {
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
		return fmt.Sprintf("%.1f nonillion years", nonillionsOfYears)
	case octillionsOfYears > 1:
		return fmt.Sprintf("%.1f octillion years", octillionsOfYears)
	case septillionsOfYears > 1:
		return fmt.Sprintf("%.1f septillion years", septillionsOfYears)
	case sextillionsOfYears > 1:
		return fmt.Sprintf("%.1f sextillion years", sextillionsOfYears)
	case quintillionsOfYears >= 1:
		return fmt.Sprintf("%.1f quintillion years", quintillionsOfYears)
	case quadrillionsOfYears >= 1:
		return fmt.Sprintf("%.1f quadrillion years", quadrillionsOfYears)
	case trillionsOfYears >= 1:
		return fmt.Sprintf("%.1f trillion years", trillionsOfYears)
	case billionsOfYears >= 1:
		return fmt.Sprintf("%.1f billion years", billionsOfYears)
	case millionsOfYears >= 1:
		return fmt.Sprintf("%.1f million years", millionsOfYears)
	case thousandsOfYears >= 1:
		return fmt.Sprintf("%.1f thousand years", thousandsOfYears)
	case centuries >= 1:
		return fmt.Sprintf("%.1f centuries", centuries)
	case years >= 1:
		return fmt.Sprintf("%.1f years", years)
	case days >= 1:
		return fmt.Sprintf("%.1f days", days)
	case hours >= 1:
		return fmt.Sprintf("%.1f hours", hours)
	case minutes >= 1:
		return fmt.Sprintf("%.1f minutes", minutes)
	case seconds >= 1:
		return fmt.Sprintf("%.1f seconds", seconds)
	default:
		return "instantly"
	}
}
