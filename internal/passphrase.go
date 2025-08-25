package internal

import (
	"fmt"
	"strings"

	"github.com/hermo/finpass/internal/entropy"
)

// GeneratePassword creates a new passphrase with the given parameters
func GeneratePassword(wordCount int, maxLength uint, delimiter string, words []string) (string, error) {
	wordFn := func() (string, error) {
		return entropy.RandomWord(maxLength, words)
	}

	var parts []string
	for j := 0; j < wordCount; j++ {
		word, err := wordFn()
		if err != nil {
			return "", err
		}
		parts = append(parts, word)
	}
	segment, err := entropy.RandomAlphaNumericSegment(entropy.AlphaNumericSegmentLength)
	if err != nil {
		return "", err
	}
	parts = append(parts, segment)

	totalParts := len(parts)
	x, err := entropy.RandomInt(totalParts)
	if err != nil {
		return "", fmt.Errorf("Error generating random index: %v", err)
	}
	parts[x], parts[totalParts-1] = parts[totalParts-1], parts[x]

	passphrase := strings.Join(parts, delimiter)
	return passphrase, nil
}
