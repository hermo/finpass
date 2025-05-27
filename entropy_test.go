package main

import (
	"testing"
)

func TestBruteforceEntropy(t *testing.T) {
	tests := []struct {
		password string
		want     float64
	}{
		{"abc", 14.101319154423276},
		{"ABC", 14.101319154423276},
		{"123", 9.965784284662087},
		{"!@#", 15},
		{"aB1!", 26.21835540671055},
	}

	for _, tt := range tests {
		if got := bruteforceEntropy(tt.password); got != tt.want {
			t.Errorf("bruteforceEntropy(%q) = %v, want %v", tt.password, got, tt.want)
		}
	}
}

func TestWordlistEntropy(t *testing.T) {
	tests := []struct {
		password    string
		separator   rune
		wordlistSize int
		want        float64
	}{
		{"a-b-c-123", '-', 91000, 82.98905320449123},
		{"a.b.c.123", '.', 91000, 82.98905320449123},
	}

	for _, tt := range tests {
		if got := wordlistEntropy(tt.password, tt.separator, tt.wordlistSize); got != tt.want {
			t.Errorf("wordlistEntropy(%q, %q, %d) = %v, want %v", tt.password, string(tt.separator), tt.wordlistSize, got, tt.want)
		}
	}
}

func TestRandomWord(t *testing.T) {
	maxLength := uint(7)
	word := randomWord(maxLength)
	if len(word) > int(maxLength) {
		t.Errorf("randomWord(%d) = %q, want length <= %d", maxLength, word, maxLength)
	}
}

func TestRandomAlphaNumericSegment(t *testing.T) {
	segment := randomAlphaNumericSegment()
	if len(segment) != 3 {
		t.Errorf("randomAlphaNumericSegment() = %q, want length == 3", segment)
	}
	var hasChar, hasNum bool
	for _, c := range segment {
		if c >= 'A' && c <= 'Z' {
			hasChar = true
		} else if c >= '0' && c <= '9' {
			hasNum = true
		}
	}
	if !hasChar || !hasNum {
		t.Errorf("randomAlphaNumericSegment() = %q, want at least one char and one num", segment)
	}
}
