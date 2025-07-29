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
		if got := BruteforceEntropy(tt.password); got != tt.want {
			t.Errorf("BruteforceEntropy(%q) = %v, want %v", tt.password, got, tt.want)
		}
	}
}

func TestWordlistEntropy(t *testing.T) {
	tests := []struct {
		password     string
		separator    rune
		wordlistSize int
		wordCount    int
		want         float64
	}{
		{"a-b-c-123", '-', 91000, 3, 66.19799208977426},
		{"a.b.c.123", '.', 91000, 3, 66.19799208977426},
	}

	for _, tt := range tests {
		if got := WordlistEntropy(tt.password, tt.separator, tt.wordlistSize, tt.wordCount); got != tt.want {
			t.Errorf("WordlistEntropy(%q, %q, %d, %d) = %v, want %v", tt.password, string(tt.separator), tt.wordlistSize, tt.wordCount, got, tt.want)
		}
	}
}

func TestRandomWord(t *testing.T) {
	maxLength := uint(7)
	word := RandomWord(maxLength)
	if len(word) > int(maxLength) {
		t.Errorf("RandomWord(%d) = %q, want length <= %d", maxLength, word, maxLength)
	}
}

func TestRandomAlphaNumericSegment(t *testing.T) {
	segment := RandomAlphaNumericSegment(3)
	if len(segment) != 3 {
		t.Errorf("RandomAlphaNumericSegment() = %q, want length == %d", segment, 3)
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
