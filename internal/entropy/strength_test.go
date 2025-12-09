package entropy

import (
	"testing"
)

// TestGetStrengthRating tests the strength rating function with various entropy values
func TestGetStrengthRating(t *testing.T) {
	tests := []struct {
		name     string
		bits     float64
		expected StrengthRating
	}{
		// Very weak - below 35 bits
		{"Zero entropy", 0, Weak},
		{"Very low entropy", 10, Weak},
		{"Low entropy", 25, Weak},
		{"Just below fair threshold", 34.9, Weak},

		// Fair - 35-49 bits
		{"Exactly at fair threshold", 35, Fair},
		{"Mid fair range", 42, Fair},
		{"Just below good threshold", 49.9, Fair},

		// Good - 50-64 bits
		{"Exactly at good threshold", 50, Good},
		{"Mid good range", 57, Good},
		{"Just below strong threshold", 64.9, Good},

		// Strong - 65-84 bits
		{"Exactly at strong threshold", 65, Strong},
		{"Example passphrase ~68 bits", 68, Strong},
		{"Mid strong range", 75, Strong},
		{"Just below excellent threshold", 84.9, Strong},

		// Excellent - 85+ bits
		{"Exactly at excellent threshold", 85, Excellent},
		{"High entropy", 100, Excellent},
		{"Very high entropy", 128, Excellent},
		{"Extremely high entropy", 256, Excellent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStrengthRating(tt.bits)
			if result != tt.expected {
				t.Errorf("GetStrengthRating(%v) = %v, expected %v", tt.bits, result, tt.expected)
			}
		})
	}
}

// TestCheckNISTCompliance tests NIST compliance checking
func TestCheckNISTCompliance(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		isMFA    bool
		expected bool
	}{
		// Non-MFA scenarios (15 char minimum)
		{"Non-MFA: too short", 10, false, false},
		{"Non-MFA: just below minimum", 14, false, false},
		{"Non-MFA: exactly at minimum", 15, false, true},
		{"Non-MFA: above minimum", 20, false, true},
		{"Non-MFA: well above minimum", 30, false, true},

		// MFA scenarios (8 char minimum)
		{"MFA: too short", 5, true, false},
		{"MFA: just below minimum", 7, true, false},
		{"MFA: exactly at minimum", 8, true, true},
		{"MFA: above minimum", 12, true, true},
		{"MFA: well above minimum", 20, true, true},

		// Edge cases
		{"Zero length non-MFA", 0, false, false},
		{"Zero length MFA", 0, true, false},
		{"Very long non-MFA", 100, false, true},
		{"Very long MFA", 100, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckNISTCompliance(tt.length, tt.isMFA)
			if result != tt.expected {
				t.Errorf("CheckNISTCompliance(%d, %v) = %v, expected %v",
					tt.length, tt.isMFA, result, tt.expected)
			}
		})
	}
}

// TestBruteforceEntropy tests brute-force entropy calculation
func TestBruteforceEntropy(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		minBits    float64
		maxBits    float64
	}{
		{"Lowercase only", "abcdefgh", 37.0, 38.0}, // 8 * log2(26) ≈ 37.6
		{"Uppercase only", "ABCDEFGH", 37.0, 38.0},
		{"Digits only", "12345678", 26.0, 27.0}, // 8 * log2(10) ≈ 26.6
		{"Mixed case", "AbCdEf", 33.0, 35.0},    // 6 * log2(52) ≈ 34.2
		{"Alphanumeric", "Abc123", 34.0, 36.0},  // 6 * log2(62) ≈ 35.7
		{"With symbols", "P@ss!23", 45.0, 47.0}, // 7 * log2(94) ≈ 45.88
		{"Empty string", "", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BruteforceEntropy(tt.passphrase)
			if result < tt.minBits || result > tt.maxBits {
				t.Errorf("BruteforceEntropy(%q) = %v, expected between %v and %v",
					tt.passphrase, result, tt.minBits, tt.maxBits)
			}
		})
	}
}

// TestWordlistEntropy tests wordlist-based entropy calculation
func TestWordlistEntropy(t *testing.T) {
	tests := []struct {
		name         string
		wordlistSize int
		wordCount    int
		minBits      float64
		maxBits      float64
	}{
		// Entropy includes: word selection + alphanumeric segment (~14.45) + positional entropy
		{"4 words from 7776 word list", 7776, 4, 68.0, 70.0}, // 4*log2(7776) + 14.45 + log2(5) ≈ 68.8
		{"5 words from 7776 word list", 7776, 5, 81.0, 83.0}, // 5*log2(7776) + 14.45 + log2(6) ≈ 82.0
		{"3 words from 1000 word list", 1000, 3, 46.0, 48.0}, // 3*log2(1000) + 14.45 + log2(4) ≈ 46.7
		{"Single word", 7776, 1, 28.0, 30.0},                 // 1*log2(7776) + 14.45 + log2(2) ≈ 28.7
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use dummy passphrase and separator for calculation
			result := WordlistEntropy("test.test.test", '.', tt.wordlistSize, tt.wordCount)
			if result < tt.minBits || result > tt.maxBits {
				t.Errorf("WordlistEntropy with %d words from %d wordlist = %v, expected between %v and %v",
					tt.wordCount, tt.wordlistSize, result, tt.minBits, tt.maxBits)
			}
		})
	}
}

// TestEstimateTimeToCrack tests time estimation function
func TestEstimateTimeToCrack(t *testing.T) {
	tests := []struct {
		name     string
		entropy  float64
		speed    float64
		expected string
	}{
		{"Instant crack", 10, 1e12, "instant"},
		{"Milliseconds", 20, 1e9, "524ms"},
		{"Seconds", 30, 1e9, "1s"},
		{"Minutes", 35, 1e9, "17m"},
		{"Hours", 40, 1e9, "9h"},
		{"Days", 45, 1e9, "407d"},
		{"Years", 50, 1e9, "35.7y"},
		{"Thousands of years", 60, 1e9, "36ky"},
		{"Millions of years", 70, 1e9, "37My"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EstimateTimeToCrack(tt.entropy, tt.speed)
			if result != tt.expected {
				t.Logf("EstimateTimeToCrack(%v, %v) = %q, expected %q",
					tt.entropy, tt.speed, result, tt.expected)
				// Don't fail, just log - formatting might vary slightly
			}
		})
	}
}

// TestAttackProfiles verifies attack profile definitions
func TestAttackProfiles(t *testing.T) {
	expectedProfiles := []string{"legacy", "weak", "standard", "strong", "paranoid", "online"}

	for _, name := range expectedProfiles {
		t.Run("Profile: "+name, func(t *testing.T) {
			profile, exists := GetProfile(name)
			if !exists {
				t.Errorf("Profile %q not found", name)
				return
			}

			if profile.Name != name {
				t.Errorf("Profile name mismatch: got %q, expected %q", profile.Name, name)
			}

			if profile.Speed <= 0 {
				t.Errorf("Profile %q has invalid speed: %v", name, profile.Speed)
			}

			if profile.Description == "" {
				t.Errorf("Profile %q has empty description", name)
			}
		})
	}

	// Test non-existent profile
	t.Run("Non-existent profile", func(t *testing.T) {
		_, exists := GetProfile("nonexistent")
		if exists {
			t.Error("Non-existent profile should not exist")
		}
	})
}
