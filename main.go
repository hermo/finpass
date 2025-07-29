package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Version is set at build time via -ldflags
var version = "devel"

type Settings struct {
	MaxLength    uint
	ShowInfo     bool
	Delimiter    string
	WordCount    int
	Profile      string
	ListProfiles bool
	AllProfiles  bool
	CustomSpeed  float64
	Count        int
	ShowVersion  bool
}

func ParseFlags() Settings {
	var settings Settings
	flag.UintVar(&settings.MaxLength, "m", 0, "maximum length of each word component")
	flag.BoolVar(&settings.ShowInfo, "i", false, "show entropy and estimated time to crack")
	flag.StringVar(&settings.Delimiter, "d", "-", "delimiter between password components")
	flag.IntVar(&settings.WordCount, "w", 3, "number of words (1-6)")
	flag.StringVar(&settings.Profile, "profile", "standard", "attack profile (legacy, weak, standard, strong, paranoid, online)")
	flag.BoolVar(&settings.ListProfiles, "list-profiles", false, "show available attack profiles")
	flag.BoolVar(&settings.AllProfiles, "all-profiles", false, "show entropy for all attack profiles")
	flag.Float64Var(&settings.CustomSpeed, "custom-speed", 0, "custom attack speed (guesses per second)")
	flag.IntVar(&settings.Count, "n", 1, "number of passwords to generate")
	flag.BoolVar(&settings.ShowVersion, "version", false, "show version information")
	flag.BoolVar(&settings.ShowVersion, "V", false, "show version information (short form)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "\nGenerate passwords using Finnish language words.")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  finpass                    # Generate one password")
		fmt.Fprintln(os.Stderr, "  finpass -n 5               # Generate 5 passwords")
		fmt.Fprintln(os.Stderr, "  finpass -i -profile strong # Show entropy analysis")
		fmt.Fprintln(os.Stderr, "  finpass -w 4 -d .          # 4 words with dot delimiter")
	}

	flag.Parse()
	return settings
}

func main() {
	settings := ParseFlags()

	if settings.ShowVersion {
		fmt.Printf("finpass version %s\n", version)
		fmt.Println("Generate passwords using Finnish language words")
		return
	}

	if settings.ListProfiles {
		listAllProfiles()
		return
	}

	if settings.MaxLength > 0 && settings.MaxLength < 3 {
		fmt.Fprintln(os.Stderr, "maxlen must be at least 3")
		os.Exit(1)
	}

	if settings.WordCount < 1 || settings.WordCount > 6 {
		fmt.Fprintln(os.Stderr, "word count must be between 1 and 6")
		os.Exit(1)
	}

	if settings.Count < 1 {
		fmt.Fprintln(os.Stderr, "count must be at least 1")
		os.Exit(1)
	}

	if settings.Count > 1 && (settings.ShowInfo || settings.AllProfiles) {
		fmt.Fprintln(os.Stderr, "entropy analysis (-i or -all-profiles) cannot be used with multiple passwords (-n > 1)")
		os.Exit(1)
	}

	wordFn := func() string {
		return randomWord(settings.MaxLength)
	}

	var lastPassphrase string
	delimiterRune := rune(settings.Delimiter[0])
	var smallWords []string
	if settings.MaxLength > 0 {
		smallWords = wordlistSubset(settings.MaxLength)
	}

	for i := 0; i < settings.Count; i++ {
		var parts []string
		for j := 0; j < settings.WordCount; j++ {
			parts = append(parts, wordFn())
		}
		parts = append(parts, randomAlphaNumericSegment())

		totalParts := len(parts)
		x, err := randomInt(totalParts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating random index: %v\n", err)
			os.Exit(1)
		}
		parts[x], parts[totalParts-1] = parts[totalParts-1], parts[x]

		passphrase := strings.Join(parts, settings.Delimiter)
		lastPassphrase = passphrase

		fmt.Println(passphrase)
	}

	if settings.ShowInfo || settings.AllProfiles {
		passphrase := lastPassphrase
		if settings.AllProfiles {
			bruteEnt, patternEnt, wordlistEnt := calculateEntropyForProfile(passphrase, delimiterRune, settings.WordCount, AttackProfile{})

			fmt.Fprintf(os.Stderr, "Password entropy analysis:\n")
			fmt.Fprintf(os.Stderr, "  Brute-force:          %5.1f bits\n", bruteEnt)
			fmt.Fprintf(os.Stderr, "  Pattern-aware attack: %5.1f bits\n", patternEnt)
			fmt.Fprintf(os.Stderr, "  Known wordlist:       %5.1f bits\n", wordlistEnt)
			if settings.MaxLength > 0 {
				wordlistEntWithSize := wordlistEntropy(passphrase, delimiterRune, len(smallWords), settings.WordCount)
				fmt.Fprintf(os.Stderr, "  Known wordlist+params:%5.1f bits\n", wordlistEntWithSize)
			}
			fmt.Fprintln(os.Stderr, "")

			fmt.Fprintf(os.Stderr, "Time to crack estimates by attack scenario:\n")
			fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s", "Profile", "Brute-force", "Pattern-aware", "Wordlist")
			if settings.MaxLength > 0 {
				fmt.Fprintf(os.Stderr, " %-18s", "Wordlist+params")
			}
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s", "-------", "------------------", "------------------", "------------------")
			if settings.MaxLength > 0 {
				fmt.Fprintf(os.Stderr, " %-18s", "------------------")
			}
			fmt.Fprintln(os.Stderr, "")

			for _, profileName := range []string{"online", "paranoid", "strong", "standard", "weak", "legacy"} {
				profile := attackProfiles[profileName]
				fmt.Fprintf(os.Stderr, "%-10s %-18s %-18s %-18s",
					profile.Name,
					estimateTimeToCrack(bruteEnt, profile.Speed),
					estimateTimeToCrack(patternEnt, profile.Speed),
					estimateTimeToCrack(wordlistEnt, profile.Speed))
				if settings.MaxLength > 0 {
					wordlistEntWithSize := wordlistEntropy(passphrase, delimiterRune, len(smallWords), settings.WordCount)
					fmt.Fprintf(os.Stderr, " %-18s", estimateTimeToCrack(wordlistEntWithSize, profile.Speed))
				}
				fmt.Fprintln(os.Stderr, "")
			}
		} else {
			var speed float64
			var profileDesc string

			if settings.CustomSpeed > 0 {
				speed = settings.CustomSpeed
				profileDesc = fmt.Sprintf("custom speed (%.0e guesses/sec)", speed)
			} else {
				profile, exists := getProfile(settings.Profile)
				if !exists {
					fmt.Fprintf(os.Stderr, "Unknown profile: %s\n", settings.Profile)
					fmt.Fprintln(os.Stderr, "Use --list-profiles to see available profiles")
					os.Exit(1)
				}
				speed = profile.Speed
				profileDesc = profile.Description
			}

			bruteEnt, patternEnt, wordlistEnt := calculateEntropyForProfile(passphrase, delimiterRune, settings.WordCount, AttackProfile{Speed: speed})

			fmt.Fprintf(os.Stderr, "Entropy and estimated time to crack using %s:\n", profileDesc)
			fmt.Fprintf(os.Stderr, "* Brute-force:           %5.1f bits (%s)\n", bruteEnt, estimateTimeToCrack(bruteEnt, speed))
			fmt.Fprintf(os.Stderr, "* Pattern-aware attack:  %5.1f bits (%s)\n", patternEnt, estimateTimeToCrack(patternEnt, speed))
			fmt.Fprintf(os.Stderr, "* Known wordlist:        %5.1f bits (%s)\n", wordlistEnt, estimateTimeToCrack(wordlistEnt, speed))
			if settings.MaxLength > 0 {
				wordlistEntWithSize := wordlistEntropy(passphrase, delimiterRune, len(smallWords), settings.WordCount)
				fmt.Fprintf(os.Stderr, "* Known wordlist and parameters (-m=%d): %5.1f bits (%s)\n", settings.MaxLength, wordlistEntWithSize, estimateTimeToCrack(wordlistEntWithSize, speed))
			}
		}
	}
}

func randomInt(max int) (int64, error) {
	if max == 0 {
		return 0, nil
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random integer: %w", err)
	}
	return nBig.Int64(), nil
}

func wordlistSubset(maxLength uint) []string {
	var wordlist []string
	for _, word := range words {
		if uint(len(word)) <= maxLength {
			wordlist = append(wordlist, word)
		}
	}
	return wordlist
}

func randomWord(maxLength uint) string {
	numWords := len(words)
	idx, err := randomInt(numWords)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random word index: %v\n", err)
		os.Exit(1)
	}
	word := words[idx]
	if maxLength > 0 {
		for uint(len(word)) > maxLength {
			idx, err := randomInt(numWords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating random word index: %v\n", err)
				os.Exit(1)
			}
			word = words[idx]
		}
	}
	return word
}

func randomAlphaNumericSegment() string {
	const (
		alphanumericChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)

	var sb strings.Builder
	sb.Grow(3) // Pre-allocate capacity for 3 characters

	var hasChar, hasNum bool

	for {
		sb.Reset() // Clear the builder for a new attempt
		hasChar = false
		hasNum = false

		for i := 0; i < 3; i++ {
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
