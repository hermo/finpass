package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
)

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
}

func ParseFlags() Settings {
	var settings Settings
	flag.UintVar(&settings.MaxLength, "m", 0, "maxlen")
	flag.BoolVar(&settings.ShowInfo, "i", false, "show entropy and estimated time to crack")
	flag.StringVar(&settings.Delimiter, "d", "-", "delimiter")
	flag.IntVar(&settings.WordCount, "w", 3, "number of words (1-6)")
	flag.StringVar(&settings.Profile, "profile", "standard", "attack profile (legacy, weak, standard, strong, paranoid, online)")
	flag.BoolVar(&settings.ListProfiles, "list-profiles", false, "show available attack profiles")
	flag.BoolVar(&settings.AllProfiles, "all-profiles", false, "show entropy for all attack profiles")
	flag.Float64Var(&settings.CustomSpeed, "custom-speed", 0, "custom attack speed (guesses per second)")
	flag.IntVar(&settings.Count, "n", 1, "number of passwords to generate")
	flag.Parse()
	return settings
}

func main() {
	settings := ParseFlags()

	if settings.ListProfiles {
		listAllProfiles()
		return
	}

	if settings.MaxLength > 0 && settings.MaxLength < 3 {
		fmt.Println("maxlen must be at least 3")
		os.Exit(1)
	}

	if settings.WordCount < 1 || settings.WordCount > 6 {
		fmt.Println("word count must be between 1 and 6")
		os.Exit(1)
	}

	if settings.Count < 1 {
		fmt.Println("count must be at least 1")
		os.Exit(1)
	}

	if settings.Count > 1 && (settings.ShowInfo || settings.AllProfiles) {
		fmt.Println("entropy analysis (-i or -all-profiles) cannot be used with multiple passwords (-n > 1)")
		os.Exit(1)
	}

	wordFn := func() string {
		return randomWord(settings.MaxLength)
	}

	var lastPassphrase string
	delimiterRune := rune(settings.Delimiter[0])

	for i := 0; i < settings.Count; i++ {
		var parts []string
		for j := 0; j < settings.WordCount; j++ {
			parts = append(parts, wordFn())
		}
		parts = append(parts, randomAlphaNumericSegment())

		totalParts := len(parts)
		x := randomInt(totalParts)
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
				smallWords := wordlistSubset(settings.MaxLength)
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
					smallWords := wordlistSubset(settings.MaxLength)
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
					fmt.Printf("Unknown profile: %s\n", settings.Profile)
					fmt.Println("Use --list-profiles to see available profiles")
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
				smallWords := wordlistSubset(settings.MaxLength)
				wordlistEntWithSize := wordlistEntropy(passphrase, delimiterRune, len(smallWords), settings.WordCount)
				fmt.Fprintf(os.Stderr, "* Known wordlist and parameters (-m=%d): %5.1f bits (%s)\n", settings.MaxLength, wordlistEntWithSize, estimateTimeToCrack(wordlistEntWithSize, speed))
			}
		}
	}
}

func randomInt(max int) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return n.Int64()
}

func randomByte() byte {
	var b [1]byte
	n, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	if n != 1 {
		panic("expected to read 1 byte")
	}
	return b[0]
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
	word := words[randomInt(numWords)]
	if maxLength > 0 {
		for uint(len(word)) > maxLength {
			word = words[randomInt(numWords)]
		}
	}
	return word
}

func randomAlphaNumericSegment() string {
	var segment string
	var hasChar, hasNum bool

	for segment = ""; len(segment) < 3 || !(hasChar && hasNum); {
		hasChar = false
		hasNum = false
		segment = ""
		for i := 0; i < 3; i++ {
			c := randomByte()
			if c >= '0' && c <= '9' {
				hasNum = true
				segment += string(c)
			} else if c >= 'A' && c <= 'Z' {
				hasChar = true
				segment += string(c)
			}
		}
	}
	return segment
}
