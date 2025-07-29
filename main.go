package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hermo/finpass/entropy"
)

const (
	// Default password generation parameters
	DefaultWordCount     = 3
	MinWordCount         = 1
	MaxWordCount         = 6
	MinWordLength        = 3
	DefaultDelimiter     = "-"
	DefaultPasswordCount = 1
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
	flag.IntVar(&settings.WordCount, "w", DefaultWordCount, "number of words (1-6)")
	flag.StringVar(&settings.Profile, "profile", "standard", "attack profile (legacy, weak, standard, strong, paranoid, online)")
	flag.BoolVar(&settings.ListProfiles, "list-profiles", false, "show available attack profiles")
	flag.BoolVar(&settings.AllProfiles, "all-profiles", false, "show entropy for all attack profiles")
	flag.Float64Var(&settings.CustomSpeed, "custom-speed", 0, "custom attack speed (guesses per second)")
	flag.IntVar(&settings.Count, "n", DefaultPasswordCount, "number of passwords to generate")
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
		ListAllProfiles()
		return
	}

	if settings.MaxLength > 0 && settings.MaxLength < MinWordLength {
		fmt.Fprintf(os.Stderr, "maxlen must be at least %d\n", MinWordLength)
		os.Exit(1)
	}

	if settings.WordCount < MinWordCount || settings.WordCount > MaxWordCount {
		fmt.Fprintf(os.Stderr, "word count must be between %d and %d\n", MinWordCount, MaxWordCount)
		os.Exit(1)
	}

	if settings.Count < DefaultPasswordCount {
		fmt.Fprintf(os.Stderr, "count must be at least %d\n", DefaultPasswordCount)
		os.Exit(1)
	}

	if settings.Count > 1 && (settings.ShowInfo || settings.AllProfiles) {
		fmt.Fprintln(os.Stderr, "entropy analysis (-i or -all-profiles) cannot be used with multiple passwords (-n > 1)")
		os.Exit(1)
	}

	wordFn := func() string {
		return entropy.RandomWord(settings.MaxLength, words)
	}

	var lastPassphrase string
	delimiterRune := rune(settings.Delimiter[0])
	var smallWords []string
	if settings.MaxLength > 0 {
		smallWords = entropy.WordlistSubset(settings.MaxLength, words)
	}

	for i := 0; i < settings.Count; i++ {
		var parts []string
		for j := 0; j < settings.WordCount; j++ {
			parts = append(parts, wordFn())
		}
		parts = append(parts, entropy.RandomAlphaNumericSegment(entropy.AlphaNumericSegmentLength))

		totalParts := len(parts)
		x, err := entropy.RandomInt(totalParts)
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
		entropy.DisplayEntropyInfo(lastPassphrase, delimiterRune, settings.WordCount, settings.MaxLength, smallWords, settings.AllProfiles, settings.CustomSpeed, settings.Profile, words)
	}
}
