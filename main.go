package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
)

type Settings struct {
	MaxLength uint
	ShowInfo  bool
}

func ParseFlags() Settings {
	var settings Settings
	flag.UintVar(&settings.MaxLength, "m", 0, "maxlen")
	flag.BoolVar(&settings.ShowInfo, "i", false, "show entropy and estimated time to crack")
	flag.Parse()
	return settings
}

func main() {
	settings := ParseFlags()

	if settings.MaxLength > 0 && settings.MaxLength < 3 {
		fmt.Println("maxlen must be at least 3")
		os.Exit(1)
	}

	wordFn := func() string {
		return randomWord(settings.MaxLength)
	}

	parts := []string{wordFn(), wordFn(), wordFn(), randomAlphaNumericSegment()}
	x := randomInt(4)
	parts[x], parts[3] = parts[3], parts[x]
	passphrase := fmt.Sprintf("%s-%s-%s-%s", parts[0], parts[1], parts[2], parts[3])
	fmt.Println(passphrase)

	if settings.ShowInfo {
		bruteEnt := bruteforceEntropy(passphrase)
		wordlistEnt := wordlistEntropy(passphrase, '-', len(words))
		fmt.Fprintln(os.Stderr, "Entropy and estimated time to crack using a fast GPU-based attack (20 MH/s, one or more RTX 4090):")
		fmt.Fprintf(os.Stderr, "* Brute-force:    %5.1f bits (%s)\n", bruteEnt, estimateTimeToCrack(bruteEnt))
		fmt.Fprintf(os.Stderr, "* Known wordlist: %5.1f bits (%s)\n", wordlistEnt, estimateTimeToCrack(wordlistEnt))
		if settings.MaxLength > 0 {
			smallWords := wordlistSubset(settings.MaxLength)
			wordlistEntWithSize := wordlistEntropy(passphrase, '-', len(smallWords))
			fmt.Fprintf(os.Stderr, "* Known wordlist and parameters (-m=%d): %5.1f bits (%s)\n", settings.MaxLength, wordlistEntWithSize, estimateTimeToCrack(wordlistEntWithSize))
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

// wordlistSubset returns a subset of the wordlist with words of length
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
