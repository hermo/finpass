package main

import (
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"math/big"
	"os"
)

type Settings struct {
	MaxLength uint
}

func ParseFlags() Settings {
	var settings Settings
	flag.UintVar(&settings.MaxLength, "m", 0, "maxlen")
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

	parts := []string{wordFn(), wordFn(), wordFn(), randomAlphaNumericString()}
	x := randomInt(4)
	parts[x], parts[3] = parts[3], parts[x]
	passphrase := fmt.Sprintf("%s-%s-%s-%s", parts[0], parts[1], parts[2], parts[3])
	fmt.Println(passphrase)
}

func randomInt(max int) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return n.Int64()
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

func randomAlphaNumericString() string {
	for {
		randomBytes := make([]byte, 2)
		_, err := rand.Read(randomBytes)
		if err != nil {
			panic(err)
		}
		s := base32.StdEncoding.EncodeToString(randomBytes)[:3]
		if isAlphaNumeric(s) {
			return s
		}
	}
}

func isAlphaNumeric(s string) bool {
	alpha := false
	numeric := false

	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			alpha = true
		}
		if r >= '0' && r <= '9' {
			numeric = true
		}
	}
	return alpha && numeric
}
