package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
)

func main() {
	parts := []string{randomWord(), randomWord(), randomWord(), randomAlphaNumericString()}
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

func randomWord() string {
	numWords := len(words)
	word := words[randomInt(numWords)]
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
