package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
)

func main() {
	parts := []string{randomWord(), randomWord(), randomWord(), randomStr()}
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

func randomStr() string {
	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:3]
}
