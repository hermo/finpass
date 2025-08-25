package internal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
)

//go:embed words.txt.gz
var compressedWords []byte

var Words []string

func init() {
	// Decompress the wordlist at startup
	reader, err := gzip.NewReader(bytes.NewReader(compressedWords))
	if err != nil {
		panic("Failed to create gzip reader: " + err.Error())
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			Words = append(Words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		panic("Failed to read compressed wordlist: " + err.Error())
	}
}
