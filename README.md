# Generate passwords using Finnish language words

This tiny program generates somewhat memorable passwords in Finnish.
Each generated password also includes a randomly placed 3-character Base32 section to add entropy.

It accepts no parameters.

Example password: `molekyylibiologia-madonnamainen-QR5-kirkonrotta`

The wordlist contains about 91690 words and is a subset of the wordlist found at https://github.com/hugovk/everyfinnishword

## Installation
Clone the repo and run `go build`.