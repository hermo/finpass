# Generate passwords using Finnish language words

This tiny program generates somewhat memorable passwords in Finnish.
Each generated password also includes a randomly placed 3-character alphanumeric section to add entropy.

## Flags

| Flag      | Description                              |
|-----------|------------------------------------------|
| -i        | Show entropy and estimated time to crack |
| -m MAXLEN | Maximum length of each word component    |


Example:

```
$ finpass -i -m 7
36C-kytkea-terkut-koukuta
Entropy and estimated time to crack using a fast GPU-based attack (20 MH/s, one or more RTX 4090):
* Brute-force:    154.2 bits (~43 nonillion years)
* Known wordlist:  66.5 bits (~170 thousand years)
* Known wordlist and parameters (-m=7):  58.6 bits (~7 centuries)
```

The wordlist contains about 91k words and is a subset of the wordlist found at https://github.com/hugovk/everyfinnishword

## Installation

Pre-built releases exist for Linux, macOS and Windows on amd64/arm64 platforms. See the releases for details.

## Development
Clone the repo and run `cargo build -r`.
