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
$ finpass -i
valuuttanoteeraus-yliset-B4X-halonhakkaaja
Entropy and estimated time to crack using a fast GPU-based attack (20 MH/s, one or more RTX 4090):
* Brute-force:    259.1 bits (1614835348617068708984695086383104.0 nonillions of years)
* Wordlist-based:  66.5 bits (169.7 thousand years)
```

The wordlist contains about 91k words and is a subset of the wordlist found at https://github.com/hugovk/everyfinnishword

## Installation

Pre-built releases exist for Linux, macOS and Windows on amd64/arm64 platforms. See the releases for details.

## Development
Clone the repo and run `go build`.
