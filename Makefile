.PHONY: favicon cli js test serve-js clean ext-icons ext-sync ext-firefox ext-chrome ext-test ext-package-firefox ext-package-chrome ape-container

cli:
	go build -ldflags="-s -w" -o finpass

favicon:
	gm convert js/favicon.svg -background none -define icon:auto-resize=48,32,16 js/favicon.ico
	gm convert js/favicon.svg -background none -resize 32x32 js/favicon-32x32.png
	gm convert js/favicon.svg -background none -resize 16x16 js/favicon-16x16.png
	gm convert js/favicon.svg -background none -resize 192x192 js/android-chrome-192x192.png
	gm convert js/favicon.svg -background none -resize 512x512 js/android-chrome-512x512.png
	gm convert js/favicon.svg -background none -resize 180x180 js/apple-touch-icon.png
	gm convert js/favicon.svg -background white -alpha remove -flatten -resize 180x180 js/apple-touch-icon.png

js: favicon
	cd js && bun run build
	cp js/favicon* js/dist/
	cp js/apple-touch-icon.png js/dist/
	cp js/android-chrome*.png js/dist/
	cp js/site.webmanifest js/dist/

test:
	go test ./...

# Serve the TypeScript version on port 8080
serve-js: js
	@echo "Serving on http://localhost:8080"
	python3 -m http.server 8080 -d js/dist

clean:
	rm -f finpass js/dist/* extension/manifest.json finpass-firefox.xpi finpass-chrome.zip

# Generate extension icons from the website favicon SVG
ext-icons:
	mkdir -p extension/icons
	gm convert js/favicon.svg -background none -resize 16x16 extension/icons/icon-16.png
	gm convert js/favicon.svg -background none -resize 48x48 extension/icons/icon-48.png
	gm convert js/favicon.svg -background none -resize 128x128 extension/icons/icon-128.png

# Copy shared assets into extension/
ext-sync: ext-icons
	cp internal/words.txt extension/words.txt

# Package for Firefox (Manifest V2)
ext-firefox: ext-sync
	cp extension/manifest.v2.json extension/manifest.json

# Package for Chrome (Manifest V3)
ext-chrome: ext-sync
	cp extension/manifest.v3.json extension/manifest.json

# Build Firefox .xpi package
ext-package-firefox: ext-firefox
	cd extension && zip -r ../finpass-firefox.xpi . \
		-x "node_modules/*" "tests/*" "package.json" "package-lock.json" \
		"vitest.config.js" "manifest.v2.json" "manifest.v3.json" "icons/icon.svg"

# Build Chrome .zip package
ext-package-chrome: ext-chrome
	cd extension && zip -r ../finpass-chrome.zip . \
		-x "node_modules/*" "tests/*" "package.json" "package-lock.json" \
		"vitest.config.js" "manifest.v2.json" "manifest.v3.json" "icons/icon.svg"

ext: ext-package-firefox ext-package-chrome

# Run extension tests
ext-test:
	cd extension && npx vitest --run

# =============================================================================
# C / Cosmopolitan APE build
# =============================================================================
# Builds the C11 port as a fat Actually Portable Executable (APE) via
# cosmocc. The Finnish wordlist is front-coded by c/tools/wordenc.c (one
# shared-prefix-length byte < 32 per word followed by the differing suffix;
# the control byte doubles as the delimiter) and embedded as a zip asset
# readable at runtime from the vfs path /zip/words.fc (see c/src/words.c).

.PHONY: ape ape-test ape-clean

COSMOCC ?= cosmocc
ZIPOBJ ?= $(dir $(COSMOCC))zipobj
APE_CFLAGS = -Wall -Wextra -Wpedantic -Werror -O2 -std=c11 \
	-DFINPASS_VERSION='"$(shell git describe --tags --always --dirty 2>/dev/null || echo devel)"'

APE_CORE_SRCS = c/src/rand.c c/src/words.c c/src/passphrase.c c/src/entropy.c
APE_TEST_NAMES = test_rand test_words test_entropy test_passphrase
APE_TEST_BINS = $(addprefix c/obj/,$(APE_TEST_NAMES))

c/obj/wordenc: c/tools/wordenc.c
	mkdir -p c/obj
	$(COSMOCC) $(APE_CFLAGS) $< -o $@

c/obj/words.fc: internal/words.txt c/obj/wordenc
	c/obj/wordenc internal/words.txt c/obj/words.fc

# Embedded wordlist object. cosmocc's fat-binary linker needs both arch
# variants present: the x86_64 object here, and an aarch64 twin in a
# .aarch64/ subdirectory next to it (same basename).
c/obj/words.o: c/obj/words.fc
	mkdir -p c/obj/.aarch64
	$(ZIPOBJ) -a x86_64 -B -o c/obj/words.o c/obj/words.fc
	$(ZIPOBJ) -a aarch64 -B -o c/obj/.aarch64/words.o c/obj/words.fc

ape: c/obj/words.o
	$(COSMOCC) $(APE_CFLAGS) c/src/main.c $(APE_CORE_SRCS) c/obj/words.o -o finpass.ape

CONTAINER_ENGINE ?= podman

# Build finpass.ape inside a container (no local cosmocc needed) and copy it out
ape-container:
	$(CONTAINER_ENGINE) build -t finpass-builder .
	@cid=$$($(CONTAINER_ENGINE) create finpass-builder); \
	$(CONTAINER_ENGINE) cp $$cid:/app/finpass.ape ./finpass.ape; \
	rc=$$?; \
	$(CONTAINER_ENGINE) rm -f $$cid >/dev/null; \
	exit $$rc

# Each test binary links the non-main core sources plus the embedded
# wordlist object, so any test may exercise wordlist_load() if it needs to.
c/obj/test_%: c/tests/test_%.c $(APE_CORE_SRCS) c/obj/words.o
	mkdir -p c/obj
	$(COSMOCC) $(APE_CFLAGS) $< $(APE_CORE_SRCS) c/obj/words.o -o $@

ape-test: $(APE_TEST_BINS)
	@for t in $(APE_TEST_BINS); do \
		echo "Running $$t"; \
		$$t || exit 1; \
	done

ape-clean:
	rm -f finpass.ape
	rm -rf c/obj
