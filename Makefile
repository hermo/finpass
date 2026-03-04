.PHONY: favicon cli wasm js test serve serve-js clean ext-icons ext-sync ext-firefox ext-chrome ext-test ext-package-firefox ext-package-chrome

cli:
	go build -ldflags="-s -w" -o finpass

wasm:
	GOTOOLCHAIN=local GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o wasm/finpass.wasm ./wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" ./wasm/

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

# Serve the WASM version on port 8000
serve: wasm
	@echo "Serving on http://localhost:8000"
	python3 -m http.server 8000 -d wasm

# Serve the TypeScript version on port 8080
serve-js: js
	@echo "Serving on http://localhost:8080"
	python3 -m http.server 8080 -d js/dist

clean:
	rm -f finpass wasm/finpass.wasm wasm/wasm_exec.js js/dist/* extension/manifest.json finpass-firefox.xpi finpass-chrome.zip

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
