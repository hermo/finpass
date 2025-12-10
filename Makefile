.PHONY: favicon cli wasm js test serve serve-js clean

cli:
	go build -ldflags="-s -w" -o finpass

wasm:
	GOTOOLCHAIN=local GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o wasm/finpass.wasm ./wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" ./wasm/

favicon:
	magick js/favicon.svg -background none -define icon:auto-resize=48,32,16 js/favicon.ico
	magick js/favicon.svg -background none -resize 32x32 js/favicon-32x32.png
	magick js/favicon.svg -background none -resize 16x16 js/favicon-16x16.png
	magick js/favicon.svg -background none -resize 192x192 js/android-chrome-192x192.png
	magick js/favicon.svg -background none -resize 512x512 js/android-chrome-512x512.png
	magick js/favicon.svg -background none -resize 180x180 js/apple-touch-icon.png
	magick js/favicon.svg -background white -alpha remove -flatten -resize 180x180 js/apple-touch-icon.png

js:
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

# Serve the vanilla JavaScript version on port 8080
serve-js: js
	@echo "Serving on http://localhost:8080"
	python3 -m http.server 8080 -d js/dist

clean:
	rm -f finpass wasm/finpass.wasm wasm/wasm_exec.js js/dist/*
