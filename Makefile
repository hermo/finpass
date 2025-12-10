.PHONY: cli wasm js test serve serve-js clean

cli:
	go build -ldflags="-s -w" -o finpass

wasm:
	GOTOOLCHAIN=local GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o wasm/finpass.wasm ./wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" ./wasm/

js:
	cd js && bun run build

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
