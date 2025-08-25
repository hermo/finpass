.PHONY: cli wasm test serve clean

cli:
	go build -o finpass ./cmd/finpass

wasm:
	GOTOOLCHAIN=local GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o wasm/finpass.wasm ./wasm
	cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" ./wasm/

test:
	go test ./...

serve: wasm
	@echo "Serving on http://localhost:8000"
	python3 -m http.server 8000 -d wasm

clean:
	rm -f finpass wasm/finpass.wasm wasm/wasm_exec.js
