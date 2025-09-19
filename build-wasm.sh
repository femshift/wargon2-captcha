#!/bin/bash

echo "Building WASM module..."

export GOOS=js
export GOARCH=wasm

cd wasm
go build -o ../web/fingerprint.wasm main.go

cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ../web/

echo "WASM module built successfully!"
echo "Files generated:"
echo "  - web/fingerprint.wasm"
echo "  - web/wasm_exec.js" 