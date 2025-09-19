#!/bin/bash

set -e

echo "Building Ladderflare WASM..."

# Ensure we have the ruleset
if [ ! -f "ruleset.yaml" ]; then
    echo "Error: ruleset.yaml not found. Run 'npm run build:rules' first."
    exit 1
fi

# Set environment variables for WASM compilation
export GOOS=js
export GOARCH=wasm

# Build the WASM binary with optimizations
echo "Compiling Go to WASM with optimizations..."
go build -ldflags="-s -w" -tags=wasm -o public/main.wasm main.go

# Copy the wasm_exec.js file from Go installation
GOROOT=$(go env GOROOT)
WASM_EXEC_JS="${GOROOT}/misc/wasm/wasm_exec.js"

# Try multiple possible locations for wasm_exec.js
if [ -f "$WASM_EXEC_JS" ]; then
    echo "Copying wasm_exec.js from misc/wasm/..."
    cp "$WASM_EXEC_JS" public/wasm_exec.js
elif [ -f "${GOROOT}/lib/wasm/wasm_exec.js" ]; then
    echo "Copying wasm_exec.js from lib/wasm/..."
    cp "${GOROOT}/lib/wasm/wasm_exec.js" public/wasm_exec.js
else
    echo "Warning: wasm_exec.js not found in standard locations"
    echo "Searched: $WASM_EXEC_JS and ${GOROOT}/lib/wasm/wasm_exec.js"
    echo "Please ensure Go is properly installed"
fi

echo "WASM build complete!"
echo "Files generated:"
echo "  - public/main.wasm"
echo "  - public/wasm_exec.js"

# Show file sizes
if command -v ls &> /dev/null; then
    echo ""
    echo "File sizes:"
    ls -lh public/main.wasm public/wasm_exec.js 2>/dev/null || true
fi