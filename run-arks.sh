#!/bin/bash
#
# Run arks server with proper library paths and configuration
#

set -e

# Detect if running release or debug build
if [[ -f "target/release/arks" ]]; then
    BINARY="target/release/arks"
    BUILD_TYPE="release"
elif [[ -f "target/debug/arks" ]]; then
    BINARY="target/debug/arks"
    BUILD_TYPE="debug"
else
    echo "Error: No arks binary found. Build first with:"
    echo "  cargo build --release --bin arks"
    echo "Or with FairPlay:"
    echo "  ./build-release.sh --fairplay"
    exit 1
fi

echo "============================================"
echo "Starting arks (ARKavo Server)"
echo "============================================"
echo ""
echo "Binary: $BINARY ($BUILD_TYPE)"
echo ""

# Check if binary was built with FairPlay
if otool -L "$BINARY" | grep -q "libfpscrypto.dylib"; then
    echo "FairPlay Streaming: ENABLED"

    # Set library path for FairPlay
    FPSSDK_BASE="$(pwd)/vendor/FairPlay_Streaming_Server_SDK_26"

    if [[ "$(uname -s)" == "Darwin" ]]; then
        export DYLD_LIBRARY_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/macos:${DYLD_LIBRARY_PATH}"
    elif [[ "$(uname -s)" == "Linux" ]]; then
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then
            export LD_LIBRARY_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/x86_64-unknown-linux-gnu:${LD_LIBRARY_PATH}"
        elif [[ "$ARCH" == "aarch64" ]]; then
            export LD_LIBRARY_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/aarch64-unknown-linux-gnu:${LD_LIBRARY_PATH}"
        fi
    fi

    # Set FairPlay credentials path if not already set
    if [[ -z "$FAIRPLAY_CREDENTIALS_PATH" ]]; then
        export FAIRPLAY_CREDENTIALS_PATH="$FPSSDK_BASE/Development/Key_Server_Module/credentials"
        echo "FairPlay credentials: $FAIRPLAY_CREDENTIALS_PATH"
    fi
else
    echo "FairPlay Streaming: DISABLED"
fi

# Set default paths for development certificates if they exist
if [[ -z "$KAS_KEY_PATH" ]] && [[ -f "recipient_private_key.pem" ]]; then
    export KAS_KEY_PATH="recipient_private_key.pem"
    echo "KAS key: $KAS_KEY_PATH"
fi

if [[ -z "$TLS_CERT_PATH" ]] && [[ -f "fullchain.pem" ]]; then
    export TLS_CERT_PATH="fullchain.pem"
    export TLS_KEY_PATH="privkey.pem"
    echo "TLS: ENABLED (fullchain.pem)"
else
    echo "TLS: DISABLED (no certificates found)"
fi

if [[ -z "$C2PA_SIGNING_KEY_PATH" ]] && [[ -f "c2pa_private_key.pem" ]]; then
    export C2PA_SIGNING_KEY_PATH="c2pa_private_key.pem"
    # Prefer certificate chain if available
    if [[ -f "c2pa_cert_chain.pem" ]]; then
        export C2PA_SIGNING_CERT_PATH="c2pa_cert_chain.pem"
        echo "C2PA signing: ENABLED (c2pa_cert_chain.pem)"
    elif [[ -f "c2pa_cert.pem" ]]; then
        export C2PA_SIGNING_CERT_PATH="c2pa_cert.pem"
        echo "C2PA signing: ENABLED (c2pa_cert.pem - WARNING: chain recommended)"
    fi
else
    echo "C2PA signing: DISABLED (no certificates found)"
fi

# Set default port if not specified
if [[ -z "$PORT" ]]; then
    export PORT=8443
fi

echo ""
echo "Server port: $PORT"
echo "  WebSocket: ws://localhost:$PORT/ws"
echo "  HTTP API: http://localhost:$PORT"
echo "  Apple App Site: http://localhost:$PORT/.well-known/apple-app-site-association"
echo ""

# Check for required services
echo "Checking required services..."

# Check NATS
NATS_URL=${NATS_URL:-nats://localhost:4222}
if ! nc -z localhost 4222 2>/dev/null; then
    echo "⚠️  WARNING: NATS server not running on port 4222"
    echo "   Start with: nats-server"
fi

# Check Redis
REDIS_URL=${REDIS_URL:-redis://localhost:6379}
if ! nc -z localhost 6379 2>/dev/null; then
    echo "⚠️  WARNING: Redis server not running on port 6379"
    echo "   Start with: redis-server"
fi

echo ""
echo "============================================"
echo "Starting server..."
echo "============================================"
echo ""

# Run the server (pass through any command line arguments)
exec "$BINARY" "$@"
