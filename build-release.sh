#!/bin/bash
#
# Build optimized release binary for arks (ARKavo Server)
# Supports optional FairPlay Streaming DRM feature
#

set -e

echo "============================================"
echo "Building arks (ARKavo Server) Release"
echo "============================================"
echo ""

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)

echo "Platform: $OS $ARCH"
echo ""

# Set optimization flags
export RUSTFLAGS="-C target-cpu=native"

# Check if FairPlay feature requested
BUILD_FAIRPLAY=false
if [[ "$1" == "--fairplay" || "$1" == "-f" ]]; then
    BUILD_FAIRPLAY=true
    echo "FairPlay Streaming support: ENABLED"

    # Set FairPlay library path
    FPSSDK_BASE="$(pwd)/vendor/FairPlay_Streaming_Server_SDK_26"

    if [[ "$OS" == "Darwin" ]]; then
        export FPSSDK_LIB_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/macos"
    elif [[ "$OS" == "Linux" ]]; then
        if [[ "$ARCH" == "x86_64" ]]; then
            export FPSSDK_LIB_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/x86_64-unknown-linux-gnu"
        elif [[ "$ARCH" == "aarch64" ]]; then
            export FPSSDK_LIB_PATH="$FPSSDK_BASE/Development/Key_Server_Module/Rust/prebuilt/aarch64-unknown-linux-gnu"
        fi
    fi

    if [[ ! -d "$FPSSDK_LIB_PATH" ]]; then
        echo "ERROR: FairPlay SDK not found at: $FPSSDK_LIB_PATH"
        echo ""
        echo "Please download the FairPlay Streaming Server SDK from Apple Developer Portal"
        echo "and extract to: vendor/FairPlay_Streaming_Server_SDK_26/"
        exit 1
    fi

    echo "FairPlay SDK path: $FPSSDK_LIB_PATH"
else
    echo "FairPlay Streaming support: DISABLED"
    echo "(Use --fairplay flag to enable)"
fi

echo ""
echo "Building..."
echo ""

# Build command
if [[ "$BUILD_FAIRPLAY" == true ]]; then
    cargo build --release --bin arks --features fairplay
else
    cargo build --release --bin arks
fi

echo ""
echo "============================================"
echo "Build Complete!"
echo "============================================"
echo ""

# Show binary info
BINARY="target/release/arks"
SIZE=$(ls -lh "$BINARY" | awk '{print $5}')
echo "Binary: $BINARY"
echo "Size: $SIZE"
echo ""

if [[ "$BUILD_FAIRPLAY" == true ]]; then
    echo "FairPlay library dependency:"
    if [[ "$OS" == "Darwin" ]]; then
        otool -L "$BINARY" | grep fpscrypto || echo "  (not found - linking may have failed)"
    else
        ldd "$BINARY" | grep fpscrypto || echo "  (not found - linking may have failed)"
    fi
    echo ""
fi

echo "To run the server:"
echo "  ./target/release/arks"
echo ""

if [[ "$BUILD_FAIRPLAY" == true ]]; then
    echo "Note: FairPlay credentials required at runtime:"
    echo "  export FAIRPLAY_CREDENTIALS_PATH=$FPSSDK_BASE/Development/Key_Server_Module/credentials"
    echo ""
fi
