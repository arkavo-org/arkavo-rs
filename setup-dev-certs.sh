#!/bin/bash
#
# Setup all development certificates for arks server
# Generates: KAS keys, TLS certificates, and C2PA signing certificates
#

set -e

echo "============================================"
echo "Arkavo Server - Development Setup"
echo "============================================"
echo ""
echo "This script will generate all required certificates for development:"
echo "  1. KAS (Key Access Service) EC private key"
echo "  2. TLS certificates for HTTPS/WSS"
echo "  3. C2PA signing certificates"
echo ""
echo "⚠️  WARNING: These are for DEVELOPMENT/TESTING ONLY"
echo "    Use proper certificates from a CA in production"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi
echo ""

# ============================================
# 1. KAS EC Private Key
# ============================================
echo "1. Generating KAS EC private key..."
if [[ -f "recipient_private_key.pem" ]]; then
    echo "   ⚠️  recipient_private_key.pem already exists, skipping..."
else
    openssl ecparam -genkey -name prime256v1 -noout -out recipient_private_key.pem
    chmod 600 recipient_private_key.pem
    echo "   ✓ KAS private key: recipient_private_key.pem"
fi
echo ""

# ============================================
# 2. TLS Certificates
# ============================================
echo "2. Generating TLS certificates (self-signed)..."
if [[ -f "fullchain.pem" ]] && [[ -f "privkey.pem" ]]; then
    echo "   ⚠️  TLS certificates already exist, skipping..."
else
    openssl req -x509 -newkey rsa:4096 \
        -keyout privkey.pem \
        -out fullchain.pem \
        -days 365 \
        -nodes \
        -subj "/CN=localhost/O=Arkavo/C=US/ST=Maryland/L=Columbia"
    echo "   ✓ TLS certificate: fullchain.pem"
    echo "   ✓ TLS private key: privkey.pem"
fi
echo ""

# ============================================
# 3. C2PA Signing Certificates
# ============================================
echo "3. Generating C2PA signing certificates..."
if [[ -f "c2pa_private_key.pem" ]] && [[ -f "c2pa_cert.pem" ]]; then
    echo "   ⚠️  C2PA certificates already exist, skipping..."
else
    # Generate EC private key (P-256 curve for ES256)
    openssl ecparam -genkey -name prime256v1 -noout -out c2pa_private_key.pem
    chmod 600 c2pa_private_key.pem

    # Generate self-signed certificate
    openssl req -new -x509 \
        -key c2pa_private_key.pem \
        -out c2pa_cert.pem \
        -days 365 \
        -subj "/CN=Arkavo C2PA Signer/O=Arkavo/C=US/ST=Maryland/L=Columbia"

    echo "   ✓ C2PA private key: c2pa_private_key.pem"
    echo "   ✓ C2PA certificate: c2pa_cert.pem"
fi
echo ""

# ============================================
# Summary
# ============================================
echo "============================================"
echo "✓ Development Certificates Ready"
echo "============================================"
echo ""
echo "Generated files:"
echo "  KAS:  recipient_private_key.pem"
echo "  TLS:  fullchain.pem, privkey.pem"
echo "  C2PA: c2pa_private_key.pem, c2pa_cert.pem"
echo ""
echo "To verify the certificates:"
echo "  # KAS key"
echo "  openssl ec -in recipient_private_key.pem -text -noout | head -5"
echo ""
echo "  # TLS certificate"
echo "  openssl x509 -in fullchain.pem -noout -subject -dates"
echo ""
echo "  # C2PA certificate"
echo "  openssl x509 -in c2pa_cert.pem -noout -subject -dates"
echo ""
echo "To run the server with all features:"
echo "  export KAS_KEY_PATH=recipient_private_key.pem"
echo "  export TLS_CERT_PATH=fullchain.pem"
echo "  export TLS_KEY_PATH=privkey.pem"
echo "  export C2PA_SIGNING_KEY_PATH=c2pa_private_key.pem"
echo "  export C2PA_SIGNING_CERT_PATH=c2pa_cert.pem"
echo "  ./target/release/arks"
echo ""
echo "Or use the provided .env template:"
echo "  cp .env.example .env"
echo "  # Edit .env with your configuration"
echo "  source .env"
echo "  ./target/release/arks"
echo ""
echo "⚠️  SECURITY REMINDERS:"
echo "  • All private keys are protected with 600 permissions"
echo "  • Private keys are in .gitignore (never commit them)"
echo "  • These are DEVELOPMENT certificates only"
echo "  • For PRODUCTION, use certificates from a recognized CA"
echo "  • Certificate validity: 365 days"
echo ""
