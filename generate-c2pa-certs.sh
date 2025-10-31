#!/bin/bash
#
# Generate C2PA certificates with proper CA chain for development
# These are for TESTING ONLY - use proper CA-signed certificates in production
#

set -e

echo "============================================"
echo "C2PA Certificate Chain Generation"
echo "============================================"
echo ""
echo "Generating C2PA certificate chain for development/testing"
echo "This will create:"
echo "  1. CA (Certificate Authority) certificate"
echo "  2. End-entity signing certificate"
echo "  3. Complete certificate chain for C2PA"
echo ""
echo "⚠️  WARNING: These certificates are for DEVELOPMENT ONLY"
echo "    Use proper CA-signed certificates in production"
echo ""

# Certificate details
CA_CN="Arkavo C2PA CA"
CERT_CN="Arkavo C2PA Signer"
CERT_O="Arkavo"
CERT_C="US"
CERT_ST="Maryland"
CERT_L="Columbia"
CERT_DAYS=365

# File names
CA_KEY="c2pa_ca_key.pem"
CA_CERT="c2pa_ca_cert.pem"
PRIVATE_KEY="c2pa_private_key.pem"
CSR="c2pa_cert.csr"
CERTIFICATE="c2pa_cert.pem"
CERT_CHAIN="c2pa_cert_chain.pem"

# Check if files already exist
if [[ -f "$PRIVATE_KEY" ]] || [[ -f "$CERTIFICATE" ]]; then
    echo "⚠️  Certificate files already exist:"
    [[ -f "$PRIVATE_KEY" ]] && echo "  - $PRIVATE_KEY"
    [[ -f "$CERTIFICATE" ]] && echo "  - $CERTIFICATE"
    [[ -f "$CERT_CHAIN" ]] && echo "  - $CERT_CHAIN"
    echo ""
    read -p "Overwrite existing certificates? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
    echo ""
fi

# 1. Generate CA private key and certificate
echo "1. Generating CA certificate..."
openssl ecparam -genkey -name prime256v1 -noout -out "$CA_KEY"
chmod 600 "$CA_KEY"

openssl req -new -x509 \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -days "$CERT_DAYS" \
    -subj "/CN=$CA_CN/O=$CERT_O/C=$CERT_C/ST=$CERT_ST/L=$CERT_L" \
    -extensions v3_ca \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign"))

echo "   ✓ CA certificate: $CA_CERT"
echo ""

# 2. Generate end-entity private key
echo "2. Generating signing private key (P-256 curve)..."
openssl ecparam -genkey -name prime256v1 -noout -out "$PRIVATE_KEY"
chmod 600 "$PRIVATE_KEY"
echo "   ✓ Private key saved: $PRIVATE_KEY"
echo ""

# 3. Generate certificate signing request (CSR)
echo "3. Generating certificate signing request..."
openssl req -new \
    -key "$PRIVATE_KEY" \
    -out "$CSR" \
    -subj "/CN=$CERT_CN/O=$CERT_O/C=$CERT_C/ST=$CERT_ST/L=$CERT_L"
echo "   ✓ CSR created: $CSR"
echo ""

# 4. Sign the certificate with CA
echo "4. Signing certificate with CA..."
openssl x509 -req \
    -in "$CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$CERTIFICATE" \
    -days "$CERT_DAYS" \
    -sha256 \
    -extensions v3_end \
    -extfile <(cat <<EOF
[v3_end]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
EOF
)

echo "   ✓ Certificate signed: $CERTIFICATE"
echo ""

# 5. Create certificate chain (end-entity + CA)
echo "5. Creating certificate chain..."
cat "$CERTIFICATE" "$CA_CERT" > "$CERT_CHAIN"
echo "   ✓ Certificate chain: $CERT_CHAIN"
echo ""

# 6. Verify the generated files
echo "6. Verifying generated certificates..."
echo ""

echo "CA Certificate:"
openssl x509 -in "$CA_CERT" -noout -subject -issuer
echo ""

echo "Signing Certificate:"
openssl x509 -in "$CERTIFICATE" -noout -subject -issuer
echo ""

echo "Verify certificate chain:"
openssl verify -CAfile "$CA_CERT" "$CERTIFICATE"
echo ""

echo "Private Key Info:"
openssl ec -in "$PRIVATE_KEY" -text -noout 2>&1 | grep "Private-Key:"
echo ""

# Calculate SHA-256 fingerprint
echo "Certificate Fingerprint (SHA-256):"
openssl x509 -in "$CERTIFICATE" -noout -fingerprint -sha256
echo ""

echo "============================================"
echo "✓ C2PA Certificate Chain Generated"
echo "============================================"
echo ""
echo "Files created:"
echo "  CA Key:        $CA_KEY (permissions: 600)"
echo "  CA Cert:       $CA_CERT"
echo "  Private Key:   $PRIVATE_KEY (permissions: 600)"
echo "  Certificate:   $CERTIFICATE"
echo "  Cert Chain:    $CERT_CHAIN (use this for C2PA)"
echo ""
echo "Valid for: $CERT_DAYS days"
echo "Expires: $(openssl x509 -in "$CERTIFICATE" -noout -enddate | cut -d= -f2)"
echo ""
echo "To use with arks server (use CERT_CHAIN, not individual cert):"
echo "  export C2PA_SIGNING_KEY_PATH=$(pwd)/$PRIVATE_KEY"
echo "  export C2PA_SIGNING_CERT_PATH=$(pwd)/$CERT_CHAIN"
echo "  ./target/release/arks"
echo ""
echo "Or use the run script (will auto-detect):"
echo "  ./run-arks.sh"
echo ""
echo "⚠️  SECURITY NOTES:"
echo "  • These are self-signed certificates for DEVELOPMENT/TESTING only"
echo "  • Private keys are stored unencrypted (protected by file permissions)"
echo "  • For PRODUCTION, obtain certificates from a recognized CA"
echo "  • Never commit private keys to version control"
echo "  • Certificates are already in .gitignore"
echo ""

# Clean up temporary files
rm -f "$CSR" c2pa_ca_cert.srl
