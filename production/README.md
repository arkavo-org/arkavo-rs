# Production Deployment Guide

This guide provides instructions for DevOps engineers deploying the Arkavo KAS server to production.

## Architecture Overview

The Arkavo server is a unified HTTPS service that provides:
- **REST API** - OpenTDF-compatible rewrap endpoints and Media DRM APIs
- **WebSocket API** - Real-time NanoTDF operations via `/ws`
- **Single Port** - All services run on port 443 (configurable via `PORT` env var)
- **TLS/HTTPS** - Rustls-based TLS with Let's Encrypt certificates

## Prerequisites

### System Requirements
- Rust 1.83.0 or later
- macOS or Linux (Darwin/Linux kernel)
- Minimum 2GB RAM, 2 CPU cores recommended
- Port 443 available (or alternative configured port)

### Required Services

#### NATS and Redis
```bash
# macOS (Homebrew)
brew install nats-server redis flatbuffers

# Linux (apt)
sudo apt-get install redis-server
# NATS: Download from https://github.com/nats-io/nats-server/releases

# Start services
nats-server &
redis-server --daemonize yes
```

#### AWS S3 (Required)
The server requires AWS S3 for storing encrypted content. Set up:

```bash
# Install AWS CLI
brew install awscli  # macOS
# OR
sudo apt-get install awscli  # Linux

# Configure AWS credentials
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter default region (e.g., us-east-1)
# Enter default output format (json)

# Create S3 bucket
aws s3 mb s3://arkavo-production --region us-east-1

# Verify credentials
aws s3 ls
```

**Required AWS Permissions:**
The IAM user/role needs the following S3 permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::arkavo-production/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::arkavo-production"
    }
  ]
}
```

### TLS Certificates

#### Option 1: Let's Encrypt (Recommended for Production)
```bash
# Install certbot
brew install certbot  # macOS
# OR
sudo apt-get install certbot  # Linux

# Obtain certificate (requires port 80 temporarily)
sudo certbot certonly --standalone -d 100.arkavo.net \
  --non-interactive --agree-tos --email admin@arkavo.net

# Certificates will be at:
# /etc/letsencrypt/live/100.arkavo.net/fullchain.pem
# /etc/letsencrypt/live/100.arkavo.net/privkey.pem

# Convert EC private key to PKCS#8 format (required for rustls)
sudo openssl pkcs8 -topk8 -nocrypt \
  -in /etc/letsencrypt/live/100.arkavo.net/privkey.pem \
  -out /etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem

# Set permissions
sudo chmod 600 /etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem
```

**Note**: Let's Encrypt now issues ECDSA (EC) certificates by default. The private key is in SEC1 format and must be converted to PKCS#8 for rustls compatibility.

**Auto-renewal**: Add to crontab (with key conversion):
```bash
# Create renewal hook script
sudo tee /etc/letsencrypt/renewal-hooks/deploy/convert-key.sh << 'EOF'
#!/bin/bash
# Convert EC key to PKCS#8 after renewal
openssl pkcs8 -topk8 -nocrypt \
  -in /etc/letsencrypt/live/100.arkavo.net/privkey.pem \
  -out /etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem
chmod 600 /etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem
systemctl restart arkavo
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/convert-key.sh

# Add to crontab
0 0 * * * certbot renew --quiet
```

#### Option 2: Self-Signed (Development Only)
```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

### KAS Private Key (First Time Setup)
```bash
# Generate EC private key for KAS operations
openssl ecparam -genkey -name prime256v1 -noout -out recipient_private_key.pem

# Validate the key
openssl ec -in recipient_private_key.pem -text -noout

# Secure the key (production)
chmod 600 recipient_private_key.pem
chown arkavo:arkavo recipient_private_key.pem  # if running as service user
```

**Security**: Never commit this key to version control. For production, use AWS KMS (see below).

### AWS KMS Setup (Production - Recommended)

Instead of storing the KAS private key as a file, encrypt it with AWS KMS:

```bash
# 1. Create a KMS key for encryption
aws kms create-key \
  --description "Arkavo KAS Private Key Encryption" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS

# Note the KeyId from output (e.g., "12345678-1234-1234-1234-123456789012")
export KMS_KEY_ID="your-key-id-here"

# 2. Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/arkavo-kas-key \
  --target-key-id $KMS_KEY_ID

# 3. Encrypt your KAS private key
aws kms encrypt \
  --key-id $KMS_KEY_ID \
  --plaintext fileb://recipient_private_key.pem \
  --output text \
  --query CiphertextBlob > kas_key_encrypted.bin

# 4. Convert to base64 for environment variable
export KMS_ENCRYPTED_KEY_BASE64=$(base64 -i kas_key_encrypted.bin)

# 5. Set environment variables
export KMS_KEY_ID="$KMS_KEY_ID"  # or alias/arkavo-kas-key
export KMS_ENCRYPTED_KEY_BASE64="$KMS_ENCRYPTED_KEY_BASE64"

# 6. Remove plaintext key file (keep backup securely)
# rm recipient_private_key.pem  # ONLY after verifying KMS works!
```

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

## Build

### Release Build
```bash
# Clone repository
git clone https://github.com/arkavo-org/arkavo-rs.git
cd arkavo-rs

# Build with optimizations
export RUSTFLAGS="-C target-cpu=native"
cargo build --release

# Binary location: ./target/release/arkavo
```

### Verify Build
```bash
./target/release/arkavo --version  # Should show version info
ldd ./target/release/arkavo         # Check dynamic library dependencies
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `8443` | HTTPS server port (443 for production) |
| `TLS_CERT_PATH` | Yes* | - | Path to TLS certificate (fullchain.pem) |
| `TLS_KEY_PATH` | Yes* | - | Path to TLS private key (privkey.pem) |
| **Security - KAS Private Key** ||||
| `KMS_KEY_ID` | **Recommended** | - | AWS KMS key ID for decrypting KAS private key |
| `KMS_ENCRYPTED_KEY_BASE64` | **Recommended** | - | Base64-encoded KMS-encrypted KAS private key |
| `KAS_KEY_PATH` | Fallback | - | Path to KAS EC private key file (use KMS instead) |
| **Security - JWT Validation** ||||
| `OAUTH_PUBLIC_KEY_PEM` | **Recommended** | - | OAuth public key PEM content for JWT validation |
| `OAUTH_PUBLIC_KEY_PATH` | **Recommended** | - | Path to OAuth public key PEM file |
| **Infrastructure** ||||
| `NATS_URL` | No | `nats://localhost:4222` | NATS server URL |
| `NATS_SUBJECT` | No | `nanotdf.messages` | NATS subject for messages |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection URL |
| `S3_BUCKET` | Yes | - | AWS S3 bucket name for encrypted content storage |
| `AWS_REGION` | No | From AWS config | AWS region for S3 bucket |
| `AWS_ACCESS_KEY_ID` | No | From AWS config | AWS access key (or use IAM role) |
| `AWS_SECRET_ACCESS_KEY` | No | From AWS config | AWS secret key (or use IAM role) |
| **Observability** ||||
| `RUST_LOG` | No | `info` | Log level (error/warn/info/debug/trace) |
| `ENABLE_TIMING_LOGS` | No | `false` | Enable performance timing logs |
| `ENABLE_MEDIA_ANALYTICS` | No | `false` | Enable media analytics |
| **Media DRM** ||||
| `MAX_CONCURRENT_STREAMS` | No | `5` | Max concurrent media streams per user |
| `MEDIA_METRICS_SUBJECT` | No | `media.metrics` | NATS subject for media metrics |

\* If `TLS_CERT_PATH` is not set, server runs in HTTP-only mode (not recommended for production)

### Security Recommendations

**Production deployments MUST configure:**
1. **JWT Validation**: Set `OAUTH_PUBLIC_KEY_PEM` or `OAUTH_PUBLIC_KEY_PATH` to enable signature verification
2. **KMS Integration**: Use `KMS_KEY_ID` and `KMS_ENCRYPTED_KEY_BASE64` instead of file-based keys
3. **Rate Limiting**: Built-in (100 req/s for OpenTDF, 300 req/s for Media API)

**Development defaults (INSECURE for production):**
- JWT signature validation DISABLED if OAuth key not provided
- File-based KAS private key if KMS not configured

### Example Production Configuration

```bash
# Server
export PORT=443
export TLS_CERT_PATH=/etc/letsencrypt/live/100.arkavo.net/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem

# Security - KAS Key via KMS
export KMS_KEY_ID=alias/arkavo-kas-key
export KMS_ENCRYPTED_KEY_BASE64="<base64-encoded-encrypted-key>"

# Security - JWT Validation
export OAUTH_PUBLIC_KEY_PEM="$(cat /path/to/oauth_public.pem)"
# OR
export OAUTH_PUBLIC_KEY_PATH=/path/to/oauth_public.pem

# Infrastructure
export NATS_URL=nats://localhost:4222
export REDIS_URL=redis://localhost:6379
export S3_BUCKET=arkavo-production
export AWS_REGION=us-east-1

# Observability
export RUST_LOG=info
export ENABLE_TIMING_LOGS=true
```

**Development/Testing Only:**
```bash
export PORT=8443
export KAS_KEY_PATH=./recipient_private_key.pem  # File-based (insecure)
# JWT validation will be DISABLED (insecure)
export RUST_LOG=debug
```

## Running the Service

### Manual Start
```bash
cd /path/to/arkavo-rs

# Start with environment variables
sudo -E PORT=443 \
  TLS_CERT_PATH=/etc/letsencrypt/live/100.arkavo.net/fullchain.pem \
  TLS_KEY_PATH=/etc/letsencrypt/live/100.arkavo.net/privkey.pem \
  KAS_KEY_PATH=./recipient_private_key.pem \
  NATS_URL=nats://localhost:4222 \
  REDIS_URL=redis://localhost:6379 \
  S3_BUCKET=arkavo-production \
  AWS_REGION=us-east-1 \
  RUST_LOG=info \
  ./target/release/arkavo
```

### Systemd Service (Recommended)

Create `/etc/systemd/system/arkavo.service`:
```ini
[Unit]
Description=Arkavo KAS Server
After=network.target redis.service nats.service
Requires=redis.service nats.service

[Service]
Type=simple
User=arkavo
Group=arkavo
WorkingDirectory=/opt/arkavo
Environment="PORT=443"
Environment="TLS_CERT_PATH=/etc/letsencrypt/live/100.arkavo.net/fullchain.pem"
Environment="TLS_KEY_PATH=/etc/letsencrypt/live/100.arkavo.net/privkey_pkcs8.pem"
Environment="KAS_KEY_PATH=/var/lib/arkavo/recipient_private_key.pem"
Environment="NATS_URL=nats://localhost:4222"
Environment="REDIS_URL=redis://localhost:6379"
Environment="S3_BUCKET=arkavo-production"
Environment="AWS_REGION=us-east-1"
Environment="RUST_LOG=info"
Environment="ENABLE_TIMING_LOGS=true"
ExecStart=/opt/arkavo/target/release/arkavo
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/arkavo
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
# Create service user
sudo useradd -r -s /bin/false arkavo

# Set permissions
sudo chown -R arkavo:arkavo /opt/arkavo
sudo chown -R arkavo:arkavo /var/lib/arkavo
sudo chmod 600 /var/lib/arkavo/recipient_private_key.pem

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable arkavo
sudo systemctl start arkavo

# Check status
sudo systemctl status arkavo
sudo journalctl -u arkavo -f
```

### Docker Deployment

Example `Dockerfile`:
```dockerfile
FROM rust:1.83-slim as builder

WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/arkavo /app/arkavo

USER nobody
EXPOSE 443

ENTRYPOINT ["/app/arkavo"]
```

Run with Docker:
```bash
docker build -t arkavo-kas .
docker run -d \
  -p 443:443 \
  -e PORT=443 \
  -e TLS_CERT_PATH=/certs/fullchain.pem \
  -e TLS_KEY_PATH=/certs/privkey.pem \
  -e KAS_KEY_PATH=/keys/recipient_private_key.pem \
  -e NATS_URL=nats://nats:4222 \
  -e REDIS_URL=redis://redis:6379 \
  -e RUST_LOG=info \
  -v /etc/letsencrypt/live/100.arkavo.net:/certs:ro \
  -v /var/lib/arkavo:/keys:ro \
  --name arkavo-kas \
  arkavo-kas
```

## API Endpoints

### REST API (HTTPS)
- `POST /kas/v2/rewrap` - OpenTDF rewrap operation
- `GET /kas/v2/kas_public_key` - Get KAS public key
- `POST /media/v1/key-request` - Media DRM key request
- `POST /media/v1/session/start` - Start media session
- `POST /media/v1/session/:id/heartbeat` - Session heartbeat
- `DELETE /media/v1/session/:id` - Terminate session

### WebSocket API
- `wss://100.arkavo.net/ws` - Binary WebSocket for NanoTDF operations

Message types (first byte):
- `0x01` - PublicKey (ECDH key exchange)
- `0x02` - KasPublicKey (KAS public key response)
- `0x03` - Rewrap (NanoTDF rewrap request)
- `0x04` - RewrappedKey (Rewrapped key response)
- `0x05` - Nats (NATS message passthrough)
- `0x06` - Event (FlatBuffers event handling)

## Monitoring

### Health Checks
```bash
# Check if server is listening
netstat -tulpn | grep :443

# Test HTTPS connectivity
curl -k https://100.arkavo.net/kas/v2/kas_public_key

# Check dependencies
redis-cli ping
nats-cli server ping
```

### Logs
```bash
# Systemd logs
sudo journalctl -u arkavo -f --since "1 hour ago"

# Set debug logging
sudo systemctl set-environment RUST_LOG=debug
sudo systemctl restart arkavo
```

### Metrics
- Check `ENABLE_TIMING_LOGS=true` for performance metrics in logs
- Media analytics published to NATS subject `media.metrics` (if enabled)

## Troubleshooting

### Port Already in Use
```bash
# Find process using port 443
sudo lsof -i :443
sudo netstat -tulpn | grep :443

# Kill process or change PORT env var
```

### TLS Certificate Issues
```bash
# Verify certificate validity
openssl x509 -in /etc/letsencrypt/live/100.arkavo.net/fullchain.pem -noout -dates

# Check certificate chain
openssl s_client -connect 100.arkavo.net:443 -showcerts

# Renew certificate
sudo certbot renew --force-renewal
```

### Connection Refused
```bash
# Check firewall
sudo ufw status  # Ubuntu
sudo firewall-cmd --list-all  # RHEL/CentOS

# Allow port 443
sudo ufw allow 443/tcp
```

### NATS/Redis Connection Issues
```bash
# Check NATS
nats-cli server ping

# Check Redis
redis-cli ping

# Restart services
sudo systemctl restart nats redis
```

## Security Considerations

1. **TLS Certificates**: Use Let's Encrypt with auto-renewal. Never use self-signed in production.
2. **Private Keys**: Store KAS private key in secure location with `chmod 600`. Consider HSM/KMS for production.
3. **Service User**: Run as non-root user with `CAP_NET_BIND_SERVICE` capability for port 443.
4. **Firewall**: Only expose port 443. Keep NATS (4222) and Redis (6379) internal.
5. **JWT Validation**: Enable proper JWT signature validation (currently disabled for development).
6. **Updates**: Regularly update dependencies with `cargo update` and rebuild.
7. **Audit Logs**: Enable `RUST_LOG=info` minimum for production audit trail.

## Performance Tuning

### System Limits
```bash
# Increase file descriptor limits
echo "arkavo soft nofile 65536" >> /etc/security/limits.conf
echo "arkavo hard nofile 65536" >> /etc/security/limits.conf

# Kernel tuning for high concurrency
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

### Redis Tuning
```bash
# Edit /etc/redis/redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
```

### NATS Tuning
```bash
# NATS config file
max_payload = 16777216  # 16MB for large NanoTDF messages
max_connections = 10000
```

## Backup and Recovery

### Critical Data
1. **KAS Private Key**: `/var/lib/arkavo/recipient_private_key.pem` - Back up securely
2. **Redis Data**: Persistent storage if caching is critical
3. **Configuration**: Environment variables and systemd service files

### Backup Script
```bash
#!/bin/bash
BACKUP_DIR="/backups/arkavo/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup KAS key
cp /var/lib/arkavo/recipient_private_key.pem "$BACKUP_DIR/"

# Backup Redis (if persistence enabled)
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb "$BACKUP_DIR/"

# Encrypt and upload to S3
tar czf - "$BACKUP_DIR" | gpg --encrypt -r admin@arkavo.net | \
  aws s3 cp - s3://arkavo-backups/arkavo-$(date +%Y%m%d).tar.gz.gpg
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/arkavo-org/arkavo-rs/issues
- Documentation: See CLAUDE.md in repository root
