# Cert Central

Production-grade, automated SSL/TLS certificate management service in Go. Integrates with Let's Encrypt (ACME v2) using DNS-01 challenges, schedules renewals, and exposes certificates via a domain-restricted, authenticated REST API.

---

## Architecture

```mermaid
graph TD
    A[config.json] -->|Loads Config| B(Main App)
    B -->|Starts| C(Background Scheduler)
    B -->|Starts| D(API Server)
    C -->|Check Expiry/Config| E{Certs Valid?}
    E -->|No / Expired / Config Changed| F(Lego ACME Client)
    F -->|DNS-01 Challenge| G(Hetzner / Cloudflare)
    G -->|Issue PEMs| H[./certs Storage]
    E -->|Yes| I(No Action)
    D -->|GET /api/v1/certificates| J(Bearer Token Auth)
    J -->|Argon2id Match| K(Filter Certs & Return JSON)
```

---

## Features

- **DNS-01 Challenges**: Issue wildcard and SAN certificates using Cloudflare or Hetzner DNS providers.
- **Background Scheduler**: Periodically monitors local certificate expiration dates and domain configurations, triggering renewals only when needed.
- **Argon2id Token Authentication**: Protects the HTTP API using API keys hashed with the Argon2id key derivation function.
- **Domain-Restricted Access Control**: Restricts authenticated tokens to retrieving only specified domains.
- **Zero-Downtime Design**: Background worker handles renewals seamlessly without interrupting the web server.

---

## Getting Started

### Prerequisites
- Go 1.22+
- Make (optional)

### Setup Configuration
Create a `config.json` file in the project root:
```json
{
  "acme_email": "admin@example.com",
  "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "dns_provider": "cloudflare",
  "renew_threshold_days": 30,
  "check_interval_hours": 24,
  "certificates": [
    {
      "primary": "example.com",
      "sans": ["*.example.com", "www.example.com"]
    }
  ],
  "api_keys": [
    {
      "token": "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs",
      "allowed_domains": ["example.com"]
    }
  ]
}
```

### Authentication Environment Variables
Provide API credentials for your DNS provider as environment variables:
```bash
# Cloudflare API Token
export CF_DNS_API_TOKEN="your_cloudflare_token"

# Or Hetzner API Key
export HETZNER_API_KEY="your_hetzner_api_key"
```

---

## Developer Commands

Run application:
```bash
make run
```

Build binaries:
```bash
make build
```

Run tests (100% mocked, TDD-verified):
```bash
make test
```

---

## Token Hashing Utility (CLI)
Hash custom tokens or generate secure random credentials using the built-in CLI wrapper:

```bash
# Generate random secure token and its Argon2id hash
./hash.sh

# Generate Argon2id hash for a custom token
./hash.sh -token mysecret
```

---

## API Documentation

### 1. Health Status
Check if application is healthy.
- **Endpoint**: `GET /health`
- **Auth**: None
- **Response**:
  ```json
  {"status": "up"}
  ```

### 2. Fetch Certificates
Retrieve PEM-encoded certificates and private keys.
- **Endpoint**: `GET /api/v1/certificates`
- **Auth**: `Authorization: Bearer <TOKEN>` (or raw `<TOKEN>` in header)
- **Response**:
  ```json
  [
    {
      "domain": "example.com",
      "sans": ["*.example.com", "www.example.com"],
      "issued": true,
      "certificate": "-----BEGIN CERTIFICATE-----\n...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n..."
    }
  ]
  ```

---

## Docker

Build minimal Docker image from scratch:
```bash
docker build -t cert-central .
```

Run container:
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config.json:/config.json \
  -v $(pwd)/certs:/certs \
  -e CF_DNS_API_TOKEN="your_token" \
  cert-central
```
