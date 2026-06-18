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
Copy the template configuration file:
```bash
cp example.config.json config.json
```
Note that `acme_directory_url` is optional, as the service dynamically defaults to Let's Encrypt Staging/Production or ZeroSSL based on your `acme_provider` and `ENV` settings.

```json
{
  "acme_email": "admin@example.com",
  "acme_provider": "letsencrypt",
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

### ACME Provider Configuration

#### 1. Let's Encrypt (Default)
By default, the service uses Let's Encrypt. The directory URL is automatically toggled depending on the `ENV` setting if `acme_directory_url` is omitted:
- **`ENV=development`** (or default): Defaults to Let's Encrypt Staging (`https://acme-staging-v02.api.letsencrypt.org/directory`).
- **`ENV=production`**: Defaults to Let's Encrypt Production (`https://acme-v02.api.letsencrypt.org/directory`).

#### 2. ZeroSSL
ZeroSSL can be configured in two ways:
- **Email-only Registration (Recommended):** Set `"acme_provider": "zerossl"` in your `config.json` (or environment variable `ACME_PROVIDER=zerossl`). The client will automatically contact ZeroSSL's API and generate/bind EAB credentials under the hood using your ACME email address.
- **Manual EAB Credentials:** If you prefer to bind to a pre-existing ZeroSSL developer account, provide your EAB credentials via configuration (`eab_kid` / `eab_hmac`) or environment variables (`EAB_KID` / `EAB_HMAC`).


### Authentication Environment Variables
Provide API credentials for your DNS provider and ACME provider (if using ZeroSSL) as environment variables:
```bash
# Cloudflare DNS API Token
export CF_DNS_API_TOKEN="your_cloudflare_token"

# Or Hetzner DNS API Token
export HETZNER_API_TOKEN="your_hetzner_api_token"

# EAB credentials for ZeroSSL (if applicable)
export EAB_KID="your_eab_key_id"
export EAB_HMAC="your_eab_hmac_key"
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

#### 1. Running Locally
```bash
# Generate random secure token and its Argon2id hash
./hash.sh

# Generate Argon2id hash for a custom token
./hash.sh -token mysecret
```

#### 2. Running via Docker
Since the keygen utility is compiled and copied into the Docker image, you can invoke it by overriding the container entrypoint:
```bash
# Generate random secure token and its Argon2id hash
docker run --rm -it --entrypoint /keygen cert-central

# Generate Argon2id hash for a custom token
docker run --rm -it --entrypoint /keygen cert-central -token mysecret
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

### Docker Compose (Recommended)
You can configure and spin up the complete service using Docker Compose:

1. **Prepare configuration:**
   Ensure your `config.json` is set up in the root directory.
2. **Set up environment variables:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in your DNS provider and/or ZeroSSL EAB credentials.
3. **Start the service:**
   ```bash
   docker compose up -d --build
   ```
4. **Persisted Certs:**
   Certs and private keys will automatically be saved and persisted in the local `./certs` directory.

### Running with Docker CLI (Manual)
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
